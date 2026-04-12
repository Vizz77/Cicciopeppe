import asyncio
import uvloop
from db import close_db, redis_conn
from db import connect_db, redis_channels
from db import dbtransaction, sqla
import math
from asyncio import Queue
from dataclasses import dataclass
from datetime import timedelta, datetime
from exploitfarm.models.enums import AttackMode
from exploitfarm.models.groups import JoinRequest, GroupEventRequestType, GroupRequestEvent
from exploitfarm.models.response import ResponseStatus
from exploitfarm.models.groups import GroupResponseEvent, GroupEventResponseType
from db import Team, Exploit, ExploitSource
from utils import json_like, datetime_now
import time
from models.config import Configuration
from workers.skio import sio_server
import logging
import traceback
from utils import set_exploit_stopped
from multiprocessing import Process
from utils.redis_pipe import RedisCallHandler
from exploitfarm.models.teams import TeamDTO
from asyncio import Lock
import random

class StopLoop(Exception):
    pass

rpc_redis = RedisCallHandler(redis_conn)
WORKERS_POOL_ID = "workers"

class g:
    manager: "WorkersManager" = None
    configuration: Configuration = None
    teams: list[Team] = []
    exploits: list[dict] = []  # List of { "exploit": Exploit, "latest_commit_id": str }
    task_list: list[asyncio.Task] = []

async def disconnect_client(client: str):
    if isinstance(client, bytes):
        client = client.decode()
    sid = await redis_conn.get(f"group:{WORKERS_POOL_ID}:client:{client}:sid")
    if isinstance(sid, bytes):
        sid = sid.decode()
    if sid:
        await sio_server.disconnect(sid)

@dataclass
class ClinetAttackerStatus:
    client_id: str
    sid: str
    queue_size: int
    used_queues: int = 0
    attack_start_time: datetime|None = None
    
    def prio_assign(self, min_factor: int) -> float:
        if min_factor == 0: return 0
        return (self.queue_size - self.used_queues) / min_factor

    def assign(self, target: "AttackTargetStatus"):
        self.used_queues += 1
        target.assigned_to = self.client_id
        self.attack_start_time = datetime_now()
    
    def end(self, target: "AttackTargetStatus", n_flags: int = 0):
        self.used_queues -= 1
        target.executed = True
        target.n_flags += n_flags
    
    def reset(self):
        self.used_queues = 0
        self.attack_start_time = None
        
    def delta_from_start(self):
        if self.attack_start_time:
            return datetime_now() - self.attack_start_time
        return timedelta(seconds=0)

@dataclass
class AttackTargetStatus:
    target: str          # team host
    exploit_id: str
    commit_id: str|None
    team_data: dict
    executed: bool = False
    assigned_to: str|None = None
    n_flags: int = 0
    
    def reset(self):
        self.executed = False
        self.assigned_to = None

def current_tick_calc():
    this_time = datetime_now()
    start_time = g.configuration.START_TIME
    if start_time > this_time:
        raise Exception("Attack not started yet")
    return math.floor((this_time - start_time).total_seconds() / g.configuration.TICK_DURATION)

def calc_round_time_available():
    this_time = datetime_now()
    match g.configuration.ATTACK_MODE:
        case AttackMode.TICK_DELAY:
            return g.configuration.TICK_DURATION
        case AttackMode.WAIT_FOR_TIME_TICK:
            start_time = g.configuration.START_TIME
            next_tick = current_tick_calc() + 1
            next_time = start_time + timedelta(seconds=g.configuration.TICK_DURATION * next_tick) + timedelta(seconds=g.configuration.ATTACK_TIME_TICK_DELAY)
            return (next_time - this_time).total_seconds()
        case AttackMode.LOOP_DELAY:
            return g.configuration.LOOP_ATTACK_DELAY

class WorkersManager:
    TIMEOUT_SEND_INTERVAL = 5
    
    def __init__(self):
        self.group_id = WORKERS_POOL_ID
        self.queue = Queue()
        self.timeout = 0
        self.deadline = datetime_now()
        self.tot_time_available = 0
        
        self.last_timeout_sent = 0
        self.last_timeout_value_sent = 0
        
        self.client_table: dict[str, ClinetAttackerStatus] = {}
        # attack target table maps "exploitId" -> { "targetHost" -> AttackTargetStatus }
        self.attack_target_table: dict[str, dict[str, AttackTargetStatus]] = {}
        self.client_table_lock = Lock()
        self.attack_target_table_lock = Lock()
        self.source_pull_required = set()
        
        self.current_virtual_time = 0
        self.task = asyncio.create_task(self.__task())

    async def generate_attack_targets(self, exploit_id: str = None):
        if exploit_id is None:
            for info in g.exploits:
                if not info["latest_commit_id"]:
                    continue
                await self.generate_attack_targets(str(info["exploit"].id))
            return
            
        async with self.attack_target_table_lock:
            self.attack_target_table[exploit_id] = {}
            for team in g.teams:
                expl_info = None
                for info in g.exploits:
                    if not info["latest_commit_id"]:
                        continue
                    if str(info["exploit"].id) == exploit_id:
                        expl_info = info
                        break
                self.attack_target_table[exploit_id][team.host] = AttackTargetStatus(
                    target=team.host,
                    exploit_id=exploit_id,
                    commit_id=expl_info["latest_commit_id"],
                    team_data=TeamDTO.model_dump(team, mode="python", exclude_unset=False)
                )

    def time_to_wait_for_next_timeout(self) -> int:
        return max(0, self.TIMEOUT_SEND_INTERVAL - (time.time() - self.last_timeout_sent))
    
    def time_to_wait_for_next_loop(self) -> int:
        return max(0, self.deadline.timestamp() - time.time())
    
    async def timeout_update_handle(self):
        if self.time_to_wait_for_next_timeout() <= 0:
            if self.last_timeout_value_sent != self.timeout:
                await asyncio.gather(
                    sio_server.send(
                        json_like(GroupRequestEvent(
                            event=GroupEventRequestType.DYNAMIC_TIMEOUT,
                            group_id=self.group_id,
                            data={ "timeout": self.timeout }
                        )),
                        room=f"group:{self.group_id}:room"
                    ),
                    redis_conn.set(f"group:{self.group_id}:timeout", self.timeout)
                )
                self.last_timeout_value_sent = self.timeout
            self.last_timeout_sent = time.time()       
    
    async def send_deadline_update(self):
        await sio_server.send(
            json_like(GroupRequestEvent(
                event=GroupEventRequestType.DEADLINE_TIMOEOUT,
                group_id=self.group_id,
                data={ "deadline": self.deadline.isoformat() }
            )),
            room=f"group:{self.group_id}:room"
        )
    
    async def send_running_status(self):
        await sio_server.send(
            json_like(GroupRequestEvent(
                event=GroupEventRequestType.RUNNING_STATUS,
                group_id=self.group_id,
                data={ "running": len(g.manager.client_table) > 0 }
            )),
            room=f"group:{self.group_id}:room"
        )
    
    async def send_killall_request(self):
        await sio_server.send(
            json_like(GroupRequestEvent(
                event=GroupEventRequestType.KILLALL_ATTACKS,
                group_id=self.group_id
            )),
            room=f"group:{self.group_id}:room"
        )
    
    async def send_kill_exploit_request(self, exploit_id: str):
        await sio_server.send(
            json_like(GroupRequestEvent(
                event=GroupEventRequestType.ATTACK_KILL_EXPLOIT,
                group_id=self.group_id,
                data={ "exploit_id": exploit_id }
            )),
            room=f"group:{self.group_id}:room"
        )
    
    async def wait_next_loop(self):
        timeout = min(
            self.time_to_wait_for_next_timeout(),
            self.time_to_wait_for_next_loop()
        )
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except TimeoutError:
            return None
    
    async def trigger_attack_start_no_lock(self, client_id: str, target: AttackTargetStatus):
        await sio_server.send(
            json_like(GroupRequestEvent(
                event=GroupEventRequestType.ATTACK_REQUEST,
                group_id=self.group_id,
                data={ 
                    "target": target.team_data,
                    "exploit_id": target.exploit_id,
                    "commit_id": target.commit_id
                }
            )),
            to=self.client_table[client_id].sid
        )

    async def trigger_exploit_pull(self):
        if not self.source_pull_required:
            return
        await sio_server.send(
            json_like(GroupRequestEvent(
                event=GroupEventRequestType.EXPLOIT_PULL,
                group_id=self.group_id,
                data={ "exploit_ids": list(self.source_pull_required) }
            )),
            room=f"group:{self.group_id}:room"
        )
        self.source_pull_required.clear()
    
    async def recalculate_timeout(self, trigger_skio_update: bool = False, reset_virtual_time: bool = False):
        if reset_virtual_time:
            self.current_virtual_time = sum(ele.queue_size * self.tot_time_available for ele in self.client_table.values())
        
        tot_targets = len(g.teams) * len(g.exploits)
        if tot_targets == 0:
            self.timeout = 0
        else:
            self.timeout = max(min(math.ceil(self.current_virtual_time / tot_targets), g.configuration.TICK_DURATION), 0)
            
        if trigger_skio_update:
            self.last_timeout_sent = 0
            await self.timeout_update_handle()
    
    async def calc_client_status(self) -> list[tuple[float, ClinetAttackerStatus]]:
        if len(self.client_table) == 0:
            return []
        min_factor = min(max(ele.queue_size, 1) for ele in self.client_table.values())
        client_status = [(ele.prio_assign(min_factor), ele) for ele in self.client_table.values()]
        client_status.sort(key=lambda x: x[0], reverse=True)
        return client_status
    
    async def attack_run_actions(self):
        if g.configuration is None:
            return
        async with self.client_table_lock:
            async with self.attack_target_table_lock:
                if self.time_to_wait_for_next_loop() <= 0:
                    await self.send_killall_request()
                    if len(self.source_pull_required) > 0:
                        await self.trigger_exploit_pull()
                    for ele in self.attack_target_table.values():
                        for ele2 in ele.values():
                            ele2.reset()
                    for ele in self.client_table.values():
                        ele.reset()
                    
                    self.tot_time_available = calc_round_time_available()
                    self.deadline = datetime_now() + timedelta(seconds=self.tot_time_available)
                    await self.send_deadline_update()
                    await self.recalculate_timeout(trigger_skio_update=True, reset_virtual_time=True)
                targets_to_exec = []
                for expl in self.attack_target_table.values():
                    targets_to_exec.extend(
                        [ele for ele in expl.values() if not ele.executed and ele.assigned_to is None]
                    )
                if len(targets_to_exec) == 0:
                    return
                
                random.shuffle(targets_to_exec)
                client_status = await self.calc_client_status()
                
                if len(client_status) == 0:
                    return
                
                if client_status[0][0] == 0:
                    return
                
                # 1st assign phase
                while client_status[0][0] >= 1 and len(targets_to_exec) > 0:
                    for prio, client in client_status:
                        if prio < 1:
                            break
                        for _ in range(math.floor(prio)):
                            if len(targets_to_exec) == 0: return
                            target_to_attack = targets_to_exec.pop()
                            client.assign(target_to_attack)
                            await self.trigger_attack_start_no_lock(client.client_id, target_to_attack)
                    client_status = await self.calc_client_status()
                
                # 2nd assign phase
                while client_status[0][0] > 0 and len(targets_to_exec) > 0:
                    for prio, client in client_status:
                        if prio == 0:
                            break
                        target_to_attack = targets_to_exec.pop()
                        client.assign(target_to_attack)
                        await self.trigger_attack_start_no_lock(client.client_id, target_to_attack)
                        if len(targets_to_exec) == 0:
                            return
                    client_status = await self.calc_client_status()
    
    async def __task(self):
        await self.generate_attack_targets()
        while True:
            try:
                await self.timeout_update_handle()
                await self.attack_run_actions()
                await self.wait_next_loop()
            except Exception as e:
                logging.exception(f"Error in global group task: {e}")
                traceback.print_exc()
                await asyncio.sleep(5)
    
    def trigger_next_loop(self, data="trigger"):
        self.queue.put_nowait(data)
    
    async def handle_request(self, request: GroupResponseEvent):
        match request.event:
            case GroupEventResponseType.SET_RUNNING_STATUS:
                await self.send_running_status()
                await self.loop_reset()
            case GroupEventResponseType.ATTACK_ENDED:
                async with self.client_table_lock:
                    async with self.attack_target_table_lock:
                        key_exploit = request.data.get("exploit_id")
                        key_target = request.data.get("target")
                        if key_exploit in self.attack_target_table and key_target in self.attack_target_table[key_exploit] and request.client in self.client_table:
                            target = self.attack_target_table[key_exploit][key_target]
                            client = self.client_table[request.client]
                            if target.assigned_to == request.client:
                                client.end(target, request.data.get("n_flags", 0))
                                
                                time_used = client.delta_from_start()
                                self.current_virtual_time += self.timeout - time_used.total_seconds()
                                await self.recalculate_timeout()
                self.trigger_next_loop()
    
    def delta_until_deadline(self) -> int:
        return self.deadline.timestamp() - time.time()
    
    async def handle_join(self, client_id: str, sid: str, queue_size: int):
        async with self.client_table_lock:
            self.client_table[client_id] = ClinetAttackerStatus(
                client_id=client_id,
                sid=sid,
                queue_size=queue_size
            )
            # Add the new client's capacity to the virtual time pool
            self.current_virtual_time += self.delta_until_deadline() * queue_size
            
        # Do NOT loop_reset(). Just recalculate timeout and trigger assignment.
        await self.recalculate_timeout(trigger_skio_update=True)
        await redis_conn.publish(redis_channels.workers, "worker_pool_update")
        
        # We trigger the loop so the new worker gets tasks immediately
        self.trigger_next_loop()
        return self.timeout, self.deadline
    
    async def __kill_and_reset_exploit(self, exploit_id: str, fetch_new_targets: bool):
        await self.send_kill_exploit_request(exploit_id)
        async with self.attack_target_table_lock:
            if exploit_id in self.attack_target_table:
                # Forcefully reclaim used queues
                for target in self.attack_target_table[exploit_id].values():
                    if target.assigned_to and target.assigned_to in self.client_table:
                        self.client_table[target.assigned_to].used_queues = max(0, self.client_table[target.assigned_to].used_queues - 1)
                del self.attack_target_table[exploit_id]
        if fetch_new_targets:
            await self.generate_attack_targets(exploit_id)

    async def handle_commits_changed(self, changed_exploits: list[str] = None):
        if not changed_exploits:
            return
        self.source_pull_required.update(changed_exploits)
        for exploit_id in changed_exploits:
            await self.__kill_and_reset_exploit(exploit_id, fetch_new_targets=True)
        await self.recalculate_timeout(trigger_skio_update=True)
        self.trigger_next_loop()
    
    async def handle_exploits_changed(self, added: list[str] = None, removed: list[str] = None):
        if removed:
            for exploit_id in removed:
                await self.__kill_and_reset_exploit(exploit_id, fetch_new_targets=False)
        if added:
            for exploit_id in added:
                await self.generate_attack_targets(exploit_id)
        await self.recalculate_timeout(trigger_skio_update=True)
        self.trigger_next_loop()
    
    async def handle_leave(self, client_id: str):
        await disconnect_client(client_id)
        async with self.client_table_lock:
            if client_id in self.client_table:
                self.current_virtual_time -= self.delta_until_deadline() * self.client_table[client_id].queue_size
                for ele in self.attack_target_table.values():
                    for data in ele.values():
                        if not data.executed and data.assigned_to == client_id:
                            data.reset()
                del self.client_table[client_id]
                await self.recalculate_timeout(trigger_skio_update=True)
                await redis_conn.publish(redis_channels.workers, "worker_pool_update")
        self.trigger_next_loop()
    
    async def loop_reset(self):
        self.deadline = datetime_now()
        self.last_timeout_sent = 0
        self.last_timeout_value_sent = 0
        self.current_virtual_time = 0
        await asyncio.gather(
            self.send_deadline_update(),
            self.recalculate_timeout(trigger_skio_update=True)
        )
        self.trigger_next_loop()
    
    async def handle_config_changed(self):
        await self.loop_reset()
    
    async def handle_teams_changed(self):
        async with self.attack_target_table_lock:
            await self.generate_attack_targets()
        await self.recalculate_timeout(trigger_skio_update=True)
        self.trigger_next_loop()

async def update_worker_exploits_info():
    async with dbtransaction() as db:
        exploits = (await db.scalars(sqla.select(Exploit).where(Exploit.run_on_workers == True))).all()
        
        old_exploits = { str(e["exploit"].id): e["latest_commit_id"] for e in g.exploits }
        new_exploit_ids = [str(expl.id) for expl in exploits]
        
        added_exploits = [eid for eid in new_exploit_ids if eid not in old_exploits.keys()]
        removed_exploits = [eid for eid in old_exploits.keys() if eid not in new_exploit_ids]
        changed_exploits = []
        
        exploits_info = []
        for expl in exploits:
            latest_source = (await db.scalars(
                sqla.select(ExploitSource)
                .where(ExploitSource.exploit_id == expl.id)
                .order_by(ExploitSource.pushed_at.desc())
                .limit(1)
            )).one_or_none()
            
            commit_id = latest_source.hash if latest_source else None
            exploits_info.append({
                "exploit": expl,
                "latest_commit_id": commit_id
            })
            
            if str(expl.id) in new_exploit_ids and str(expl.id) not in added_exploits:
                if old_exploits.get(str(expl.id)) != commit_id:
                    changed_exploits.append(str(expl.id))
                
        g.exploits = exploits_info
    if g.manager:
        if changed_exploits:
            await g.manager.handle_commits_changed(changed_exploits)
        if added_exploits or removed_exploits:
            await g.manager.handle_exploits_changed(added_exploits, removed_exploits)

async def get_latest_exploit_source(exploit_id):
    async with dbtransaction() as db:
        stmt = (
            sqla.select(ExploitSource)
                .where(ExploitSource.exploit_id == exploit_id)
                .order_by(ExploitSource.pushed_at.desc())
                .limit(1)
        )
        return await db.scalar(stmt)

async def exploit_source_watcher():
    async with redis_conn.pubsub() as pubsub:
        await pubsub.subscribe(redis_channels.exploit_source)
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=None)
            if message:
                await update_worker_exploits_info()

async def exploit_watcher():
    async with redis_conn.pubsub() as pubsub:
        await pubsub.subscribe(redis_channels.exploit)
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=None)
            if message:
                await update_worker_exploits_info()

async def update_config_info():
    g.configuration = await Configuration.get_from_db()
    if g.manager:
        await g.manager.handle_config_changed()

async def update_teams_info():
    async with dbtransaction() as db:
        g.teams = list((await db.scalars(sqla.select(Team))).all())
    if g.manager:
        await g.manager.handle_teams_changed()

async def redis_cleaner():
    group_keys = await redis_conn.keys(f"group:{WORKERS_POOL_ID}:*")
    if len(group_keys) > 0:
        await redis_conn.delete(*group_keys)

@rpc_redis.call_handler("leave-global-group")
async def leave_group(sid:str, client: str):
    keys_to_delete = await redis_conn.keys(f"group:{WORKERS_POOL_ID}:client:{client}:*")
    # sid is shared mapping, we shouldn't delete `sid:{sid}:*` recklessly unless we uniquely manage it, 
    # but since this mimics group_manager logic, it's ok.
    sid_associated_keys = await redis_conn.keys(f"sid:{sid}:*")
    await asyncio.gather(
        redis_conn.delete(*keys_to_delete, *sid_associated_keys),
        redis_conn.srem(f"group:{WORKERS_POOL_ID}:members", client),
        sio_server.leave_room(sid, f"group:{WORKERS_POOL_ID}:room"),
    )
    if g.manager:
        await g.manager.handle_leave(client)

@rpc_redis.call_handler("event-workers")
async def event_group(sid: str, response_req: GroupResponseEvent):
    if g.manager:
        await g.manager.handle_request(response_req)
    return {"message": "handled", "status": ResponseStatus.OK}

@rpc_redis.call_handler("join-workers")
async def join_group(sid, join_req: JoinRequest):
    members = await redis_conn.smembers(f"group:{WORKERS_POOL_ID}:members")
    if join_req.client.encode() in members:
        return {"status": ResponseStatus.ERROR, "message": "Client already in the group"}
    
    await asyncio.gather(
        redis_conn.mset({
            f"group:{WORKERS_POOL_ID}:client:{join_req.client}:sid": sid,
            f"group:{WORKERS_POOL_ID}:client:{join_req.client}:queue_size": join_req.queue_size,
            f"sid:{sid}:group": WORKERS_POOL_ID,
            f"sid:{sid}:client": join_req.client
        }),
        redis_conn.sadd(f"group:{WORKERS_POOL_ID}:members", join_req.client),
        sio_server.enter_room(sid, f"group:{WORKERS_POOL_ID}:room"),
    )
    
    timeout, deadline = await g.manager.handle_join(str(join_req.client), sid, join_req.queue_size)
    return {"message": "joined", "status": ResponseStatus.OK, "response": {
        "timeout": timeout,
        "deadline": deadline,
        "running": True
    }}

async def generate_config_update_tasks():
    await update_config_info()
    await update_teams_info()
    await update_worker_exploits_info()

    async def listener_config_update():
        async with redis_conn.pubsub() as pubsub:
            await pubsub.subscribe(redis_channels.config)
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=None)
                if message:
                    await update_config_info()
                    
    async def listener_teams_update():
        async with redis_conn.pubsub() as pubsub:
            await pubsub.subscribe(redis_channels.team)
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=None)
                if message:
                    await update_teams_info()
                    
    g.task_list.extend([
        asyncio.create_task(listener_config_update()),
        asyncio.create_task(listener_teams_update()),
        asyncio.create_task(exploit_watcher()),
        asyncio.create_task(exploit_source_watcher())
    ])

async def tasks_init():
    try:
        await connect_db()
        await redis_cleaner()
        g.manager = WorkersManager()
        await generate_config_update_tasks()
        redis_tasks = rpc_redis.create_tasks()
        logging.info("Global Group manager started")
        await asyncio.gather(*redis_tasks, *g.task_list)
    except KeyboardInterrupt:
        pass
    finally:
        await close_db()

def inital_setup():
    try:
        while True:
            try:
                g.task_list = []
                # Always ensure a fresh redis_conn tied to the new loop
                import db
                import redis.asyncio as redis
                from env import DEBUG
                global redis_conn, rpc_redis
                # Reset the global connection in db.py to force a fresh connection pool and new locks
                db.redis_conn = redis.Redis(host='localhost' if DEBUG else 'redis', port=6379)
                redis_conn = db.redis_conn
                rpc_redis.redis_conn = redis_conn

                with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
                    runner.run(tasks_init())
            except Exception as e:
                traceback.print_exc()
                logging.exception(f"Global Group SocketIO loop failed: {e}, restarting loop")
                time.sleep(10)
    except (KeyboardInterrupt, StopLoop):
        logging.info("SocketIO stopped by KeyboardInterrupt")
    except (TimeoutError, asyncio.TimeoutError):
        logging.error("Something went wrong with the communication with the client!!")

def run_workers_manager_daemon() -> Process:
    p = Process(target=inital_setup)
    p.start()
    return p
