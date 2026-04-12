from exploitfarm.models.groups import GroupDTO, AddGroupForm, EditGroupForm
from exploitfarm.models.groups import WorkersGroupDTO
from exploitfarm.models.response import MessageResponse
from exploitfarm.models.enums import GroupStatus
from exploitfarm.models.groups import WorkerClientInfoDTO
from typing import List
from fastapi import APIRouter, HTTPException
from utils import json_like
from db import DBSession, Exploit, sqla
from db import redis_channels, redis_conn, AttackGroupID
from db import AttackGroup
from typing import Tuple
from utils.query import get_groups_with_latest_attack
import asyncio
from db import AttackExecution
from models.config import Configuration, SetupStatus

router = APIRouter(prefix="/groups", tags=["Attack Groups"])

@router.get("", response_model=List[GroupDTO])
async def group_get(db: DBSession):
    groups = await get_groups_with_latest_attack(db)
    async def result(result: sqla.Row[Tuple[AttackGroup, AttackExecution]]):
        group, latest_attack = result.tuple()
        members = await redis_conn.smembers(f"group:{group.id}:members")
        status = GroupStatus.active
        if members is None or len(members) == 0:
            status = GroupStatus.inactive
            members = set()
        return GroupDTO(
            **json_like(group, mode="python", unset=True),
            last_attack_at=latest_attack.received_at if latest_attack else None,
            members=members,
            status=status
        )
    return await asyncio.gather(*[result(ele) for ele in groups])

@router.get("/workers", response_model=WorkersGroupDTO)
async def workers_pool_status(db: DBSession):
    """Return live status of the workers pool (not a DB-backed group)."""
    members_raw = await redis_conn.smembers(f"group:workers:members")
    members = [m.decode() if isinstance(m, bytes) else m for m in members_raw]
    exploits = (await db.execute(sqla.select(Exploit.id).where(Exploit.run_on_workers == True))).scalars().all()
    timeout = await redis_conn.get("group:workers:timeout")
    timeout = int(timeout) if timeout else None
    worker_clients = []
    if members:
        for client_id in members:
            # Safely fetch properties from redis directly
            queue_size_raw = await redis_conn.get(f"group:workers:client:{client_id}:queue_size")
            sid_raw = await redis_conn.get(f"group:workers:client:{client_id}:sid")
            worker_clients.append(WorkerClientInfoDTO(
                id=client_id,
                sid=sid_raw.decode() if isinstance(sid_raw, bytes) else (sid_raw or ""),
                queue_size=int(queue_size_raw) if queue_size_raw else 1,
            ))
            
    return WorkersGroupDTO(
        id = "workers",
        name = "Workers",
        members = members,
        clients = worker_clients,
        exploits= exploits,
        timeout=timeout,
        status=GroupStatus.active if len(members) > 0 else GroupStatus.inactive
    )

@router.post("", response_model=MessageResponse[GroupDTO])
async def new_group(data: AddGroupForm, db: DBSession):
    config = await Configuration.get_from_db()
    # This is useful to avoid unexpected errors causing to start a group without a setup
    if config.SETUP_STATUS == SetupStatus.SETUP:
        raise HTTPException(400, "Setup is not completed, can't create groups")
    group = (await db.scalars(
        sqla.insert(AttackGroup)
            .values(data.db_data())
            .returning(AttackGroup)
    )).one()
    await db.commit()
    await redis_conn.publish(redis_channels.attack_group, f"add:{group.id}")
    return { "message": "Group created successfully", "response": json_like(group, unset=True) }

@router.delete("/{group_id}", response_model=MessageResponse[GroupDTO])
async def delete_group(group_id: AttackGroupID, db: DBSession):
    result = (await db.scalars(
        sqla.delete(AttackGroup)
            .where(AttackGroup.id == group_id)
            .returning(AttackGroup)
    )).one_or_none()
    if not result:
        raise HTTPException(404, "Group not found")
    await db.commit()
    await redis_conn.publish(redis_channels.attack_group, f"delete:{result.id}")
    return { "message": "Client deleted successfully", "response": json_like(result, unset=True) }

@router.put("/{group_id}", response_model=MessageResponse[GroupDTO])
async def client_edit(group_id: AttackGroupID, data: EditGroupForm, db: DBSession):
    group = (await db.scalars(
        sqla.update(AttackGroup)
        .values(json_like(data))
        .where(AttackGroup.id == group_id)
        .returning(AttackGroup)
    )).one_or_none()
    if not group:
        raise HTTPException(404, "Group not found")
    await db.commit()
    await redis_conn.publish(redis_channels.attack_group, f"update:{group.id}")
    return { "message": "Group updated successfully", "response": json_like(group, unset=True) }