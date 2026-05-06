from exploitfarm.models.groups import GroupDTO, AddGroupForm, EditGroupForm
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
import uuid
from sqlalchemy.orm import selectinload

router = APIRouter(prefix="/groups", tags=["Attack Groups"])

async def build_group_dto(group: AttackGroup, latest_attack: AttackExecution | None) -> GroupDTO:
    members_raw = await redis_conn.smembers(f"group:{group.id}:members")
    members = [m.decode() if isinstance(m, bytes) else m for m in members_raw] if members_raw else []
    
    status = GroupStatus.active if members else GroupStatus.inactive
    
    timeout = await redis_conn.get(f"group:{group.id}:timeout")
    timeout = int(timeout) if timeout else None
    
    worker_clients = []
    for client_id in members:
        queue_size_raw = await redis_conn.get(f"group:{group.id}:client:{client_id}:queue_size")
        sid_raw = await redis_conn.get(f"group:{group.id}:client:{client_id}:sid")
        worker_clients.append(WorkerClientInfoDTO(
            id=client_id,
            sid=sid_raw.decode() if isinstance(sid_raw, bytes) else (sid_raw or ""),
            queue_size=int(queue_size_raw) if queue_size_raw else 1,
        ))
        
    return GroupDTO(
        id=group.id,
        name=group.name,
        members=worker_clients,
        exploits=[e.id for e in group.exploits],
        last_attack_at=latest_attack.received_at if latest_attack else None,
        status=status,
        timeout=timeout
    )

@router.get("", response_model=List[GroupDTO])
async def group_get(db: DBSession):
    groups = await get_groups_with_latest_attack(db)
    async def result(result: sqla.Row[Tuple[AttackGroup, AttackExecution]]):
        group, latest_attack = result.tuple()
        return await build_group_dto(group, latest_attack)
    return await asyncio.gather(*[result(ele) for ele in groups])

@router.post("", response_model=MessageResponse[GroupDTO])
async def new_group(data: AddGroupForm, db: DBSession):
    config = await Configuration.get_from_db()
    if config.SETUP_STATUS == SetupStatus.SETUP:
        raise HTTPException(400, "Setup is not completed, can't create groups")
    
    exploits = (await db.scalars(sqla.select(Exploit).where(Exploit.id.in_(data.exploits)))).all()
    if len(exploits) != len(data.exploits):
        raise HTTPException(404, "One or more exploits not found")
    
    for exploit in exploits:
        if exploit.group_id is not None:
            raise HTTPException(400, f"Exploit {exploit.id} is already assigned to another group")
        
    group = AttackGroup(**data.db_data())
    group.exploits = list(exploits)
    
    db.add(group)
    await db.commit()
    await db.refresh(group)
    await redis_conn.publish(redis_channels.attack_group, f"add:{group.id}")
    
    return { "message": "Group created successfully", "response": GroupDTO(
        id=group.id,
        name=group.name,
        members=[],
        exploits=[e.id for e in exploits],
        last_attack_at=None,
        status=GroupStatus.inactive,
        timeout=None
    ) }

@router.delete("/{group_id}", response_model=MessageResponse[GroupDTO])
async def delete_group(group_id: AttackGroupID, db: DBSession):
    if group_id == uuid.UUID(int=0):
        raise HTTPException(400, "Cannot delete the default group")
        
    group = (await db.scalars(
        sqla.select(AttackGroup)
            .where(AttackGroup.id == group_id)
    )).one_or_none()
    
    if not group:
        raise HTTPException(404, "Group not found")
        
    await db.delete(group)
    await db.commit()
    await redis_conn.publish(redis_channels.attack_group, f"delete:{group.id}")
    return { "message": "Group deleted successfully", "response": GroupDTO(
        id=group.id,
        name=group.name,
        members=[],
        exploits=[],
        last_attack_at=None,
        status=GroupStatus.inactive,
        timeout=None
    ) }

@router.put("/{group_id}", response_model=MessageResponse[GroupDTO])
async def group_edit(group_id: AttackGroupID, data: EditGroupForm, db: DBSession):
    if group_id == uuid.UUID(int=0):
        data.name = None
    
    group = (await db.scalars(
        sqla.select(AttackGroup)
        .options(selectinload(AttackGroup.exploits))
        .where(AttackGroup.id == group_id)
    )).one_or_none()
    
    if not group:
        raise HTTPException(404, "Group not found")
        
    for k, v in data.db_data().items():
        setattr(group, k, v)
        
    if data.exploits is not None:
        exploits = (await db.scalars(sqla.select(Exploit).where(Exploit.id.in_(data.exploits)))).all()
        if len(exploits) != len(data.exploits):
            raise HTTPException(404, "One or more exploits not found")
        for exploit in exploits:
            if exploit.group_id is not None and exploit.group_id != group_id:
                raise HTTPException(400, f"Exploit {exploit.id} is already assigned to another group")
        group.exploits = list(exploits)

    await db.commit()
    
    latest_attack = (await db.scalars(
        sqla.select(AttackExecution)
        .where(AttackExecution.executed_by_group_id == group_id)
        .order_by(AttackExecution.received_at.desc())
        .limit(1)
    )).one_or_none()

    await redis_conn.publish(redis_channels.attack_group, f"update:{group.id}")
    dto = await build_group_dto(group, latest_attack)
    return { "message": "Group updated successfully", "response": dto }