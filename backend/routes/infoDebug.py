from typing import List
from fastapi import APIRouter, HTTPException
from db import Service, AttackExecution , Exploit , DBSession, sqla, redis_conn, redis_channels, ServiceID
from exploitfarm.models.service import ServiceDTO, ServiceAddForm, ServiceEditForm
from exploitfarm.models.response import MessageResponse
from utils import json_like

router = APIRouter(prefix="/info", tags=["Info"])

@router.post("/info" , response_model = MessageResponse[ServiceDTO])
async def info(db : DBSession , name_service : str ):
    info = (await db.scalars(
        sqla.select(AttackExecution.flags)
        .join(Service.exploits)
        .join(Exploit.executions)
        .where(Service.name == name_service)
    )).one_or_none()
    if not info: 
        raise HTTPException(404 , "No info found")
    return info

async def build_return(db : DBSession):
    try:
        names = (await db.scalars(sqla.select(Service.name).all()))
    except:
        print("[ERROR] impossible to fetch the query")
    
    info_block = {}
    for name in names:
        flag_stolen = info(db , name)
        info_block[str(name)] = str(flag_stolen)
    
    return info_block

