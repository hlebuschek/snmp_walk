from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    nextCmd,
)
import asyncio

# Создание FastAPI приложения
app = FastAPI()

# Модель запроса для SNMP Walk
class SNMPWalkRequest(BaseModel):
    ip: str
    community: str = "public"
    oid: str = "1.3.6.1.2.1.1"  # Пример OID для системной информации

# Функция для выполнения SNMP Walk
async def snmp_walk(ip: str, community: str, oid: str):
    results = {}
    try:
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161), timeout=2, retries=2),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication:
                raise HTTPException(status_code=500, detail=f"SNMP Error: {errorIndication}")
            elif errorStatus:
                raise HTTPException(
                    status_code=500,
                    detail=f"SNMP Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                )
            else:
                for varBind in varBinds:
                    oid, value = varBind[0].prettyPrint(), varBind[1]
                    results[oid] = value.prettyPrint()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected Error: {str(e)}")

# Маршрут для выполнения SNMP Walk
@app.post("/snmp/walk")
async def snmp_walk_endpoint(request: SNMPWalkRequest):
    """
    Выполняет SNMP Walk на указанном устройстве и возвращает данные.
    """
    result = await snmp_walk(request.ip, request.community, request.oid)
    return {"results": result}

# Маршрут для выполнения SNMP Walk на нескольких устройствах
@app.post("/snmp/walk/bulk")
async def snmp_walk_bulk_endpoint(requests: list[SNMPWalkRequest]):
    """
    Выполняет SNMP Walk на нескольких устройствах параллельно и возвращает данные.
    """
    tasks = [snmp_walk(req.ip, req.community, req.oid) for req in requests]
    results = await asyncio.gather(*tasks)
    return {"results": results}

# Корневой маршрут
@app.get("/")
async def root():
    return {"message": "SNMP Walk API"}

# Маршрут для приветствия
@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}

# Запуск сервера
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
