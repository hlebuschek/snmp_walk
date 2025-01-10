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
from binascii import hexlify
import asyncio

# Создание FastAPI приложения
app = FastAPI()

# Модель запроса для SNMP Walk
class SNMPWalkRequest(BaseModel):
    ip: str
    community: str = "public"
    port: int = 161
    oid: str = "1.3.6.1"

# Функция для выполнения SNMP Walk
async def snmp_walk_with_error_handling(ip: str, community: str = "public", port: int = 161, oid: str = "1.3.6.1"):
    results = {}
    try:
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication:
                results["error"] = f"Ошибка соединения: {errorIndication}"
                continue
            elif errorStatus:
                results["error"] = (
                    f"Ошибка SNMP: {errorStatus.prettyPrint()} на объекте "
                    f"{errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                )
                continue
            else:
                for varBind in varBinds:
                    oid, value = varBind[0].prettyPrint(), varBind[1]
                    if isinstance(value, bytes):
                        decoded_value = hexlify(value).decode()
                        results[oid] = decoded_value
                    else:
                        results[oid] = value.prettyPrint()
        return results
    except Exception as e:
        results["error"] = f"Неожиданная ошибка: {str(e)}"
        return results

# Маршрут для выполнения SNMP Walk
@app.post("/snmp/")
async def snmp_walk(request: list[SNMPWalkRequest]):
    """
    Выполняет SNMP Walk на нескольких устройствах параллельно и возвращает данные.
    """
    tasks = [
        snmp_walk_with_error_handling(
            ip=req.ip,
            community=req.community,
            port=req.port,
            oid=req.oid
        ) for req in request
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [result if not isinstance(result, Exception) else {"error": str(result)} for result in results]

# Запуск сервера
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
