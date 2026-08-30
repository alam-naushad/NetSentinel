from pydantic import BaseModel, ConfigDict, field_validator
from typing import Optional, Any, Union, List

class ZeekConnectionRecord(BaseModel):
    model_config = ConfigDict(extra='ignore')
    
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    proto: str
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None
    local_orig: Optional[bool] = None
    local_resp: Optional[bool] = None
    missed_bytes: Optional[int] = None
    history: Optional[str] = None
    orig_pkts: Optional[int] = None
    orig_ip_bytes: Optional[int] = None
    resp_pkts: Optional[int] = None
    resp_ip_bytes: Optional[int] = None
    tunnel_parents: Optional[str] = None

    @field_validator('tunnel_parents', mode='before')
    @classmethod
    def normalize_tunnel_parents(cls, v: Any) -> Optional[str]:
        if v is None or v == '' or v == [] or v == '-' or v == '(empty)':
            return None
        if isinstance(v, (list, set, tuple)):
            return ','.join(str(item) for item in v) if v else None
        return str(v)

    @field_validator('service', 'conn_state', 'history', mode='before')
    @classmethod
    def normalize_string_dash(cls, v: Any) -> Optional[str]:
        if v is None or v == '' or v == '-' or v == '(empty)':
            return None
        return str(v)
