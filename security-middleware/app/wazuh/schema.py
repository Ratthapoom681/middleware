"""Wazuh Pydantic schemas."""

from pydantic import BaseModel
from typing import Optional


class WazuhAlert(BaseModel):
    rule_id: Optional[str] = None
    level: Optional[int] = None
    description: Optional[str] = None
    agent_name: Optional[str] = None
    timestamp: Optional[str] = None
