"""Pydantic schemas for Audit API."""

from pydantic import BaseModel
from typing import Optional


class AuditEntry(BaseModel):
    id: Optional[int] = None
    action: Optional[str] = None
    module: Optional[str] = None
    user: Optional[str] = "system"
    detail: Optional[str] = None
