"""Pydantic schemas for Log API."""

from pydantic import BaseModel
from typing import Optional


class LogEntry(BaseModel):
    id: Optional[int] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    timestamp: Optional[str] = None
