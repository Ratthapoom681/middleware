"""Redmine Pydantic schemas."""

from pydantic import BaseModel
from typing import Optional


class RedmineTicketCreate(BaseModel):
    subject: str
    description: str
    priority_id: int = 2
    tracker_id: Optional[int] = None
