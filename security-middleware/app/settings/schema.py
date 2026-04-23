"""Pydantic schemas for the Settings API."""

from pydantic import BaseModel
from typing import Any


class SettingsUpdate(BaseModel):
    config: dict[str, Any]


class SettingsResponse(BaseModel):
    section: str
    config: dict[str, Any]
