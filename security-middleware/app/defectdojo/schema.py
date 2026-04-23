"""DefectDojo Pydantic schemas."""

from pydantic import BaseModel
from typing import Optional


class DefectDojoFinding(BaseModel):
    id: Optional[int] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    component_name: Optional[str] = None
