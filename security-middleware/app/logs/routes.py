"""Logs API routes – unified log view + WebSocket streaming."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.logs import aggregator
from app.core.websocket import ws_manager

router = APIRouter()


@router.get("")
async def get_logs(source: str = "all", level: str = "all", limit: int = 100):
    """Get aggregated logs from all sources."""
    logs = await aggregator.get_aggregated_logs(source, level, limit)
    return {"logs": logs, "count": len(logs)}


@router.get("/stats")
async def get_stats():
    """Get log statistics for dashboard."""
    return await aggregator.get_log_stats()


@router.websocket("/stream")
async def log_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time log streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
