"""Webhook routes for third-party integrations."""

from typing import List, Union
from fastapi import APIRouter, Header, HTTPException, Request, BackgroundTasks
from app.config import load_config
from app.wazuh.client import WazuhClient
from app.core.pipeline.orchestrator import PipelineOrchestrator
from app.core.logger import logger

router = APIRouter()

@router.post("/wazuh")
async def wazuh_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: Union[str, None] = Header(None)
):
    """
    Receive alerts directly from Wazuh Integrations (Push Model).
    """
    try:
        from app.settings.models import settings_manager
        from app.config import build_typed_configs
        
        # Ensure settings are loaded
        if not settings_manager._loaded:
            await settings_manager.reload()
            
        configs = build_typed_configs(settings_manager)
        wazuh_cfg = configs["wazuh"]

        # Check API key if configured
        if wazuh_cfg.webhook_api_key:
            if x_api_key != wazuh_cfg.webhook_api_key:
                logger.warning("Unauthorized webhook attempt (invalid API key)")
                raise HTTPException(status_code=401, detail="Unauthorized")

        data = await request.json()
        if not data:
            raise HTTPException(status_code=400, detail="No JSON payload")

        # Wazuh integrations can send a dict or list
        alerts = data if isinstance(data, list) else [data]

        # Parse alerts to findings using WazuhClient parser
        wazuh_client = WazuhClient(wazuh_cfg)
        findings_list = []
        for alert in alerts:
            finding = wazuh_client._alert_to_finding(alert)
            if finding:
                findings_list.append(finding)

        if not findings_list:
            return {"status": "ok", "message": "No actionable alerts found"}

        # Trigger pipeline in background
        orchestrator = PipelineOrchestrator()
        background_tasks.add_task(orchestrator.process_batch, findings_list)

        return {
            "status": "ok", 
            "message": f"Processing {len(findings_list)} findings in background"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Wazuh webhook processing failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
