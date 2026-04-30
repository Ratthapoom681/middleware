"""Debug: trace impossible-travel via full pipeline (process_batch)."""
import sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from src.config import load_config
from src.sources.wazuh_client import WazuhClient
from src.pipeline.detection_engine import DetectionEngine
from src.pipeline.detection_store import DetectionAlertStore
from src.main import MiddlewarePipeline
from tools.simulate_wazuh_integration import build_alert, load_sample
from pathlib import Path
import json, tempfile

sample = load_sample(Path("samples/wazuh_fortigate_failed_login_indexer_hit.json"))
temp_dir = tempfile.mkdtemp(prefix="detect-test-")

print("=" * 60)
print("IMPOSSIBLE TRAVEL: Full pipeline, 2 separate webhook calls")
print("=" * 60)

temp_db = os.path.join(temp_dir, "travel.db")

for idx in range(1, 3):
    config = load_config("config/config.yaml")
    wazuh_client = WazuhClient(config.wazuh)
    
    alert = build_alert(
        sample, global_index=idx, scenario="impossible-travel",
        scenario_index=idx, srcip="85.11.187.20",
        agent_name="wazuh-server", payload_format="indexer",
    )
    finding = wazuh_client._alert_to_finding(alert)

    pipeline = MiddlewarePipeline(config)
    if pipeline.detection_store:
        pipeline.detection_store.close()
    pipeline.detection_store = DetectionAlertStore(db_path=temp_db)
    pipeline.detection_engine.set_alert_store(pipeline.detection_store)

    try:
        pipeline.process_batch(
            [finding],
            event_context={"origin": "webhook", "alert_count": 1, "source_counts": {"wazuh": 1}},
        )
    finally:
        pipeline.close()

store = DetectionAlertStore(db_path=temp_db)
alerts = store.get_alerts()
print(f"\n  Detection alerts in DB: {len(alerts)}")
for a in alerts:
    print(f"    [{a['rule_type']}] {a['description'][:80]}")
store.close()

import shutil
shutil.rmtree(temp_dir, ignore_errors=True)
print("\nDone.")
