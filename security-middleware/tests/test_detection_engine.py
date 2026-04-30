import time
from datetime import datetime, timezone
import pytest

from src.config import DetectionConfig, DetectionRuleConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.detection_engine import DetectionEngine
from src.pipeline.detection_store import DetectionAlertStore


@pytest.fixture
def memory_store():
    store = DetectionAlertStore(db_path=":memory:")
    yield store
    store.close()


@pytest.fixture
def config():
    return DetectionConfig(
        enabled=True,
        rules=[
            DetectionRuleConfig(
                name="Brute Force Test",
                type="brute_force",
                enabled=True,
                cooldown_seconds=0,
                parameters={
                    "threshold": 3,
                    "window_seconds": 60,
                    "event_type_field": "data.status",
                    "event_type_value": "failed",
                    "group_by": "srcip"
                }
            ),
            DetectionRuleConfig(
                name="Abnormal Port Test",
                type="abnormal_port",
                enabled=True,
                cooldown_seconds=0,
                parameters={
                    "suspicious_ports": [4444, 1337],
                    "port_field": "dstport"
                }
            ),
            DetectionRuleConfig(
                name="Impossible Travel Test",
                type="impossible_travel",
                enabled=True,
                cooldown_seconds=0,
                parameters={
                    "max_travel_seconds": 3600,
                    "window_seconds": 3600,
                    "group_by": "user"
                }
            ),
            DetectionRuleConfig(
                name="Port Scan Test",
                type="port_scan",
                enabled=True,
                cooldown_seconds=0,
                parameters={
                    "threshold": 4,
                    "window_seconds": 60,
                    "group_by": "srcip",
                    "port_field": "dstport"
                }
            )
        ]
    )


@pytest.fixture
def engine(config, memory_store):
    eng = DetectionEngine(config)
    eng.set_alert_store(memory_store)
    return eng


def test_brute_force_detection(engine, memory_store):
    def failed_login(source_id: str) -> Finding:
        return Finding(
            source=FindingSource.WAZUH,
            source_id=source_id,
            title="Failed login",
            description="Test login",
            severity=Severity.LOW,
            timestamp=datetime.now(timezone.utc),
            srcip="10.0.0.1",
            raw_data={"data": {"status": "failed", "dstuser": "admin"}}
        )
    
    # 2 failures -> threshold is 3, so not triggered yet
    findings = [failed_login("1"), failed_login("2")]
    alerts = engine.evaluate(findings)
    assert len(alerts) == 0
    
    # 3rd failure -> triggers
    alerts = engine.evaluate([failed_login("3")])
    assert len(alerts) == 1
    assert alerts[0].rule_type == "brute_force"
    assert alerts[0].evidence["source_ip"] == "10.0.0.1"
    assert alerts[0].evidence["attempt_count"] == 3
    
    stored = memory_store.get_alerts()
    assert len(stored) == 1


def test_abnormal_port_detection(engine):
    f1 = Finding(
        source=FindingSource.WAZUH,
        source_id="1",
        title="Conn",
        description="Test conn",
        severity=Severity.INFO,
        timestamp=datetime.now(timezone.utc),
        srcip="10.0.0.1",
        dstport="80",
        raw_data={}
    )
    f2 = Finding(
        source=FindingSource.WAZUH,
        source_id="2",
        title="Conn",
        description="Test conn",
        severity=Severity.INFO,
        timestamp=datetime.now(timezone.utc),
        srcip="10.0.0.1",
        dstport="4444",
        raw_data={}
    )
    
    alerts = engine.evaluate([f1, f2])
    assert len(alerts) == 1
    assert alerts[0].rule_type == "abnormal_port"
    assert alerts[0].evidence["dstport"] == "4444"


def test_impossible_travel_detection(engine):
    ts1 = datetime.fromtimestamp(time.time() - 100, timezone.utc)
    ts2 = datetime.fromtimestamp(time.time(), timezone.utc)
    
    f1 = Finding(
        source=FindingSource.WAZUH,
        source_id="1",
        title="Login",
        description="Test login",
        severity=Severity.INFO,
        timestamp=ts1,
        srcip="1.1.1.1",
        src_country="US",
        raw_data={"data": {"user": "alice"}}
    )
    f2 = Finding(
        source=FindingSource.WAZUH,
        source_id="2",
        title="Login",
        description="Test login",
        severity=Severity.INFO,
        timestamp=ts2,
        srcip="2.2.2.2",
        src_country="CN",
        raw_data={"data": {"user": "alice"}}
    )
    
    # First login -> no alert
    alerts = engine.evaluate([f1])
    assert len(alerts) == 0
    
    # Second login from different country within 1 hour -> alert
    alerts = engine.evaluate([f2])
    assert len(alerts) == 1
    assert alerts[0].rule_type == "impossible_travel"
    assert alerts[0].evidence["user"] == "alice"
    assert alerts[0].evidence["country_1"] == "CN"
    assert alerts[0].evidence["country_2"] == "US"


def test_impossible_travel_persists_window_across_engine_instances(config, memory_store):
    ts1 = datetime.fromtimestamp(time.time() - 100, timezone.utc)
    ts2 = datetime.fromtimestamp(time.time(), timezone.utc)

    first_engine = DetectionEngine(config)
    first_engine.set_alert_store(memory_store)
    second_engine = DetectionEngine(config)
    second_engine.set_alert_store(memory_store)

    f1 = Finding(
        source=FindingSource.WAZUH,
        source_id="travel-1",
        title="Login",
        description="Test login",
        severity=Severity.INFO,
        timestamp=ts1,
        srcip="1.1.1.1",
        src_country="US",
        raw_data={"data": {"user": "alice"}},
    )
    f2 = Finding(
        source=FindingSource.WAZUH,
        source_id="travel-2",
        title="Login",
        description="Test login",
        severity=Severity.INFO,
        timestamp=ts2,
        srcip="2.2.2.2",
        src_country="CN",
        raw_data={"data": {"user": "alice"}},
    )

    assert first_engine.evaluate([f1]) == []
    alerts = second_engine.evaluate([f2])

    assert len(alerts) == 1
    assert alerts[0].rule_type == "impossible_travel"


def test_port_scan_detection(engine):
    findings = []
    # Connect to 3 distinct ports -> no alert (threshold is 3)
    for port in ["22", "80", "443"]:
        findings.append(Finding(
            source=FindingSource.WAZUH,
            source_id="ps1",
            title="Conn",
            description="Test conn",
            severity=Severity.INFO,
            timestamp=datetime.now(timezone.utc),
            srcip="192.168.1.100",
            dstport=port,
            raw_data={}
        ))
    
    alerts = engine.evaluate(findings)
    assert len(alerts) == 0
    
    # Connect to 4th port -> alert
    alerts = engine.evaluate([Finding(
        source=FindingSource.WAZUH,
        source_id="ps2",
        title="Conn",
        description="Test conn",
        severity=Severity.INFO,
        timestamp=datetime.now(timezone.utc),
        srcip="192.168.1.100",
        dstport="8080",
        raw_data={}
    )])
    
    assert len(alerts) == 1
    assert alerts[0].rule_type == "port_scan"
    assert alerts[0].evidence["distinct_port_count"] == 4
    assert alerts[0].evidence["source_ip"] == "192.168.1.100"


def test_port_scan_persists_window_across_engine_instances(config, memory_store):
    ports = ["22", "80", "443", "8080"]
    alerts = []

    for index, port in enumerate(ports, start=1):
        engine = DetectionEngine(config)
        engine.set_alert_store(memory_store)
        alerts = engine.evaluate([Finding(
            source=FindingSource.WAZUH,
            source_id=f"scan-{index}",
            title="Conn",
            description="Test conn",
            severity=Severity.INFO,
            timestamp=datetime.now(timezone.utc),
            srcip="192.168.1.100",
            dstport=port,
            raw_data={},
        )])

    assert len(alerts) == 1
    assert alerts[0].rule_type == "port_scan"
    assert alerts[0].evidence["distinct_port_count"] == 4

def test_cooldown_persists_across_engine_instances(config, memory_store):
    # Set cooldown high enough
    for rule in config.rules:
        if rule.type == "port_scan":
            rule.cooldown_seconds = 300

    ports = ["22", "80", "443", "8080"]
    alerts = []
    
    # Engine 1: Trigger the alert
    for index, port in enumerate(ports, start=1):
        engine1 = DetectionEngine(config)
        engine1.set_alert_store(memory_store)
        alerts = engine1.evaluate([Finding(
            source=FindingSource.WAZUH,
            source_id=f"scan-{index}",
            title="Conn",
            description="Test conn",
            severity=Severity.INFO,
            timestamp=datetime.now(timezone.utc),
            srcip="192.168.1.200",
            dstport=port,
            raw_data={},
        )])

    assert len(alerts) == 1
    
    # Engine 2: Send another port that would normally trigger it again, but cooldown should block it
    engine2 = DetectionEngine(config)
    engine2.set_alert_store(memory_store)
    alerts = engine2.evaluate([Finding(
        source=FindingSource.WAZUH,
        source_id="scan-5",
        title="Conn",
        description="Test conn",
        severity=Severity.INFO,
        timestamp=datetime.now(timezone.utc),
        srcip="192.168.1.200",
        dstport="9090",
        raw_data={},
    )])

    # Cooldown should prevent the second alert
    assert len(alerts) == 0
