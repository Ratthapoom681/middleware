middleware/
├── main.py
├── requirements.txt
├── .env
├── .env.example
│
├── app/
│   ├── __init__.py
│   ├── config.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   ├── logger.py
│   │   ├── websocket.py
│   │   └── pipeline/
│   │       ├── __init__.py
│   │       ├── dedup.py
│   │       ├── filter.py
│   │       ├── map_severity.py
│   │       ├── m_logic.py
│   │       ├── t_enrich.py
│   │       └── t_logic.py
│   │
│   ├── defectdojo/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── client.py
│   │   ├── routes.py
│   │   └── schema.py
│   │
│   ├── wazuh/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── client.py
│   │   ├── routes.py
│   │   └── schema.py
│   │
│   ├── redmine/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── client.py
│   │   ├── routes.py
│   │   └── schema.py
│   │
│   ├── logs/
│   │   ├── __init__.py
│   │   ├── aggregator.py
│   │   ├── routes.py
│   │   └── schema.py
│   │
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── monitor.py
│   │   ├── dead_letter.py
│   │   └── routes.py
│   │
│   ├── scheduler/
│   │   ├── __init__.py
│   │   ├── jobs.py
│   │   └── routes.py
│   │
│   ├── settings/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── schema.py
│   │
│   ├── data_retention/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── backup.py
│   │   ├── cleanup.py
│   │   └── routes.py
│   │
│   └── audit/
│       ├── __init__.py
│       ├── models.py
│       ├── routes.py
│       └── schema.py
│
├── frontend/
│   ├── shared/
│   │   ├── style.css
│   │   ├── components.js
│   │   └── api.js
│   │
│   ├── main/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── main.js
│   │
│   ├── logs/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── logs.js
│   │
│   ├── defectdojo/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── defectdojo.js
│   │
│   ├── wazuh/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── wazuh.js
│   │
│   ├── redmine/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── redmine.js
│   │
│   ├── pipeline/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── pipeline.js
│   │
│   ├── audit/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── audit.js
│   │
│   └── setting/
│       ├── index.html
│       ├── style.css
│       └── setting.js
│
├── config/
│   └── rules/
│       ├── correlation_rules.yaml
│       ├── suppression_rules.yaml
│       └── severity_map.yaml
│
├── data/
│   ├── db/
│   ├── backup/
│   ├── logs/
│   └── cache/
│
└── tests/
    ├── __init__.py
    ├── test_defectdojo.py
    ├── test_wazuh.py
    ├── test_redmine.py
    ├── test_pipeline.py
    ├── test_logs.py
    ├── test_settings.py
    └── test_audit.py


Sidebar Menu:

Dashboard
──────────────
Logs
  ├─ All Sources
  ├─ DefectDojo
  ├─ Wazuh
  └─ Redmine
──────────────
Pipeline
──────────────
Audit Log
──────────────
Settings
  ├─ DefectDojo
  ├─ Wazuh
  ├─ Redmine
  ├─ Pipeline Rules
  ├─ Data Retention
  └─ System
		
Dedup Logic 
	data.srcip
	data.dstip
	data.dstport
	data.attack
