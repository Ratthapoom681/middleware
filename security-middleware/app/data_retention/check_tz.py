from datetime import datetime, timezone
import json

now_naive = datetime.utcnow()
now_aware = datetime.now(timezone.utc)

print(f"Naive: {now_naive.isoformat()}")
print(f"Aware: {now_aware.isoformat()}")

data = {
    "naive": now_naive.isoformat(),
    "aware": now_aware.isoformat()
}

print(f"JSON: {json.dumps(data)}")
