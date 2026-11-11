import time
import uuid
from typing import Dict, Any, List

class KafkaTelemetryEmitter:
    """
    Non-blocking async audit telemetry emitter for Apache Kafka and Superset FinOps dashboards.
    """
    def __init__(self):
        self.emitted_events: List[Dict[str, Any]] = []

    def emit_audit_event(
        self,
        tenant: str,
        user: str,
        secrecy_tier: str,
        cache_hit: bool,
        tokens_used: int,
        entities_detected: int,
        target_cloud: str
    ):
        event = {
            "event_id": str(uuid.uuid4()),
            "tenant": tenant,
            "user": user,
            "secrecy_tier": secrecy_tier,
            "cache_hit": cache_hit,
            "tokens_used": tokens_used,
            "entities_detected": entities_detected,
            "target_cloud": target_cloud,
            "timestamp": time.time()
        }
        self.emitted_events.append(event)
