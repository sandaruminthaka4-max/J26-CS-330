"""
SDN Mitigation Webhook Dispatcher.
Dispatches structured reconnaissance alert payloads to the SDN zero-touch mitigation controller
with exponential backoff, timeout handling, and deduplication.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


class SDNMitigationClient:
    """
    Client for delivering alerts to the SDN zero-touch mitigation engine.
    """

    def __init__(
        self,
        endpoint_url: str = "http://localhost:8080/api/v1/mitigation/alert",
        timeout_seconds: float = 3.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        self.endpoint_url = endpoint_url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._sent_alert_ids = set()

    def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronously posts an alert to the mitigation controller with retries.
        """
        alert_id = alert_payload.get("alert_id")

        # Deduplication protection
        if alert_id in self._sent_alert_ids:
            logger.info(f"Duplicate alert {alert_id} suppressed from re-dispatch.")
            return {"status": "DUPLICATE_SUPPRESSED", "alert_id": alert_id}

        headers = {
            "Content-Type": "application/json",
            "X-Source-Component": "IoMT-Reconnaissance-IDS",
        }

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                t0 = time.perf_counter()
                response = requests.post(
                    self.endpoint_url,
                    json=alert_payload,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                latency_ms = (time.perf_counter() - t0) * 1000.0

                if response.status_code in (200, 201, 202):
                    self._sent_alert_ids.add(alert_id)
                    data = response.json() if response.content else {}
                    logger.info(
                        f"Alert {alert_id} successfully delivered to SDN controller in {latency_ms:.1f}ms."
                    )
                    return {
                        "status": "DELIVERED",
                        "response_code": response.status_code,
                        "controller_ack": data,
                        "dispatch_latency_ms": round(latency_ms, 2),
                    }
                else:
                    logger.warning(
                        f"Mitigation controller returned HTTP {response.status_code} on attempt {attempt}: {response.text}"
                    )
            except requests.RequestException as e:
                last_error = str(e)
                logger.warning(f"Failed attempt {attempt} to reach SDN controller: {last_error}")

            if attempt < self.max_retries:
                time.sleep(self.backoff_factor * (2 ** (attempt - 1)))

        return {
            "status": "FAILED",
            "error": last_error or "Unknown error",
            "attempts": self.max_retries,
        }
