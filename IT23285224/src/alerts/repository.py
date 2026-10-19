"""
SQLite-Backed Alert Persistence Repository.
Provides transactional logging, alert history retrieval, and status updates.
"""

from contextlib import contextmanager
import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseAlertRepository(ABC):
    @abstractmethod
    def save_alert(self, alert: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        min_confidence: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def update_delivery_status(self, alert_id: str, status: str, action: Optional[str] = None) -> bool:
        pass


class SQLiteAlertRepository(BaseAlertRepository):
    """
    Thread-safe SQLite alert repository.
    """

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    recon_subtype TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    is_critical_asset INTEGER,
                    model_version TEXT,
                    delivery_status TEXT,
                    mitigation_action TEXT,
                    raw_data_json TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)")
            conn.commit()

    def save_alert(self, alert: Dict[str, Any]) -> str:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, flow_id, prediction, attack_type,
                    recon_subtype, confidence, severity, status, source_ip,
                    destination_ip, destination_port, is_critical_asset,
                    model_version, delivery_status, mitigation_action, raw_data_json
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    alert["alert_id"],
                    alert["timestamp"],
                    alert["flow_id"],
                    alert["prediction"],
                    alert["attack_type"],
                    alert["recon_subtype"],
                    alert["confidence"],
                    alert["severity"],
                    alert["status"],
                    alert.get("source_ip"),
                    alert.get("destination_ip"),
                    alert.get("destination_port"),
                    1 if alert.get("is_critical_asset") else 0,
                    alert.get("model_version"),
                    alert.get("delivery_status", "PENDING"),
                    alert.get("mitigation_action", "NONE"),
                    json.dumps(alert),
                ),
            )
            conn.commit()
        return alert["alert_id"]

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cur.fetchone()
            if row:
                return dict(row)
        return None

    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        min_confidence: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if min_confidence is not None:
            query += " AND confidence >= ?"
            params.append(min_confidence)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [dict(row) for row in cur.fetchall()]

    def update_delivery_status(self, alert_id: str, status: str, action: Optional[str] = None) -> bool:
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE alerts SET delivery_status = ?, mitigation_action = COALESCE(?, mitigation_action)
                WHERE alert_id = ?
                """,
                (status, action, alert_id),
            )
            conn.commit()
            return cur.rowcount > 0
