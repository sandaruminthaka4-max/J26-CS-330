"""
schemas.py — Pydantic request and response schemas for the DoS Detection REST API
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class FlowFeatures(BaseModel):
    """
    Input schema representing SDN flow metadata received from OpenFlow statistics.
    All fields default safely to 0.0 to guarantee graceful degradation
    if certain OpenFlow counters or match fields are missing.
    """
    Header_Length: Optional[float] = Field(0.0, description="Total packet header length in bytes")
    Protocol_Type: Optional[float] = Field(0.0, alias="Protocol Type", description="Network protocol (e.g. 6=TCP, 17=UDP, 1=ICMP)")
    Duration: Optional[float] = Field(0.0, description="Flow duration in seconds")
    Rate: Optional[float] = Field(0.0, description="Packet rate (packets / sec)")
    Srate: Optional[float] = Field(0.0, description="Source-to-destination packet rate")
    Drate: Optional[float] = Field(0.0, description="Destination-to-source packet rate")
    fin_flag_number: Optional[float] = Field(0.0, description="Count/indicator of FIN TCP flag")
    syn_flag_number: Optional[float] = Field(0.0, description="Count/indicator of SYN TCP flag")
    rst_flag_number: Optional[float] = Field(0.0, description="Count/indicator of RST TCP flag")
    psh_flag_number: Optional[float] = Field(0.0, description="Count/indicator of PSH TCP flag")
    ack_flag_number: Optional[float] = Field(0.0, description="Count/indicator of ACK TCP flag")
    ece_flag_number: Optional[float] = Field(0.0, description="Count/indicator of ECE TCP flag")
    cwr_flag_number: Optional[float] = Field(0.0, description="Count/indicator of CWR TCP flag")
    ack_count: Optional[float] = Field(0.0, description="Cumulative count of ACK packets")
    syn_count: Optional[float] = Field(0.0, description="Cumulative count of SYN packets")
    fin_count: Optional[float] = Field(0.0, description="Cumulative count of FIN packets")
    rst_count: Optional[float] = Field(0.0, description="Cumulative count of RST packets")
    HTTP: Optional[float] = Field(0.0, description="HTTP protocol indicator")
    HTTPS: Optional[float] = Field(0.0, description="HTTPS protocol indicator")
    DNS: Optional[float] = Field(0.0, description="DNS protocol indicator")
    Telnet: Optional[float] = Field(0.0, description="Telnet indicator")
    SMTP: Optional[float] = Field(0.0, description="SMTP indicator")
    SSH: Optional[float] = Field(0.0, description="SSH indicator")
    IRC: Optional[float] = Field(0.0, description="IRC indicator")
    TCP: Optional[float] = Field(0.0, description="TCP protocol indicator")
    UDP: Optional[float] = Field(0.0, description="UDP protocol indicator")
    DHCP: Optional[float] = Field(0.0, description="DHCP indicator")
    ARP: Optional[float] = Field(0.0, description="ARP indicator")
    ICMP: Optional[float] = Field(0.0, description="ICMP protocol indicator")
    IGMP: Optional[float] = Field(0.0, description="IGMP indicator")
    IPv: Optional[float] = Field(0.0, description="IPv4/IPv6 indicator")
    LLC: Optional[float] = Field(0.0, description="LLC indicator")
    Tot_sum: Optional[float] = Field(0.0, alias="Tot sum", description="Total flow bytes sum")
    Min: Optional[float] = Field(0.0, description="Minimum packet length")
    Max: Optional[float] = Field(0.0, description="Maximum packet length")
    AVG: Optional[float] = Field(0.0, description="Average packet length")
    Std: Optional[float] = Field(0.0, description="Packet length standard deviation")
    Tot_size: Optional[float] = Field(0.0, alias="Tot size", description="Total flow size")
    IAT: Optional[float] = Field(0.0, description="Mean inter-arrival time")
    Number: Optional[float] = Field(0.0, description="Total packet count in flow")
    Magnitue: Optional[float] = Field(0.0, description="Magnitude metric")
    Radius: Optional[float] = Field(0.0, description="Variance radius metric")
    Covariance: Optional[float] = Field(0.0, description="Covariance metric")
    Variance: Optional[float] = Field(0.0, description="Variance metric")
    Weight: Optional[float] = Field(0.0, description="Flow weight metric")

    @field_validator("Duration", "Rate", "Srate", "Drate", mode="before")
    @classmethod
    def check_non_negative(cls, v):
        if v is not None and float(v) < 0:
            raise ValueError("Rate and Duration values cannot be negative.")
        return v

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "Duration": 2.5,
                "Rate": 45000.0,
                "Protocol Type": 6.0,
                "TCP": 1.0,
                "syn_flag_number": 1.0,
                "syn_count": 112500.0,
                "Number": 112500.0,
                "Tot sum": 6750000.0,
            }
        }
    }


class PredictionResponse(BaseModel):
    """
    Contract Response schema returned to the Mitigation Component.
    """
    prediction: str = Field(..., description="Classification result: 'Normal' or 'DoS'")
    is_dos: bool = Field(..., description="Boolean flag: True if DoS attack detected, False otherwise")
    confidence: float = Field(..., description="True model posterior probability for positive class [0.0, 1.0]")
    model_name: str = Field("XGBoost", description="Name of the inference model")
    inference_latency_ms: float = Field(..., description="Isolated model prediction time in milliseconds")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="UTC timestamp")


class HealthResponse(BaseModel):
    """
    System health check response schema.
    """
    status: str = Field(..., description="Overall health: 'ok' or 'degraded'")
    model_loaded: bool = Field(..., description="True if XGBoost model artifact is loaded in memory")
    model_path: str = Field(..., description="Path to model file")
    feature_count: int = Field(..., description="Number of model input features")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")


class ErrorResponse(BaseModel):
    """
    Standard error structure.
    """
    error: str
    detail: str
