"""
Pydantic Request & Response Validation Schemas for Reconnaissance Detection API.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FlowFeaturesPayload(BaseModel):
    """
    Input schema representing a single network flow's features.
    Accepts raw unscaled values conforming to CICIoMT2024 schema.
    """
    flow_id: Optional[str] = Field(default=None, description="Unique flow transaction identifier")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    destination_port: Optional[int] = Field(default=None, description="Destination port number")
    is_critical_asset: Optional[bool] = Field(default=False, description="Whether target is a life-critical IoMT device")
    
    # 45 numerical flow features
    Header_Length: Optional[float] = 0.0
    Protocol_Type: Optional[float] = Field(default=0.0, alias="Protocol Type")
    Duration: Optional[float] = 0.0
    Rate: Optional[float] = 0.0
    Srate: Optional[float] = 0.0
    Drate: Optional[float] = 0.0
    fin_flag_number: Optional[float] = 0.0
    syn_flag_number: Optional[float] = 0.0
    rst_flag_number: Optional[float] = 0.0
    psh_flag_number: Optional[float] = 0.0
    ack_flag_number: Optional[float] = 0.0
    ece_flag_number: Optional[float] = 0.0
    cwr_flag_number: Optional[float] = 0.0
    ack_count: Optional[float] = 0.0
    syn_count: Optional[float] = 0.0
    fin_count: Optional[float] = 0.0
    rst_count: Optional[float] = 0.0
    HTTP: Optional[float] = 0.0
    HTTPS: Optional[float] = 0.0
    DNS: Optional[float] = 0.0
    Telnet: Optional[float] = 0.0
    SMTP: Optional[float] = 0.0
    SSH: Optional[float] = 0.0
    IRC: Optional[float] = 0.0
    TCP: Optional[float] = 0.0
    UDP: Optional[float] = 0.0
    DHCP: Optional[float] = 0.0
    ARP: Optional[float] = 0.0
    ICMP: Optional[float] = 0.0
    IGMP: Optional[float] = 0.0
    IPv: Optional[float] = 0.0
    LLC: Optional[float] = 0.0
    Tot_sum: Optional[float] = Field(default=0.0, alias="Tot sum")
    Min: Optional[float] = 0.0
    Max: Optional[float] = 0.0
    AVG: Optional[float] = 0.0
    Std: Optional[float] = 0.0
    Tot_size: Optional[float] = Field(default=0.0, alias="Tot size")
    IAT: Optional[float] = 0.0
    Number: Optional[float] = 0.0
    Magnitue: Optional[float] = 0.0
    Radius: Optional[float] = 0.0
    Covariance: Optional[float] = 0.0
    Variance: Optional[float] = 0.0
    Weight: Optional[float] = 0.0

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class BatchFlowPayload(BaseModel):
    flows: List[FlowFeaturesPayload]


class PredictionResponse(BaseModel):
    prediction: str
    attack_type: str
    recon_subtype: str
    confidence: float
    severity: str
    timestamp: str
    flow_id: str
    model_version: str
    alert_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    probabilities: Optional[Dict[str, float]] = None


class BatchPredictionResponse(BaseModel):
    count: int
    predictions: List[PredictionResponse]
    processing_time_ms: float


class ModelInfoResponse(BaseModel):
    model_name: str
    model_version: str
    champion_algorithm: str
    selected_feature_count: int
    selected_features: List[str]
    target_classes: List[str]
    status: str
