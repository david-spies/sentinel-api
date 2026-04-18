"""
ai/core/models.py

Pydantic v2 schemas that mirror the Go models.go type system exactly.
All field names and JSON tags match the Go structs so the AI service can
deserialise payloads from the Go scanner without transformation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations (must match Go constants exactly)
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class OWASPCategory(str, Enum):
    API1  = "API1:2023 - Broken Object Level Authorization"
    API2  = "API2:2023 - Broken Authentication"
    API3  = "API3:2023 - Broken Object Property Level Authorization"
    API4  = "API4:2023 - Unrestricted Resource Consumption"
    API5  = "API5:2023 - Broken Function Level Authorization"
    API6  = "API6:2023 - Unrestricted Access to Sensitive Business Flows"
    API7  = "API7:2023 - Server Side Request Forgery"
    API8  = "API8:2023 - Security Misconfiguration"
    API9  = "API9:2023 - Improper Inventory Management"
    API10 = "API10:2023 - Unsafe Consumption of APIs"
    NONE  = "General"


class HTTPMethod(str, Enum):
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    DELETE  = "DELETE"
    HEAD    = "HEAD"
    OPTIONS = "OPTIONS"


class EndpointStatus(str, Enum):
    DOCUMENTED   = "DOCUMENTED"
    UNDOCUMENTED = "UNDOCUMENTED"
    ZOMBIE       = "ZOMBIE"
    INTERNAL     = "INTERNAL"


# ---------------------------------------------------------------------------
# Core entities (mirror Go structs field-for-field)
# ---------------------------------------------------------------------------

class Parameter(BaseModel):
    name:     str
    location: str        # path | query | body | header
    type:     str = ""
    required: bool = False
    is_pii:   bool = Field(False, alias="is_pii")

    model_config = {"populate_by_name": True}


class Endpoint(BaseModel):
    url:              str = ""
    path:             str
    method:           HTTPMethod = HTTPMethod.GET
    status_code:      int = 0
    content_type:     str = ""
    response_size_bytes: int = Field(0, alias="response_size_bytes")
    ttfb_ms:          int = Field(0, alias="ttfb_ms")
    headers:          dict[str, str] = Field(default_factory=dict)
    auth_required:    bool = False
    auth_type:        str = ""
    has_rate_limit:   bool = False
    rate_limit_header: str = ""
    endpoint_status:  EndpointStatus = Field(
        EndpointStatus.DOCUMENTED, alias="endpoint_status"
    )
    parameters:       list[Parameter] = Field(default_factory=list)
    discovered_at:    Optional[datetime] = None
    risk_score:       int = 0

    model_config = {"populate_by_name": True}

    @property
    def has_pii_params(self) -> bool:
        return any(p.is_pii for p in self.parameters)


class Finding(BaseModel):
    id:           str
    severity:     Severity
    owasp_category: OWASPCategory = Field(OWASPCategory.NONE, alias="owasp_category")
    title:        str
    description:  str
    endpoint:     Optional[Endpoint] = None
    evidence:     str = ""
    remediation:  str = ""
    cvss_score:   float = Field(0.0, alias="cvss_score")
    risk_score:   int = 0
    discovered_at: Optional[datetime] = None
    tags:         list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @property
    def owasp(self) -> OWASPCategory:
        """Convenience alias matching the Go field name."""
        return self.owasp_category


# ---------------------------------------------------------------------------
# HTTP request / response contracts (must match reporter.go AIRequest etc.)
# ---------------------------------------------------------------------------

class AIRequest(BaseModel):
    """Payload posted by the Go reporter to POST /analyze-findings."""
    scan_id:  str
    target:   str
    findings: list[Finding]


class AIFindingResponse(BaseModel):
    """Per-finding enrichment returned to the Go reporter."""
    id:           str
    remediation:  str
    priority:     str   # IMMEDIATE | SHORT_TERM | LONG_TERM
    code_snippet: str = ""

    # Extended fields used by the dashboard (not consumed by Go reporter)
    cvss_adjusted: float = 0.0
    risk_score:    int   = 0
    justification: str   = ""


class AIResponse(BaseModel):
    """Full response from POST /analyze-findings."""
    findings:          list[AIFindingResponse]
    findings_enriched: int
    model_used:        str
    inference_ms:      float


# ---------------------------------------------------------------------------
# DuckDB history types
# ---------------------------------------------------------------------------

class ScanHistoryEntry(BaseModel):
    """Mirrors Go models.ScanHistoryEntry for DuckDB persistence."""
    scan_id:         str
    target:          str
    scanned_at:      datetime
    duration:        str
    sentinel_score:  int = Field(alias="sentinel_rank_score")
    critical_count:  int = Field(alias="critical")
    high_count:      int = Field(alias="high")
    medium_count:    int = Field(alias="medium")
    endpoint_count:  int = Field(alias="total_endpoints")
    shadow_count:    int = Field(alias="shadow_apis")

    model_config = {"populate_by_name": True}


class HistoryResponse(BaseModel):
    entries: list[ScanHistoryEntry]
    total:   int


# ---------------------------------------------------------------------------
# Health / status
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status:       str   # ok | degraded | starting
    model_loaded: bool
    model_name:   str
    uptime_s:     float
    version:      str
