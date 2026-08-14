# oraclecryptaudit/models.py
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    check_name: str          # e.g. "TDE Wallet Status"
    severity: Severity
    passed: bool              # True = todo correcto, False = hallazgo de riesgo
    description: str          # qué se comprobó
    detail: str = ""          # detalle técnico (valores encontrados)
    recommendation: str = ""  # qué hacer para arreglarlo


@dataclass
class AuditReport:
    target: str
    findings: list[Finding] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)

    def add(self, finding: Finding):
        self.findings.append(finding)

    @property
    def summary(self) -> dict:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            if not f.passed:
                counts[f.severity] += 1
        return counts
