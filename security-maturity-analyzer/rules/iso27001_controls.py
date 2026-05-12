"""
ISO/IEC 27001 Controls and Maturity Level Definitions
Based on COBIT Maturity Model as referenced in the SMESEC framework.

Levels:
  0 - Inexistente        (0%)
  1 - Inicial / ad hoc   (1–20%)
  2 - Repetible          (21–40%)
  3 - Proceso definido   (41–60%)
  4 - Administrado       (61–80%)
  5 - Optimizado         (81–100%)
"""

from dataclasses import dataclass, field
from typing import List, Dict

# ─────────────────────────────────────────────
# Maturity Level Definitions
# ─────────────────────────────────────────────

MATURITY_LEVELS = {
    0: {
        "name": "Inexistente",
        "range": (0, 0),
        "color": "\033[91m",      # Red
        "description": (
            "No se reconoce la necesidad del control interno. "
            "El control no es parte de la cultura o misión organizacional. "
            "Existe un alto riesgo de deficiencias e incidentes de control."
        ),
        "recommendations": [
            "Establecer una política de seguridad de la información formal.",
            "Designar un responsable de seguridad (CISO o equivalente).",
            "Comenzar a registrar eventos básicos del sistema.",
            "Realizar una evaluación inicial de riesgos.",
        ],
    },
    1: {
        "name": "Inicial / Ad Hoc",
        "range": (1, 20),
        "color": "\033[91m",      # Red
        "description": (
            "Se reconoce algo de la necesidad del control interno. "
            "El enfoque hacia los requerimientos de riesgo y control es ad hoc y desorganizado, "
            "sin comunicación o supervisión. Los empleados no están concientes de sus responsabilidades."
        ),
        "recommendations": [
            "Documentar los procedimientos de seguridad existentes.",
            "Implementar monitoreo básico de accesos.",
            "Establecer procedimientos de respuesta a incidentes.",
            "Capacitar al personal en conceptos básicos de seguridad.",
        ],
    },
    2: {
        "name": "Repetible pero Intuitivo",
        "range": (21, 40),
        "color": "\033[93m",      # Yellow
        "description": (
            "Existen controles pero no están documentados. Su operación depende del conocimiento "
            "y motivación de los individuos. La efectividad no se evalúa de forma adecuada. "
            "Existen muchas debilidades de control y no se resuelven de forma apropiada."
        ),
        "recommendations": [
            "Formalizar y documentar todos los controles existentes.",
            "Implementar revisiones periódicas de logs y eventos.",
            "Desarrollar un plan de gestión de vulnerabilidades.",
            "Establecer métricas de seguridad básicas.",
        ],
    },
    3: {
        "name": "Proceso Definido",
        "range": (41, 60),
        "color": "\033[93m",      # Yellow
        "description": (
            "Existen controles y están documentados de forma adecuada. Se evalúa la efectividad "
            "operativa de forma periódica. Aunque la gerencia puede manejar la mayoría de los "
            "problemas de control de forma predecible, algunas debilidades persisten."
        ),
        "recommendations": [
            "Automatizar la recolección y análisis de logs.",
            "Implementar un SIEM (Security Information and Event Management).",
            "Realizar auditorías de seguridad periódicas.",
            "Desarrollar y probar planes de continuidad del negocio.",
        ],
    },
    4: {
        "name": "Administrado y Medible",
        "range": (61, 80),
        "color": "\033[92m",      # Green
        "description": (
            "Existe un ambiente efectivo de control interno y de administración de riesgos. "
            "La evaluación formal y documentada de los controles ocurre de forma periódica. "
            "Muchos controles están automatizados y se realizan de forma periódica."
        ),
        "recommendations": [
            "Implementar análisis predictivo de amenazas.",
            "Integrar threat intelligence feeds.",
            "Realizar pruebas de penetración regulares.",
            "Optimizar procesos de respuesta a incidentes.",
        ],
    },
    5: {
        "name": "Optimizado",
        "range": (81, 100),
        "color": "\033[92m",      # Green
        "description": (
            "La organización utiliza un proceso integrado y continuo de mejora de la seguridad. "
            "Los controles de seguridad son proactivos y predictivos. La gestión de riesgos está "
            "plenamente integrada en los procesos organizacionales."
        ),
        "recommendations": [
            "Mantener el programa de mejora continua.",
            "Compartir inteligencia de amenazas con el sector.",
            "Buscar certificación ISO 27001 si aún no se tiene.",
            "Implementar Zero Trust Architecture.",
        ],
    },
}


def get_maturity_level(score: float) -> int:
    """Return maturity level (0-5) for a given score (0-100)."""
    if score <= 0:  return 0
    if score <= 20: return 1
    if score <= 40: return 2
    if score <= 60: return 3
    if score <= 80: return 4
    return 5


# ─────────────────────────────────────────────
# ISO 27001 Control Domains
# ─────────────────────────────────────────────

@dataclass
class ControlDomain:
    id: str
    name: str
    clause: str
    weight: float                   # relative importance (weights sum to 1)
    indicators: List[str]           # log patterns that indicate this domain is active
    risk_patterns: List[str]        # patterns that indicate a problem
    description: str = ""


ISO27001_DOMAINS: Dict[str, ControlDomain] = {
    "access_control": ControlDomain(
        id="A.9",
        name="Control de Accesos",
        clause="A.9 – Access Control",
        weight=0.25,
        indicators=[
            r"(?i)(login|logon|logged.on|log.on|authentication|session.start|"
            r"accepted password|accepted publickey|session opened|"
            r"account.*logged|successfully logged|privileges assigned)",
        ],
        risk_patterns=[
            r"(?i)(failed password|authentication failure|invalid user|"
            r"access denied|login failed|logon failure|bad password|"
            r"too many authentication|brute.?force|"
            r"account failed|failed to log on|account.*locked)",
        ],
        description="Gestión de accesos de usuarios, contraseñas y privilegios.",
    ),
    "operations_security": ControlDomain(
        id="A.12",
        name="Seguridad en Operaciones",
        clause="A.12 – Operations Security",
        weight=0.20,
        indicators=[
            r"(?i)(service.start|service.stop|process.start|cron|systemd|"
            r"backup|restore|update|upgrade|patch|kill process|started daily)",
        ],
        risk_patterns=[
            r"(?i)(kernel.*panic|out.of.memory|oom.killer|disk.full|"
            r"disk.*failure|disk.*error|hardware.error|"
            r"segfault|core.dump|malware|virus|trojan|ransomware|"
            r"failed to start|backup.failed|backup.*error)",
        ],
        description="Protección contra malware, gestión de vulnerabilidades y backup.",
    ),
    "communications_security": ControlDomain(
        id="A.13",
        name="Seguridad en Comunicaciones",
        clause="A.13 – Communications Security",
        weight=0.20,
        indicators=[
            r"(?i)(ssl|tls|https|vpn|firewall|connection.established|"
            r"port.*open|network.*connect)",
        ],
        risk_patterns=[
            r"(?i)(ssl.?error|tls.?error|certificate.?error|"
            r"port.?scan|syn.?flood|ddos|dos.attack|"
            r"connection.refused|connection.reset|"
            r"suspicious.*traffic|anomalous.*traffic|"
            r"iptables.*drop|firewall.*block|denied.*connection)",
        ],
        description="Seguridad en redes, transferencia de información y servicios de red.",
    ),
    "incident_management": ControlDomain(
        id="A.16",
        name="Gestión de Incidentes",
        clause="A.16 – Information Security Incident Management",
        weight=0.15,
        indicators=[
            r"(?i)(incident|alert.*trigger|alarm|notification|"
            r"escalat|ticket|report.*security)",
        ],
        risk_patterns=[
            r"(?i)(critical.?error|fatal|panic|emergency|"
            r"system.*failure|service.*down|unhandled.*exception|"
            r"data.?breach|intrusion.?detect|unauthorized.?access)",
        ],
        description="Detección, reporte y gestión de incidentes de seguridad.",
    ),
    "cryptography": ControlDomain(
        id="A.10",
        name="Criptografía",
        clause="A.10 – Cryptography",
        weight=0.10,
        indicators=[
            r"(?i)(encrypt|decrypt|ssl|tls|https|aes|rsa|sha|"
            r"certificate|key.*exchange|cipher)",
        ],
        risk_patterns=[
            r"(?i)(weak.?cipher|deprecated.?ssl|sslv2|sslv3|"
            r"rc4|md5.?signature|certificate.?expired|"
            r"certificate.?invalid|self.?signed|"
            r"plain.?text.*password|unencrypted.*credential)",
        ],
        description="Uso de criptografía para proteger la confidencialidad e integridad.",
    ),
    "physical_security": ControlDomain(
        id="A.11",
        name="Seguridad Física",
        clause="A.11 – Physical & Environmental Security",
        weight=0.10,
        indicators=[
            r"(?i)(usb|removable.?media|physical.?access|"
            r"badge|card.?reader|cctv|temperature|ups|power)",
        ],
        risk_patterns=[
            r"(?i)(usb.*unauthorized|removable.*blocked|"
            r"physical.*breach|temperature.*critical|"
            r"power.*failure|ups.*low|hardware.*failure)",
        ],
        description="Seguridad de áreas físicas y equipos.",
    ),
}

# ─────────────────────────────────────────────
# Scoring thresholds
# ─────────────────────────────────────────────

# Minimum event counts to consider a domain "active"
MIN_EVENTS_FOR_LOGGING = 10

# Thresholds that influence scoring
THRESHOLDS = {
    "critical_failure_rate": 0.30,   # >30% failures → heavy penalty
    "high_failure_rate": 0.15,       # >15% failures → moderate penalty
    "medium_failure_rate": 0.05,     # >5% failures → light penalty
    "good_log_volume": 100,          # ≥100 events per domain → bonus
    "excellent_log_volume": 500,     # ≥500 events → extra bonus
}
