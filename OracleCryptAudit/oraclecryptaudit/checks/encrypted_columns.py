# oraclecryptaudit/checks/encrypted_columns.py
import re
from oraclecryptaudit.models import Finding, Severity


# Patrones heurísticos de nombres de columna sensibles
SENSITIVE_PATTERNS = {
    "PII / Identificación": re.compile(r"(dni|nif|nie|passport|ssn|social_security)", re.I),
    "Datos bancarios": re.compile(r"(iban|account_num|card_num|cvv|credit_card|bank_account)", re.I),
    "Credenciales": re.compile(r"(password|passwd|pwd|secret|api_key|token)", re.I),
    "Contacto": re.compile(r"(email|phone|mobile|address)", re.I),
}


def check_encrypted_columns(connector) -> list[Finding]:
    """Lista columnas ya cifradas vía TDE column encryption."""
    findings = []

    with connector.cursor() as cur:
        cur.execute("""
            SELECT owner, table_name, column_name, encryption_alg
            FROM dba_encrypted_columns
            WHERE owner NOT IN ('SYS', 'SYSTEM')
            ORDER BY owner, table_name, column_name
        """)
        rows = cur.fetchall()

    if rows:
        detail = "; ".join(f"{o}.{t}.{c} ({alg})" for o, t, c, alg in rows)
        findings.append(Finding(
            check_name="Encrypted Columns (TDE)",
            severity=Severity.INFO,
            passed=True,
            description=f"{len(rows)} columna(s) con cifrado TDE a nivel de columna.",
            detail=detail
        ))
    else:
        findings.append(Finding(
            check_name="Encrypted Columns (TDE)",
            severity=Severity.MEDIUM,
            passed=False,
            description="No se ha encontrado ninguna columna con TDE column encryption.",
            recommendation="Si existen columnas con datos sensibles, evaluar cifrado a "
                            "nivel de columna con ALTER TABLE ... MODIFY (columna ENCRYPT)."
        ))

    return findings


def check_sensitive_columns_unencrypted(connector) -> list[Finding]:
    """Heurística: busca columnas con nombres sensibles y comprueba si están cifradas."""
    findings = []

    with connector.cursor() as cur:
        # Columnas de esquemas de usuario (excluye catálogos del sistema)
        cur.execute("""
            SELECT owner, table_name, column_name
            FROM dba_tab_columns
            WHERE owner NOT IN (
                SELECT username FROM dba_users WHERE oracle_maintained = 'Y'
            )
            ORDER BY owner, table_name, column_name
        """)
        all_columns = cur.fetchall()

        cur.execute("""
            SELECT owner, table_name, column_name
            FROM dba_encrypted_columns
        """)
        encrypted_set = {(o, t, c) for o, t, c, *_ in cur.fetchall()}

    for category, pattern in SENSITIVE_PATTERNS.items():
        matches = [
            (owner, table, col) for owner, table, col in all_columns
            if pattern.search(col) and (owner, table, col) not in encrypted_set
        ]
        if matches:
            detail = "; ".join(f"{o}.{t}.{c}" for o, t, c in matches)
            findings.append(Finding(
                check_name=f"Sensitive Columns Unencrypted ({category})",
                severity=Severity.HIGH,
                passed=False,
                description=f"{len(matches)} columna(s) potencialmente sensibles "
                             f"({category}) sin cifrar detectadas por heurística de nombre.",
                detail=detail,
                recommendation="Revisar manualmente si estas columnas contienen datos "
                                "sensibles reales y aplicar cifrado TDE a nivel de columna "
                                "o tokenización/enmascaramiento si aplica."
            ))

    if not findings:
        findings.append(Finding(
            check_name="Sensitive Columns Unencrypted",
            severity=Severity.INFO,
            passed=True,
            description="No se detectaron columnas con nombres sensibles sin cifrar "
                         "(heurística de nombre)."
        ))

    return findings
