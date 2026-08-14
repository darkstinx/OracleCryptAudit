# oraclecryptaudit/checks/network_encryption.py
from oraclecryptaudit.models import Finding, Severity


def check_session_encryption(connector) -> list[Finding]:
    """
    Comprueba si la sesión actual va cifrada (Native Network Encryption o TLS/SSL),
    consultando V$SESSION_CONNECT_INFO. No requiere acceso al filesystem del servidor,
    solo la propia conexión SQL ya establecida — por eso es el método principal.
    """
    findings = []

    with connector.cursor() as cur:
        cur.execute("""
            SELECT network_service_banner
            FROM v$session_connect_info
            WHERE sid = SYS_CONTEXT('USERENV', 'SID')
        """)
        rows = cur.fetchall()

    banners = [row[0] for row in rows]
    banner_text = " | ".join(banners)

    # Detectamos indicios de cifrado en los banners de red.
    # Ejemplos típicos:
    #   "Encryption service for Linux: Version 21.0.0.0.0 - Production"  -> hay servicio de cifrado cargado
    #   "AES256 Encryption service adapter for Linux"                     -> cifrado activo con algoritmo
    encryption_active = any("encryption service adapter" in b.lower() for b in banners)
    encryption_service_present = any("encryption service for" in b.lower() for b in banners)
    tls_present = any("tls" in b.lower() or "ssl" in b.lower() for b in banners)

    if encryption_active or tls_present:
        findings.append(Finding(
            check_name="Session Network Encryption",
            severity=Severity.INFO,
            passed=True,
            description="La sesión actual está cifrada en tránsito.",
            detail=banner_text
        ))
    elif encryption_service_present:
        findings.append(Finding(
            check_name="Session Network Encryption",
            severity=Severity.MEDIUM,
            passed=False,
            description="El servicio de cifrado está disponible pero no parece "
                         "estar aplicándose activamente a esta sesión.",
            detail=banner_text,
            recommendation="Verificar SQLNET.ENCRYPTION_SERVER=REQUIRED en sqlnet.ora "
                            "del servidor para forzar cifrado en todas las conexiones, "
                            "no solo permitirlo."
        ))
    else:
        findings.append(Finding(
            check_name="Session Network Encryption",
            severity=Severity.HIGH,
            passed=False,
            description="No se detecta cifrado en tránsito para esta sesión. "
                         "El tráfico cliente-servidor podría viajar en claro.",
            detail=banner_text if banner_text else "Sin banners de red disponibles.",
            recommendation="Configurar SQLNET.ENCRYPTION_SERVER=REQUIRED y "
                            "SQLNET.ENCRYPTION_TYPES_SERVER=(AES256) en sqlnet.ora, "
                            "o habilitar TLS/SSL mediante listener con wallet SSL."
        ))

    return findings


def check_sqlnet_file(sqlnet_ora_content: str) -> list[Finding]:
    """
    Check opcional: analiza el contenido de un sqlnet.ora proporcionado manualmente
    (útil si el auditor SÍ tiene acceso al filesystem del servidor).
    """
    findings = []
    content_lower = sqlnet_ora_content.lower()

    has_encryption_server = "sqlnet.encryption_server" in content_lower
    requires_encryption = "encryption_server" in content_lower and "required" in content_lower

    if requires_encryption:
        findings.append(Finding(
            check_name="sqlnet.ora Encryption Policy",
            severity=Severity.INFO,
            passed=True,
            description="sqlnet.ora exige cifrado (ENCRYPTION_SERVER=REQUIRED).",
        ))
    elif has_encryption_server:
        findings.append(Finding(
            check_name="sqlnet.ora Encryption Policy",
            severity=Severity.MEDIUM,
            passed=False,
            description="sqlnet.ora menciona cifrado pero no lo exige como REQUIRED "
                         "(probablemente REQUESTED o ACCEPTED, que permiten fallback sin cifrar).",
            recommendation="Cambiar SQLNET.ENCRYPTION_SERVER a REQUIRED para forzar "
                            "cifrado en todas las conexiones entrantes."
        ))
    else:
        findings.append(Finding(
            check_name="sqlnet.ora Encryption Policy",
            severity=Severity.HIGH,
            passed=False,
            description="No se encontró configuración de cifrado en sqlnet.ora.",
            recommendation="Añadir SQLNET.ENCRYPTION_SERVER=REQUIRED y "
                            "SQLNET.ENCRYPTION_TYPES_SERVER=(AES256)."
        ))

    return findings
