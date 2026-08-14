# oraclecryptaudit/checks/tde_wallet.py
from oraclecryptaudit.models import Finding, Severity


def check_wallet_status(connector) -> list[Finding]:
    """Comprueba si el Oracle Wallet existe y está abierto."""
    findings = []

    with connector.cursor() as cur:
        try:
            cur.execute("""
                SELECT wrl_parameter, status, wallet_type
                FROM v$encryption_wallet
            """)
            row = cur.fetchone()
        except Exception as e:
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.CRITICAL,
                passed=False,
                description="No se pudo consultar v$encryption_wallet",
                detail=str(e),
                recommendation="Verificar privilegios (requiere SYSDBA o rol con acceso a vistas V$)."
            ))
            return findings

        if row is None:
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.CRITICAL,
                passed=False,
                description="No existe configuración de Wallet en esta instancia.",
                recommendation="Configurar un Oracle Wallet para habilitar TDE."
            ))
            return findings

        wrl_parameter, status, wallet_type = row

        if status == "OPEN":
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.INFO,
                passed=True,
                description="El Wallet está abierto y operativo con clave maestra activa.",
                detail=f"Ubicación: {wrl_parameter} | Tipo: {wallet_type}"
            ))
        elif status == "OPEN_NO_MASTER_KEY":
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.HIGH,
                passed=False,
                description="El Wallet está abierto pero no tiene clave maestra de cifrado.",
                detail=f"Ubicación: {wrl_parameter} | Tipo: {wallet_type}",
                recommendation="Generar la clave maestra con ADMINISTER KEY MANAGEMENT SET KEY "
                                "IDENTIFIED BY <password> WITH BACKUP. Sin master key, TDE no puede "
                                "cifrar nada aunque el keystore esté 'abierto'."
            ))
        elif status == "CLOSED":
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.CRITICAL,
                passed=False,
                description="El Wallet existe pero está cerrado.",
                detail=f"Ubicación: {wrl_parameter}",
                recommendation="Abrir el wallet con ALTER SYSTEM SET ENCRYPTION WALLET OPEN, "
                                "o configurar AUTOLOGIN para apertura automática tras reinicio."
            ))
        elif status == "NOT_AVAILABLE":
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.CRITICAL,
                passed=False,
                description="No hay Wallet configurado (NOT_AVAILABLE).",
                recommendation="Crear y configurar un Oracle Wallet antes de habilitar TDE."
            ))
        else:
            findings.append(Finding(
                check_name="TDE Wallet Status",
                severity=Severity.MEDIUM,
                passed=False,
                description=f"Estado de Wallet inesperado: {status}",
                detail=f"Ubicación: {wrl_parameter} | Tipo: {wallet_type}"
            ))

        # Aviso especial si es AUTOLOGIN (menos seguro que password-protected,
        # pero común en producción por disponibilidad — lo marcamos como INFO/MEDIUM)
        if wallet_type == "AUTOLOGIN":
            findings.append(Finding(
                check_name="TDE Wallet Type",
                severity=Severity.MEDIUM,
                passed=False,
                description="El Wallet es de tipo AUTOLOGIN.",
                detail="AUTOLOGIN permite apertura automática sin contraseña, "
                       "lo que facilita disponibilidad pero reduce la protección "
                       "si un atacante compromete el filesystem.",
                recommendation="Evaluar si el trade-off disponibilidad/seguridad es aceptable "
                                "para el nivel de criticidad de los datos. Restringir permisos "
                                "de filesystem sobre el wallet al máximo (chmod 600, usuario oracle only)."
            ))

    return findings


def check_tablespace_encryption(connector) -> list[Finding]:
    """Comprueba qué tablespaces están cifrados y cuáles no."""
    findings = []

    with connector.cursor() as cur:
        cur.execute("""
            SELECT tablespace_name, encrypted
            FROM dba_tablespaces
            ORDER BY tablespace_name
        """)
        rows = cur.fetchall()

    unencrypted = [name for name, enc in rows if enc == 'NO']
    encrypted = [name for name, enc in rows if enc == 'YES']

    if unencrypted:
        findings.append(Finding(
            check_name="Tablespace Encryption",
            severity=Severity.HIGH,
            passed=False,
            description=f"{len(unencrypted)} tablespace(s) sin cifrar detectados.",
            detail=f"Sin cifrar: {', '.join(unencrypted)}",
            recommendation="Considerar migrar tablespaces con datos sensibles a "
                            "tablespaces cifrados (CREATE TABLESPACE ... ENCRYPTION) "
                            "o cifrar in-place si la versión lo soporta."
        ))
    else:
        findings.append(Finding(
            check_name="Tablespace Encryption",
            severity=Severity.INFO,
            passed=True,
            description="Todos los tablespaces están cifrados.",
            detail=f"Cifrados: {', '.join(encrypted)}"
        ))

    return findings
