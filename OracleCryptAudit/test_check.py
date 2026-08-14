# test_check.py
from oraclecryptaudit.connector import OracleConnector
from oraclecryptaudit.checks.tde_wallet import check_wallet_status, check_tablespace_encryption
from oraclecryptaudit.checks.encrypted_columns import check_encrypted_columns, check_sensitive_columns_unencrypted
from oraclecryptaudit.checks.network_encryption import check_session_encryption

conn = OracleConnector(user="system", password="TuPasswordSegura123", dsn="127.0.0.1:1521/XEPDB1")

with conn:
    findings = (
        check_wallet_status(conn)
        + check_tablespace_encryption(conn)
        + check_encrypted_columns(conn)
        + check_sensitive_columns_unencrypted(conn)
        + check_session_encryption(conn)
    )
    for f in findings:
        status = "✅ PASS" if f.passed else "❌ FAIL"
        print(f"[{f.severity.value}] {status} - {f.check_name}: {f.description}")
        if f.detail:
            print(f"   Detalle: {f.detail}")
        if f.recommendation:
            print(f"   Recomendación: {f.recommendation}")
        print()
