# oraclecryptaudit/connector.py
import oracledb
from contextlib import contextmanager

#oracledb.init_oracle_client(
#    lib_dir="/home/kali/Oracle/instantclient_23_26",
#    config_dir="/home/kali/Oracle/instantclient_23_26/network/admin"
#)

class OracleConnector:
    def __init__(self, user: str, password: str, dsn: str):
        self.user = user
        self.password = password
        self.dsn = dsn
        self._connection = None

    def connect(self):
        self._connection = oracledb.connect(
            user=self.user,
            password=self.password,
            dsn=self.dsn
        )
        return self._connection

    def close(self):
        if self._connection:
            self._connection.close()
            self._connection = None

    @contextmanager
    def cursor(self):
        if not self._connection:
            self.connect()
        cur = self._connection.cursor()
        try:
            yield cur
        finally:
            cur.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
