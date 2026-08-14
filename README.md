# OracleCryptAudit

Herramienta en Python para auditar la postura de cifrado y protección de datos sensibles en bases de datos Oracle, pensada para entornos donde el cifrado (TDE, cifrado en tránsito, protección de PII) es un requisito de cumplimiento crítico — como banca o fintech.

## Motivación

La mayoría de herramientas de seguridad para bases de datos están hechas por gente sin experiencia real como DBA, y suelen quedarse en comprobaciones superficiales (usuarios con privilegios, contraseñas por defecto). Este proyecto nace de la intersección entre experiencia real como DBA Oracle en banca y un roadmap activo hacia ciberseguridad: audita específicamente lo que un DBA de Oracle sabe que importa de verdad en materia de cifrado, con el nivel de detalle que solo da haber administrado estas bases de datos en producción.

## Qué audita

### 1. Estado del Transparent Data Encryption (TDE) Wallet
- Si existe un keystore/wallet configurado.
- Si está abierto (`OPEN`), cerrado (`CLOSED`), o abierto sin clave maestra (`OPEN_NO_MASTER_KEY` — un estado intermedio que muchas herramientas no distinguen y que deja la base de datos igual de expuesta que si no hubiera wallet).
- Tipo de wallet (`PASSWORD` vs `AUTOLOGIN`), señalando el trade-off de seguridad/disponibilidad de cada uno.

### 2. Cifrado de tablespaces
Qué tablespaces están cifrados y cuáles no, vía `DBA_TABLESPACES`.

### 3. Cifrado de columnas (TDE Column Encryption)
Qué columnas ya están protegidas con `DBMS_CRYPTO`/`ENCRYPT`, vía `DBA_ENCRYPTED_COLUMNS`.

### 4. Detección heurística de columnas sensibles sin cifrar
Escaneo de metadatos de columnas (`DBA_TAB_COLUMNS`) contra patrones de nombre típicos de PII y datos bancarios (DNI/NIF, IBAN, número de tarjeta, credenciales, email, teléfono), cruzado con las columnas que sí están cifradas, para señalar huecos de protección.

**Importante**: esto es una heurística basada en nombres de columna, no un análisis del contenido real de los datos. Puede generar falsos positivos (ej. `email_template`) y falsos negativos (una columna `col_47` que en realidad contiene un DNI). Se documenta así de forma explícita para no sobrevender la herramienta — cualquier hallazgo debe validarse manualmente.

### 5. Cifrado en tránsito (sesión actual)
Comprueba si la sesión SQL activa está cifrada en la red (Oracle Native Network Encryption o TLS/SSL), consultando `V$SESSION_CONNECT_INFO`. Se eligió este método (en vez de leer `sqlnet.ora` del servidor) porque no requiere acceso al sistema operativo del servidor — un auditor externo o un DBA con solo acceso SQL puede ejecutarlo igualmente, lo cual refleja mejor un escenario de auditoría real.

## Arquitectura

```
OracleCryptAudit/
├── oraclecryptaudit/
│   ├── connector.py         # Gestión de conexión Oracle (oracledb, modo thin)
│   ├── models.py             # Estructuras de datos: Finding, Severity, AuditReport
│   └── checks/
│       ├── tde_wallet.py             # Checks 1 y 2
│       ├── encrypted_columns.py      # Checks 3 y 4
│       └── network_encryption.py     # Check 5
├── test_check.py             # Script de ejecución / demo
└── requirements.txt
```

Cada check devuelve una lista de objetos `Finding` (severidad, descripción, detalle técnico, recomendación), lo que permite que un futuro `report.py` genere informes en Markdown/HTML sin lógica especial por check.

## Requisitos

- Python 3.10+
- `oracledb` (`pip install oracledb`)
- Acceso a una instancia Oracle (probado contra Oracle XE 21c)

## Uso

```bash
python3 test_check.py
```

Cada hallazgo se muestra con severidad (`CRITICAL`/`HIGH`/`MEDIUM`/`INFO`), si pasó o no el check, descripción, detalle técnico y recomendación cuando aplica.

## Limitaciones conocidas

- **Cifrado en tránsito solo auditable en modo "thin" de forma parcial**: el driver `python-oracledb` en modo thin (sin Oracle Instant Client) no soporta Oracle Native Network Encryption, por lo que si el driver detecta que la sesión debería estar cifrada por esa vía pero no puede verificarlo, lo reporta como no cifrado. Auditar esto con precisión total requiere modo "thick" (con Instant Client instalado). En pruebas contra Oracle XE en Docker, el modo thick presentó fallos de conexión (`ORA-12637`) no resueltos durante el desarrollo — posiblemente relacionado con la gestión de red de Docker Desktop/Docker Engine en combinación con Oracle Net, no con la configuración de cifrado en sí. Documentado como mejora futura.
- **Heurística de columnas sensibles basada en nombres**, no en contenido real de los datos (ver punto 4 arriba).
- Requiere privilegios suficientes sobre vistas `DBA_*` y `V$*` (típicamente rol `DBA` o privilegios equivalentes concedidos explícitamente).

## Roadmap

- [ ] `report.py`: generación de informe HTML/Markdown estilo compliance report (PCI-DSS/ISO 27001)
- [ ] CLI con `argparse` (parámetros de conexión, formato de salida, umbral de severidad)
- [ ] Check de privilegios excesivos (roles peligrosos, `PUBLIC`, usuarios con contraseñas por defecto)
- [ ] Resolver auditoría de cifrado en tránsito en modo thick sobre Docker
- [ ] Soporte para análisis de `sqlnet.ora` cuando sí hay acceso al filesystem del servidor
