# OracleCryptAudit — Notas técnicas del desarrollo

Documento de aprendizaje: todo lo que se hizo, por qué, y qué se aprendió en cada paso. Pensado para repasar antes de la entrevista.

---

## 1. Entorno: Oracle XE en Docker

**Qué hicimos**: instalamos Docker en Kali (el script oficial falló porque Kali usa `kali-rolling`, una distro que Docker no reconoce — hubo que forzar el repo a `bookworm`, la versión estable de Debian en la que se basa Kali).

**Por qué importa**: es un problema típico al usar herramientas "enterprise" sobre distros de pentesting no estándar.

**Comandos clave**:
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
# Si falla el repo de kali-rolling:
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io
```

Levantamos Oracle XE 21c con:
```bash
docker run -d --name oracle-xe -p 1521:1521 -p 5500:5500 \
  -e ORACLE_PWD=<password> \
  container-registry.oracle.com/database/express:21.3.0-xe
```

---

## 2. Conexión desde Python: modo "thin" vs "thick"

Esto es el concepto más importante de toda la sesión, y el que más vale la pena dominar.

El driver `python-oracledb` tiene dos modos:

- **Thin**: 100% Python, no necesita nada instalado en el sistema. Rápido de montar. **Pero no soporta todas las features**, entre ellas Oracle Native Network Encryption (cifrado nativo de Oracle Net).
- **Thick**: usa las librerías nativas de Oracle (Instant Client) por debajo. Soporta todo, pero añade una dependencia externa a instalar y mantener.

Para nuestro caso: todos los checks basados en consultas SQL normales (Wallet, tablespaces, columnas cifradas) funcionan perfectamente en modo thin. Solo el check de cifrado en tránsito (que depende de negociación de red a bajo nivel) necesita modo thick.

---

## 3. TDE Wallet: CDB vs PDB (el concepto más "senior" de la sesión)

Oracle desde la versión 12c usa arquitectura **multitenant**: un CDB (Container Database) raíz que aloja uno o varios PDBs (Pluggable Databases). Oracle XE viene con un PDB por defecto llamado `XEPDB1`.

**El hallazgo clave**: el estado del TDE Wallet (`v$encryption_wallet`) se gestiona **de forma independiente en el CDB root y en cada PDB**, aunque compartan la ubicación física del wallet en disco. Abrir el wallet en el CDB root NO lo abre automáticamente en el PDB.

Secuencia completa que hay que ejecutar (aplica igual la primera vez que configuras TDE en una instancia nueva):

```sql
-- 1. Conectado en CDB$ROOT
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE '/opt/oracle/admin/XE/wallet' IDENTIFIED BY "password";
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "password";
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "password" WITH BACKUP;

-- 2. Cambiar al PDB
ALTER SESSION SET CONTAINER = XEPDB1;

-- 3. Repetir apertura y clave maestra, esta vez en el contexto del PDB
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "password";
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "password" WITH BACKUP;
```

**Estado intermedio importante**: tras abrir el keystore pero antes de generar la clave maestra, el estado es `OPEN_NO_MASTER_KEY` — el wallet está "abierto" pero TDE sigue sin poder cifrar nada. Muchas herramientas superficiales tratarían esto como "wallet OK" por estar `OPEN`, cuando en realidad sigue siendo un estado inseguro. `OracleCryptAudit` lo distingue explícitamente como `HIGH` en vez de pasarlo como correcto.


---

## 4. Cifrado de columnas: TDE Column Encryption

Sintaxis para cifrar una columna al crear la tabla:
```sql
CREATE TABLE cards (
    card_num VARCHAR2(20) ENCRYPT,
    cvv      VARCHAR2(4) ENCRYPT
);
```

Se audita consultando `DBA_ENCRYPTED_COLUMNS`, que muestra qué columnas están cifradas y con qué algoritmo (en nuestras pruebas, AES de 192 bits por defecto).

---

## 5. El intento de cifrado en tránsito (Native Network Encryption) — troubleshooting completo

Esta fue la parte más larga y con más curva de aprendizaje real. Documento el proceso completo (aunque no llegara a buen puerto del todo).

### 5.1 Primer síntoma
Al intentar auditar la sesión con `V$SESSION_CONNECT_INFO` en modo thin, el driver lanzó:
```
DPY-3001: Native Network Encryption and Data Integrity is only supported in python-oracledb thick mode
```
→ Confirmó que necesitábamos modo thick.

### 5.2 Instalación de Oracle Instant Client
Se descargó el Instant Client Basiclite y se inicializó desde Python con:
```python
oracledb.init_oracle_client(lib_dir="/ruta/instantclient_23_26")
```

### 5.3 Error de librería no encontrada (`DPI-1047`)
```
Cannot locate a 64-bit Oracle Client library: "libnnz.so: cannot open shared object file"
```
**Causa real**: no faltaba el fichero (existía en disco), sino que el *loader* de Linux no sabía buscar en esa carpeta. Se soluciona añadiendo la ruta a `LD_LIBRARY_PATH`:
```bash
export LD_LIBRARY_PATH=/ruta/instantclient_23_26:$LD_LIBRARY_PATH
```
**Lección**: un error de "librería no encontrada" no siempre significa que falte el archivo — primero comprobar con `ldd` qué dependencias resuelve y cuáles no:
```bash
ldd /ruta/instantclient_23_26/libclntsh.so | grep "not found"
```

### 5.4 Configuración forzada de cifrado en el servidor
En `sqlnet.ora` del servidor (dentro del contenedor, en `/opt/oracle/oradata/dbconfig/XE/sqlnet.ora` — nótese que `network/admin/sqlnet.ora` es un **symlink** a esta ruta real):
```
SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA256)
```

### 5.5 Cuelgue de conexión (sin respuesta)
Al forzar cifrado, las conexiones se quedaban colgadas indefinidamente. Hipótesis inicial: agotamiento de entropía del sistema (`/proc/sys/kernel/random/entropy_avail` mostraba 256, un valor bajo típico en contenedores). Se probó forzar `/dev/urandom` en vez de `/dev/random`:
```
SQLNET.RANDOM_DEVICE = /dev/./urandom
```
Esto se aplicó tanto en el servidor como en un `sqlnet.ora` de **cliente** nuevo (en `instantclient_23_26/network/admin/sqlnet.ora`), indicando además a `oracledb.init_oracle_client()` dónde buscarlo vía `config_dir`.

**Nota**: en kernels Linux modernos, `entropy_avail` cambió de significado (siempre puede mostrar valores "bajos" sin que sea un problema real), así que esta hipótesis quedó parcialmente descartada más adelante.

### 5.6 Nuevo error, más específico: `ORA-12637: Packet receive failed`
Tras el cambio de `RANDOM_DEVICE`, la conexión dejó de colgarse pero falló rápido con este error. Se probaron dos variables de control para aislar la causa:
- Cambiar `ENCRYPTION_SERVER` de `REQUIRED` a `REQUESTED` (cifrado opcional en vez de obligatorio) → mismo error. **Conclusión: no era un problema de negociación de cifrado en sí.**
- Cambiar `localhost` por `127.0.0.1` en el DSN (para descartar un problema de resolución IPv6) → mismo error. **Conclusión: tampoco era resolución de nombres.**

### 5.7 Diagnóstico final (parcial)
Se confirmó que:
- El listener estaba sano (`lsnrctl status` mostraba todos los servicios `READY`).
- La conexión desde **dentro** del propio contenedor (`sqlplus` local) funcionaba sin ningún problema.
- El puerto 1521 respondía correctamente a nivel TCP desde el host (`nc -zv localhost 1521` → open).
- El fallo ocurría específicamente en la fase de conexión Oracle Net del **cliente en modo thick desde el host**, contra el servidor en contenedor Docker.

**Conclusión de trabajo**: el problema es una incompatibilidad entre el modo thick de `python-oracledb` (vía Instant Client) y la capa de red virtualizada de Docker en este entorno concreto — no un error de configuración de cifrado. Es un problema conocido en general (hay reportes similares de otros usuarios combinando Instant Client + Docker Desktop/Engine + NAT), pero no se resolvió durante la sesión.

### 5.8 Decisión final
En vez de seguir invirtiendo tiempo indefinidamente, se tomó la decisión de:
1. Revertir toda la configuración de red a su estado por defecto (recreando el contenedor desde cero, ya que quedó en un estado degradado tras múltiples reinicios con configuraciones conflictivas — hasta las conexiones normales en modo thin dejaron de funcionar temporalmente, con error `DPY-4011: the database or network closed the connection`, probablemente por agotamiento de sesiones/procesos tras los intentos colgados).
2. Dejar el check de red funcionando en modo thin (con la limitación conocida de no poder confirmar Native Network Encryption con certeza total).
3. Documentar la limitación de forma honesta en el README, en vez de ocultarla o fingir que está resuelta.

---

## 6. Recrear el contenedor desde cero

Cuando el contenedor quedó en estado degradado:
```bash
docker stop oracle-xe
docker rm oracle-xe
docker run -d --name oracle-xe -p 1521:1521 -p 5500:5500 \
  -e ORACLE_PWD=<password> \
  container-registry.oracle.com/database/express:21.3.0-xe
```
La imagen ya estaba descargada localmente, así que la recreación fue rápida. Todo el proceso de configuración de Wallet + esquema de prueba se repitió desde cero siguiendo los mismos pasos del punto 3, esta vez sin tocar `sqlnet.ora`.

---

## 7. Comandos de terminal aprendidos por el camino

- `mkdir -p`: crea toda la ruta de carpetas intermedias que falten, y no da error si ya existe.
- `LD_LIBRARY_PATH`: variable de entorno (no un archivo) que le dice al sistema dónde buscar librerías compartidas (`.so`) además de las rutas estándar. Se pierde al cerrar la terminal salvo que se añada a un fichero de perfil (`.bashrc`, o el script `activate` de un venv).
- `ldd <binario>`: muestra las dependencias de librerías compartidas de un binario y cuáles no se han podido resolver.
- Symlinks (`lrwxrwxrwx`): un archivo que en realidad es un puntero a otro. Escribir sobre un symlink con redirección (`>`) puede comportarse de forma inesperada según el shell — mejor verificar con `ls -la` antes de sobrescribir configuración crítica.

