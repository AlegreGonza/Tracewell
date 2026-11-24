# Documentación de `backend/domain/rules`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## builder.py

Constructor de reglas: arma una regla por umbral a partir de los campos de un formulario.

Lógica pura (sin FastAPI): valida el formulario, genera el YAML con el MISMO formato que las reglas
de `rules/`, calcula la vista previa sobre una captura y guarda el archivo. La regla usa el detector
`threshold` (extra_detectors.py): el analista elige filtros y umbral, no escribe código.

Nunca modifica ni desactiva reglas existentes: guardar con un id o un archivo que ya existe falla.


### Funciones y clases


**`preview`**: Qué pasaría con la captura actual: sesiones que cumplen el filtro y alertas que daría el umbral. No guarda nada y no toca las alertas del análisis actual.


### Notas del código

- `<módulo>`: Nombres de dispositivo de Windows: un archivo con ese nombre (con.yaml, nul.yaml...) es problemático.


## engine.py

Motor de reglas: carga reglas YAML y las evalúa sobre el tráfico.

Idea central: la REGLA (YAML) es dato (nombre, severidad, técnica MITRE,
umbrales) y el DETECTOR (Python) es la lógica que sabe buscar un patrón.
Así un analista ajusta umbrales o cambia la severidad sin tocar código, pero
no ejecutamos código arbitrario que venga de un archivo.

Una sola pasada: cada paquete se decodifica una vez y se ofrece a todos los
detectores. Memoria acotada por detector, no por el tamaño del pcap.


### Funciones y clases


**`_suffix_list`**: Lista (puede ser vacía) de sufijos de dominio; se normalizan a minúsculas y sin puntos en los bordes.


**`_decode`**: Ethernet -> IP -> TCP/UDP, o None si no aplica o está dañado. Un paquete ilegible NO debe tumbar el análisis: en una herramienta de seguridad el tráfico malicioso a veces está malformado a propósito.


**`PortScanDetector`**: Una IP origen envía SYN a muchos puertos distintos de un mismo destino en poco tiempo. Contamos SYN "puros" (sin ACK): son los intentos de abrir conexión; una conversación normal repite pocos puertos.


**`FtpCleartextDetector`**: Comandos USER/PASS de FTP viajando sin cifrar. Por seguridad la alerta NO guarda la contraseña: la evidencia dice que existió y de qué largo era. Los reportes se comparten; una contraseña en texto claro dentro de un JSON sería una filtración nueva.


**`DnsSuspiciousDetector`**: Consultas DNS con nombres que parecen datos y no nombres humanos. Malware que usa DNS para C2 o para sacar datos (túneles, DGA) mete información codificada en el primer label: es largo y de alta entropía.


**`_text_list`**: Lista de textos no vacíos de un campo opcional (ausente = vacía); falla si el tipo no es una lista de texto.


**`RuleRunner`**: Pasa paquetes ya decodificados (`decode_layer`) por los detectores; `analyze` lo usa para compartir la pasada y la decodificación con las sesiones.

**`evaluate`**: Pasa cada paquete por todos los detectores y devuelve las alertas ordenadas por tiempo (usa `RuleRunner`).


### Notas del código

- `Rule`: Campos explicativos OPCIONALES del YAML: ayudan al analista a decidir. Solo se muestran en la interfaz; NO viajan en el JSON exportado (el contrato schema_version 1 no cambia).
- `Alert`: Evidencia: por qué saltó la alerta, con datos concretos. Sin esto el analista tiene que creerle a la herramienta; con esto puede verificar.
- `<módulo>`: Tope de entradas por estructura de estado de un detector. Sin tope, un atacante (o un DDoS) que genere millones de pares origen/destino distintos haría crecer la memoria sin límite. Costo asumido: con más pares que el tope se "olvida" a los menos recientes (un escaneo muy lento repartido entre más de MAX_TRACKED pares podría pasar inadvertido). Preferimos eso a quedarnos sin RAM.
- `PortScanDetector.__init__`: (origen, destino) -> {puerto: último instante visto}. Un dict por puerto (y no una lista de SYN) acota la memoria: repetir el mismo puerto un millón de veces ocupa una sola entrada.
- `PortScanDetector.feed`: Llegamos al umbral: descartamos los puertos fuera de la ventana y recién entonces decidimos (con puertos viejos no hay escaneo "rápido").
- `<módulo>`: Detectores adicionales (beaconing, inundación SYN, puertos sospechosos, DNS no habitual, subidas grandes). Van en otro archivo para que este no crezca sin fin; se importan AL FINAL porque usan las clases de este módulo. Importarlos antes causaría una importación circular.
- `<módulo>`: getattr: si alguien importó extra_detectors ANTES que este módulo, `_extra` está a medio cargar y todavía no tiene DETECTORS; en ese caso se registra él mismo al terminar de cargarse.


## extra_detectors.py

Detectores adicionales: beaconing, inundación SYN, puertos sospechosos, DNS a un
resolvedor no habitual subidas grandes de datos, fuerza bruta y la regla personalizada por umbral.

Mismas reglas que el resto: la REGLA es un YAML (umbral, severidad, MITRE) y el
DETECTOR es código chico. Cada detector guarda estado acotado (`_LRU`): un atacante
no puede hacer crecer la memoria con millones de pares distintos.

Registro: `engine.py` importa este módulo al final y suma `DETECTORS`; si alguien lo
importa primero, se registra solo al terminar de cargarse (ver el final del archivo).


### Funciones y clases


**`BeaconingDetector`**: Conexiones (o datagramas) hacia un mismo destino a intervalos MUY regulares. Un malware que "llama a casa" suele hacerlo cada N segundos con poca variación. Se cuentan los intentos de conexión TCP (SYN) y los datagramas UDP; un humano o una app normal navegan de forma irregular. Se ignoran intervalos cortos (`min_interval_seconds`): un keep-alive de 1 segundo no es un beacon.


**`DnsUnusualResolverDetector`**: Consultas DNS enviadas directo a un servidor público que no está en la lista de conocidos. Un malware puede saltarse el resolvedor de la red y consultar su propio servidor. Los destinos privados (el router, el DNS de la empresa) se consideran normales.


**`BruteForceDetector`**: Muchos intentos de conexión de una misma IP a SSH (22) o RDP (3389) en poco tiempo. Cada intento de iniciar sesión abre una conexión nueva: se cuentan los SYN puros de un origen hacia un mismo destino y puerto. Un usuario normal abre pocas; un programa que prueba contraseñas, decenas. Es una pista: no mira si el inicio de sesión falló (el tráfico va cifrado).


**`ThresholdDetector`**: Regla creada por el analista: N eventos que cumplen un filtro en una ventana de tiempo. Filtro: protocolo, red/IP de origen, red/IP de destino y puerto de destino (todo opcional). En TCP se cuentan los intentos de conexión (SYN puros); en UDP y `any`, cada paquete. Se cuenta por par origen -> destino y se alerta una vez por par.


### Notas del código

- `<módulo>`: Puertos de servicios que hablan a intervalos regulares de forma normal (DNS, NTP, mDNS, NetBIOS, SSDP, DHCP).
- `SuspiciousPortsDetector.feed`: Solo el SYN que inicia la conexión: las respuestas del servidor van al puerto efímero del cliente, que podría coincidir por casualidad con uno de la lista.
- `<módulo>`: Si este módulo se importó ANTES que engine, engine ya terminó de cargarse y no vio DETECTORS: se registran aquí. (Si engine se importó primero, ya lo hizo él y esto es inocuo.)
- `BruteForceDetector.__init__`: (origen, destino, puerto) -> instantes de los últimos intentos


## iocs.py

Lista de indicadores de compromiso (IOC) cargada desde un archivo local.

Un IOC es una IP, una red (CIDR) o un dominio que ya se sabe malicioso. El
analista carga su lista y Tracewell marca las sesiones que coinciden. Todo es
local: no se consulta ningún servicio externo (mandar IP de tu red a un tercero
filtraría datos).

Formatos (se detectan por la extensión y, si no alcanza, por el contenido):
- texto: un indicador por línea, `#` para comentarios (el formato original);
- CSV/TSV: con una columna de valor (`value`, `valor`, `indicator`, `ioc`, `ip`, `domain`...);
- STIX 2.1 (JSON): indicadores con patrón `ipv4-addr`, `ipv6-addr`, `domain-name` o `network-traffic`.
Las mismas validaciones valen para los tres (red /0 rechazada, IP mal escrita, límites de tamaño).


### Funciones y clases


**`_parse_entry`**: ('ip'|'red'|'dominio', valor) de un valor ya limpio; IocError indicando DÓNDE falló (por defecto, «línea N»).


**`parse_csv_iocs`**: CSV/TSV con una columna de valor. Con una sola columna se admite sin encabezado. Los errores indican la fila (`línea N`, contando también el encabezado y los comentarios).


**`_pattern_values`**: Valores de IP/dominio comparados con `=` (o con `IN`) en un patrón STIX. Un `NOT` lo descarta: sería lo contrario.


**`parse_stix_iocs`**: STIX 2.1 en JSON. Solo se leen indicadores de IP/dominio/tráfico de red; hashes, URL y demás se ignoran.


**`detect_format`**: 'stix', 'csv' o 'texto': por la extensión (.json/.stix, .csv/.tsv, .txt) y, si no dice nada, por el contenido.


**`load_iocs`**: Lee y valida un archivo de IOC (texto, CSV o STIX). FileNotFoundError si no existe (la API lo traduce a 404).


### Notas del código

- `IocSet`: Índice por (versión, prefijo) -> {dirección de red: (orden, red)}; se arma una vez en __post_init__.
- `<módulo>`: cada sesión se compara contra todas las redes: se acota el costo
- `_parse_entry`: ningún dominio real termina en un número: es una IP mal escrita



## Parámetros de detección lenta, por contenido y DNS agregado

Todos son opcionales en el YAML de la regla (carpeta `rules/`); sin ellos rigen los valores por defecto.

### `port_scan`: escaneo lento
- `long_window_seconds` (defecto 0 = apagada; la regla del repo usa 900): segunda ventana, larga.
- `long_threshold` (defecto 20): puertos distintos para alertar dentro de la ventana larga.
- Solo cuentan los puertos que NO respondieron SYN+ACK: un cliente que usa muchos servicios reales
  de un servidor no suma. Estado acotado: `_LRU` (MAX_TRACKED), purga por antigüedad al llegar al
  umbral y tope de 1024 puertos con respuesta recordados por par. Una alerta por par origen/destino.
- Costo: un escáner lento contra un host con muchos puertos abiertos (todos responden) no se ve por esta vía.

### `brute_force_remote`: fuerza bruta lenta
- `long_window_seconds` (defecto 0 = apagada; la regla del repo usa 300) y `long_attempts` (defecto 10).
- Un chequeo de monitoreo cada 60 s da 5 intentos en 300 s y no alerta; uno cada 30 s o menos sí.
  Con 900 s ese chequeo de 60 s alertaría (15 intentos), por eso la ventana larga es de 300 s.
- La evidencia (`threshold`, `window_seconds`) refleja la ventana que disparó la alerta.

### `ftp_cleartext`: por contenido
- Detecta `USER <usuario>` seguido de `PASS <clave>` en el mismo flujo TCP, en cualquier puerto.
- `ports` (defecto [21]) son los puertos de confianza: ahí un `PASS` sin `USER` visto también alerta.
- El `USER` debe llevar un solo argumento imprimible (el `USER` de IRC lleva varios y se descarta).
- POP3 usa los mismos comandos y también expone credenciales: se alerta igual, y `evidence.protocol`
  es `POP3` si el servidor saludó con `+OK`, `FTP` si saludó con `220` (o el puerto es 21) y
  `USER/PASS` si no se vio el banner. La contraseña nunca se guarda (`<oculta>` y su largo).

### `dns_suspicious`: túneles con etiquetas cortas
- `min_total_length` (defecto 50, 0 = apagado): subdominios sin el dominio registrable (aproximado:
  últimas 2 etiquetas, o 3 en `co.uk`/`com.ar`...), de al menos esos caracteres en total, en 2 o más
  etiquetas y con entropía >= `min_entropy`. Una sola etiqueta larga ya la cubre el análisis por etiqueta.
- `min_unique_subdomains` (defecto 0 = apagado) y `volume_window_seconds` (defecto 60): alerta si un
  origen consulta tantos subdominios únicos de un mismo dominio padre en la ventana. Apagado porque
  CDN y trackers legítimos generan muchos subdominios; actívelo en redes donde no ocurra.
- Se respeta `ignore_suffixes` en ambas medidas.

## Carpeta de reglas del usuario (`paths.py`, `load_all_rules`)

Las reglas nuevas del panel se guardan en una carpeta escribible fuera de la instalación:
Windows `%APPDATA%\Tracewell\rules`; otros sistemas `$XDG_CONFIG_HOME/tracewell/rules` o `~/.config/tracewell/rules`.
`TRACEWELL_USER_RULES_DIR` (o `create_app(user_rules_dir=...)`) la reemplaza; los tests la usan con `tmp_path`.

Criterio de carga (`engine.load_all_rules(incluidas, usuario)`):
1. Las reglas incluidas (`rules/`) se cargan estrictas: si una está mal, la app no arranca (como siempre).
2. Las del usuario se suman después. Si la carpeta no existe se omite (se crea al guardar la primera regla).
3. Una regla de usuario cuyo id ya existe (incluida, o un archivo de usuario anterior en orden alfabético)
   se IGNORA y se registra un aviso en el log `tracewell`: una regla de usuario no puede pisar ni
   desactivar una incluida. Un archivo de usuario roto también se ignora con aviso, para no impedir el arranque.
4. Guardar (`builder.save`) crea la carpeta si falta, rechaza ids ya activos (`409`) y traduce los errores de
   disco: `RuleSaveDenied` (`403`, sin permiso) y `RuleSaveError` (`500`, otro fallo), con mensaje en español.

## MITRE ATT&CK en las alertas (forma exacta del campo)

Cada regla declara su técnica en el YAML y TODA alerta la hereda. El motor valida al cargar que la
técnica sea `T####` o `T####.###` y que la táctica sea EXACTAMENTE una de estas (en este orden, como
`engine.MITRE_TACTICS`); una táctica distinta (`C2`, `discovery`, `Defense Evasion`...) falla al cargar
(una regla de usuario así se ignora con aviso en el log):

`Reconnaissance`, `Initial Access`, `Credential Access`, `Discovery`, `Lateral Movement`, `Collection`,
`Command and Control`, `Exfiltration`, `Impact`.

```yaml
mitre:
  technique: T1071.004                       # ID de ATT&CK
  name: "Application Layer Protocol: DNS"    # nombre de la técnica (subtécnica: «Padre: Hija»)
  tactic: Command and Control                # nombre canónico de la táctica
```

En el JSON de las alertas (`GET /api/alerts`, `GET /api/export`, `alerts` del reporte y de `/api/capture`)
son tres campos de texto PLANOS, siempre presentes y no vacíos, junto a `rule_id`, `name`, `severity`,
`description`, `src_ip`, `dst_ip`, `first_ts` y `evidence`:

```json
{ "mitre_tactic": "Discovery", "mitre_technique": "T1046", "mitre_name": "Network Service Discovery" }
```

- `mitre_tactic`: nombre canónico de la lista de arriba (para el ID `TA####` ver `export/siem.py`).
- `mitre_technique`: ID, con subtécnica si corresponde (`T1568.002`).
- `mitre_name`: nombre de la técnica tal como figura en ATT&CK.
- El constructor de reglas del panel usa por defecto `T1595 Active Scanning` / `Reconnaissance` y rechaza
  una táctica fuera de la lista.

Reglas incluidas (`rules/`):

| Regla | Técnica | Táctica |
|---|---|---|
| `port_scan` | T1046 Network Service Discovery | Discovery |
| `brute_force_remote` | T1110 Brute Force | Credential Access |
| `ftp_cleartext` | T1040 Network Sniffing | Credential Access |
| `syn_flood` | T1498 Network Denial of Service | Impact |
| `large_upload` | T1048 Exfiltration Over Alternative Protocol | Exfiltration |
| `beaconing` | T1071 Application Layer Protocol | Command and Control |
| `suspicious_ports` | T1571 Non-Standard Port | Command and Control |
| `host_sweep` | T1046 Network Service Discovery | Discovery |
| `dns_suspicious` | T1071.004 Application Layer Protocol: DNS | Command and Control |
| `dns_unusual_resolver` | T1071.004 Application Layer Protocol: DNS | Command and Control |
| `dga_nxdomain` | T1568.002 Dynamic Resolution: Domain Generation Algorithms | Command and Control |
| `malicious_ja4` | T1573 Encrypted Channel | Command and Control |
| `tls_certificate` | T1573 Encrypted Channel | Command and Control |
| `user_agent_scanner` | T1595.002 Active Scanning: Vulnerability Scanning | Reconnaissance |
| `user_agent_script` | T1071.001 Application Layer Protocol: Web Protocols | Command and Control |
| `smb_rpc_lateral` | T1021 Remote Services | Lateral Movement |
| `icmp_tunnel` | T1095 Non-Application Layer Protocol | Command and Control |

## Excepciones contra falsos positivos (`allow_hosts`, `allow_services`)

Además de `ignore_suffixes` (solo `dns_suspicious`), TODA regla acepta dos parámetros opcionales en `params`
(si no se declaran, no constan en `Rule.params`):

- `allow_hosts`: lista de IP o redes CIDR (`10.0.0.5`, `192.168.1.0/24`, `2001:db8::/32`). Un paquete cuyo
  origen O destino cae en la lista no se evalúa para esa regla. Sirve para servidores de archivos, controladores
  de dominio, escáneres autorizados o monitoreo.
- `allow_services`: lista de puertos (`445`) o nombres (`ssh`, `smb`, `rdp`, `dns`, `http`, `https`, `ftp`,
  `telnet`, `ntp`, `rpc`, `ldap`, `kerberos`, `winrm`); se normalizan a puertos. Un paquete TCP/UDP con ese
  puerto de origen o de destino no se evalúa. No aplica a ICMP.

`RuleRunner.feed` consulta `Detector.allow` (`engine.Allowlist`) antes de entregar el paquete al detector, así
que la excepción vale igual para las reglas incluidas, las de usuario y las creadas con el constructor.
Valores mal formados (IP inválida, puerto fuera de 0-65535, nombre desconocido) fallan al cargar la regla.
Una excepción silencia la regla por completo para ese host o servicio: use la más angosta posible.

## threat_detectors.py: detecciones nuevas

Detectores puros (sin FastAPI ni disco salvo el CSV de JA4). Se registran desde `extra_detectors.py`. `Decoded`
ahora también cubre ICMP/ICMPv6: `proto` 1 o 58, `sport` y `dport` en 0, `flags` = tipo ICMP y `payload` = carga
útil del eco (sin identificador ni secuencia). Los detectores que no son de ICMP lo ignoran.

| Detector (regla) | Qué mira | Parámetros (defecto) | Evidencia |
|---|---|---|---|
| `dga_nxdomain` | Respuestas DNS NXDOMAIN (UDP, puerto de origen 53) por cliente | `min_nxdomain` 20, `window_seconds` 60, `min_random_ratio` 0.5, `min_label_length` 8, `min_entropy` 2.5, `max_vowel_ratio` 0.3, `ignore_suffixes` [arpa, local] | `nxdomain_count`, `random_looking`, `random_ratio`, `sample_domains`, `resolver` |
| `ja4_blocklist` (`malicious_ja4`) | ClientHello TLS (hasta 12 segmentos TCP) y su huella JA4 | `fingerprints` [], `fingerprints_file` | `ja4`, `label`, `reference`, `sni`, `destination_port` |
| `tls_certificate` | Certificado del servidor en TLS <= 1.2 (en claro) | `flag_self_signed` true, `flag_expired` true, `external_only` true | `reasons`, `subject`, `issuer`, `not_before`, `not_after`, `self_signed`, `sha256`, `server_port` |
| `user_agent` (`user_agent_scanner`, `user_agent_script`) | Peticiones HTTP/1.x en claro (cualquier puerto TCP) | `patterns` [], `flag_empty` false, `flag_missing` false, `min_length` 0, `ports` [] | `user_agent`, `reasons`, `method`, `host`, `path`, `destination_port` |
| `smb_rpc_lateral` | SYN a 445/135 de un equipo interno hacia muchos internos | `ports` [445, 135], `min_hosts` 8, `window_seconds` 300, `internal_only` true | `distinct_hosts`, `sample_hosts`, `ports`, `window_seconds`, `threshold` |
| `icmp_tunnel` | Ecos ICMP (tipos 8/0; ICMPv6 128/129) por par origen -> destino | `min_payload_bytes` 256, `min_large_packets` 10, `min_packets` 600, `min_bytes` 2000000, `window_seconds` 60 (0 apaga `min_packets` y `min_bytes`) | `reasons`, `echo_packets`, `payload_bytes`, `large_packets`, `max_payload_bytes`, `window_seconds` |

Notas y control de falsos positivos:
- **DGA**: no basta el volumen de NXDOMAIN (un sufijo de búsqueda mal puesto los genera con nombres legibles).
  Un nombre «parece aleatorio» si su dominio registrable tiene >= `min_label_length` caracteres, entropía
  >= `min_entropy` y pocas vocales (`max_vowel_ratio`), o mezcla letras con dígitos o guiones. Con
  `min_random_ratio: 0` alerta solo por volumen. La alerta se lee cliente -> resolvedor. Una por cliente.
- **JA4**: la lista se entrega VACÍA. Una huella identifica una biblioteca TLS que comparten programas
  legítimos y maliciosos; no se inventan huellas. Una coincidencia es un indicio, no una prueba. Si el ClientHello
  llega partido (hello grande, p. ej. con grupos poscuánticos) se unen hasta 12 segmentos o 64 KiB del mismo flujo.
- **Certificados**: el vencimiento se compara con la hora de la CAPTURA, no con la de hoy. En TLS 1.3 el
  certificado va cifrado y no se evalúa. Por defecto solo servidores públicos (`external_only`): los equipos
  internos usan certificados propios a menudo. Una alerta por servidor y certificado; se lee cliente -> servidor.
  El certificado se busca en los primeros 12 segmentos o 64 KiB del flujo del servidor, sin reordenar segmentos.
- **User-Agent**: `flag_empty` marca la cabecera presente pero vacía; `flag_missing` marca la petición completa
  sin la cabecera (apagado en la regla incluida: muchos clientes simples la omiten, y el pcap de demostración
  trae una así). La ruta se guarda sin la query y el agente se trunca a 200 caracteres y se sanea. Una alerta por
  origen, destino y agente. `user_agent_scanner` (alta) lista herramientas de escaneo; `user_agent_script`
  (baja) lista bibliotecas de scripts y agentes vacíos o de menos de `min_length` caracteres.
- **SMB/RPC**: cuenta destinos DISTINTOS por origen en la ventana. Servidores de archivos, controladores de dominio
  y consolas de gestión hablan con muchos equipos por diseño: agréguelos a `allow_hosts`. Con `internal_only` solo
  cuentan origen y destino en redes privadas.
- **ICMP**: ventanas fijas (memoria constante por par). Un ping normal lleva 32-64 bytes; una prueba de MTU o
  `ping -s` grande a propósito es el falso positivo típico (por eso `min_large_packets` 10). Una alerta por par.
- Todas guardan estado acotado (`_LRU`, topes por flujo) y toleran basura sin lanzar excepciones.

### Archivo de huellas JA4 (`rules/data/ja4_malicious.csv`)

Texto UTF-8, una huella por línea: `ja4,etiqueta,referencia`. Las líneas vacías y las que empiezan con `#` se
ignoran. Solo la huella es obligatoria (10 caracteres alfanuméricos, `_`, 12 hex, `_`, 12 hex; se pasa a
minúsculas); etiqueta (80 caracteres) y referencia (200) aparecen en la evidencia. Una línea inválida se omite
con un aviso en el log `tracewell`. Tope: 1 MB y 50 000 huellas. La ruta de `fingerprints_file` es relativa a la
carpeta del YAML, sin `..` ni rutas absolutas; si el archivo falta o no se puede leer, la regla avisa y queda
sin huellas (no tumba el análisis). Agregue solo huellas que pueda justificar con una fuente fiable y cítela.
