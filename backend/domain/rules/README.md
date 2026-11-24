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
