# Documentación de `backend/domain/sessions`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## grouper.py

Agrupa paquetes en sesiones (flujos de red).

Una sesión es una conversación entre dos extremos: se identifica por la
"5-tupla" (IP origen, puerto origen, IP destino, puerto destino, protocolo).

Por qué agrupar: un analista no mira 2 millones de paquetes sueltos; mira
"esta IP habló 40.000 veces con aquella en el puerto 21". La sesión es la
unidad con la que razonan las reglas (escaneo de puertos = una IP, muchas
sesiones a puertos distintos).


### Funciones y clases


**`_inner_ethertype`**: Ethertype real del contenido: con una etiqueta VLAN 802.1Q, dpkt deja `eth.type` en 0x8100 y guarda el tipo interno en la última de `vlan_tags`.


**`ip_layer`**: Ethernet -> capa IP: devuelve (ip, familia) o None si el paquete no es IP. Lanza dpkt.UnpackError si está dañado o es un fragmento sin capa 4.


**`_endpoints_flags`**: ((ip_src, sport, ip_dst, dport, proto), flags TCP) o None si no es IP (flags = 0 si no es TCP). Lanza dpkt.UnpackError si el paquete está dañado.


**`_key`**: Clave BIDIRECCIONAL: A->B y B->A caen en la misma sesión. Ordenamos los dos extremos para que no importe quién habla. Sin esto, la respuesta del servidor abriría una "sesión" aparte de la petición.


**`packet_endpoints`**: (ip_src, sport, ip_dst, dport, proto) de un paquete, o None si no es IP o está dañado. Versión que nunca lanza, para consultas sueltas.


**`group_packets`**: Recorre los paquetes (en streaming) y arma las sesiones. En memoria guardamos un resumen por sesión, no los paquetes: el costo crece con la cantidad de sesiones (~640 B cada una), no con el tamaño del archivo. Pero un escaneo o un DDoS puede generar millones de sesiones, así que hay un TOPE: al alcanzarlo, las sesiones nuevas se descartan (las existentes siguen actualizándose) y el resultado queda marcado `truncated`.


### Notas del código

- `Session`: Clave bidireccional de la sesión. Sirve para volver a encontrar sus paquetes más tarde sin guardarlos en memoria. Interna: no se exporta.
- `Session`: Banderas TCP contadas por sesión (0 en UDP/ICMP). Sirven para ver rechazos y reintentos (acceso remoto, escaneos). Internas: NO van al JSON exportado, que arma sus claves a mano.
- `Session`: MAC de cada extremo, leídas del PRIMER paquete de la sesión (Ethernet). Solo dicen algo del equipo si está en la misma red local: tras un router, la MAC de un extremo remoto es la del router. Internas: NO van al JSON exportado.
- `GroupingResult`: Análisis parcial: se alcanzó el tope de sesiones y las sesiones NUEVAS ya no se registraron. Se informa para que el analista no crea que vio todo.
- `ip_layer`: Un fragmento que NO es el primero no trae cabecera TCP/UDP: sus "puertos" serían basura. Lo tratamos como dañado en vez de inventar.
- `ip_layer`: El Ethernet DICE llevar IP pero dpkt no pudo leerla (cabecera cortada) y dejó bytes crudos: es un paquete dañado, no uno "sin IP" como un ARP. Sin esto se contaba en `non_ip` y el analista no veía que había daño.
- `_protocol_number`: En IPv6 dpkt solo setea `p` (protocolo del payload tras las cabeceras de extensión) si pudo seguir la cadena; con ESP (cifrado) no hay "siguiente" visible y `p` no existe. En ese caso la última cabecera de la cadena es lo más honesto que podemos reportar.
- `_record_packet`: origlen = bytes reales en el cable; len(data) puede ser menos si hubo snaplen. Para "cuánto tráfico fue" importa lo que viajó, no lo guardado.
- `<módulo>`: linktype soportado por ahora (el 99% de las capturas de escritorio)
- `Session`: SYN puros (intentos de abrir conexión), contando los reenviados


## query.py

Consultas sobre sesiones: filtros y estadísticas.

Por qué existe: después de agrupar, el analista quiere acotar ("solo TCP al
puerto 21") y tener una foto general ("¿qué protocolos dominan?"). Ambas
operaciones trabajan sobre las sesiones ya resumidas, nunca sobre el pcap:
son baratas y se pueden repetir cada vez que el usuario cambia un filtro.


### Funciones y clases


**`filter_sessions`**: Devuelve las sesiones que cumplen TODOS los criterios dados (AND). - protocol: sin distinguir mayúsculas ("tcp" == "TCP"). - ip: coincide si es el origen O el destino (la sesión es bidireccional, al analista le da igual quién inició). - port: ídem, origen o destino. Un criterio en None no filtra.


**`compute_stats`**: Totales y distribución por protocolo. Acepta un GroupingResult (incluye non_ip/malformed) o una lista de sesiones, p. ej. ya filtrada: así las estadísticas siguen al filtro.


### Notas del código

- `_parse_ip_filter`: Solo texto: ipaddress acepta bytes/int como "dirección empaquetada", y un filtro que viene de la UI nunca debería llegar así.
- `_parse_ip_filter`: Zona IPv6 (fe80::1%eth0): Python la acepta pero las IPs de las sesiones nunca la llevan, así que jamás coincidiría y devolvería [] en silencio, justo lo que queremos evitar.
- `_normalize_protocol`: "" no significa "sin filtro" (eso es None): sería un filtro que no coincide con nada y devolvería [] sin avisar.
- `_matches`: Comparamos como objetos IP, no como texto: "::1" y "0:0:0:0:0:0:0:1" son la misma dirección pero distinto string.
- `filter_sessions`: Validamos ANTES de recorrer: un filtro inválido debe fallar fuerte, no devolver una lista vacía que parezca "no hay tráfico".
- `Stats`: Paquetes que no entraron en ninguna sesión: se informan aparte para que el total no esconda tráfico (ARP) ni archivos dañados.

