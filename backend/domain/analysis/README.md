# Documentación de `backend/domain/analysis`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## analyzer.py

Orquestador: lee un pcap, agrupa sesiones y evalúa reglas.

Por qué vive en `core` y no en `api`: es lógica de negocio ("qué significa
analizar una captura"). Si la dejáramos en la API, una CLI o la ventana de
escritorio tendrían que duplicarla o levantar un servidor para usarla.


### Funciones y clases


**`analyze`**: Tres pasadas en streaming sobre el archivo (sesiones, reglas y nombres de sitio). Varias pasadas en vez de una: cada consumidor queda simple e independiente y la memoria no crece con el archivo. Si el costo duele en capturas enormes, se unifica después (decisión anotada en docs/decisiones.md).


**`session_packets`**: Paquetes de una sesión, paginados -> (lista de PacketSummary, hay_más). No guardamos los paquetes de cada sesión (la memoria crecería con el archivo): releemos el pcap y nos quedamos con los de esa clave.


**`session_stream`**: Conversación de una sesión TCP, reconstruida releyendo el archivo (como `session_packets`). IndexError si la sesión no existe; ValueError si no es TCP (los otros protocolos no tienen "conversación").


### Notas del código

- `Analysis`: paquetes y bytes por intervalo (None si la captura no tiene paquetes)


## case_timeline.py

Cronología del caso: alertas, DNS sospechoso, sesiones marcadas e IOC, juntos y en orden de tiempo.

Es una vista NUEVA, distinta del gráfico de paquetes por intervalo (`timeline.py`): acá cada fila es un hecho
que un analista cuenta en un ticket («a las 10:03 el equipo X consultó este dominio raro; a las 10:04 saltó
la alerta de beaconing; la sesión 12 coincide con un IOC»). Con `host` se limita a un equipo.

Funciones puras: reciben lo ya calculado (alertas, filas de DNS, sesiones, notas, coincidencias de IOC).
La hora es la del PRIMER paquete de cada hecho (UTC, epoch); a igual hora conserva este orden de clase:
alerta, IOC, DNS, sesión marcada.


### Funciones y clases


**`_dns_events`**: Solo las consultas con pistas (nombre aleatorio, NXDOMAIN, TTL bajo...): el resto es ruido en un caso.


**`build_case_timeline`**: Hechos del caso en orden cronológico. `host` limita a los que involucran esa IP (ValueError si no es una IP); `limit` acota cuántos se devuelven (los más antiguos) y `truncated` avisa si había más.


## direction.py

Dirección de una sesión respecto de TU red: ¿quién habló con quién, adentro o afuera?

Etiquetas: «Interno→Externo» (salida a internet), «Externo→Interno» (algo de afuera le habló a un equipo tuyo),
«Interno→Interno (lateral)» (entre equipos de la red local, donde se mueve un atacante ya adentro) y
«Externo→Externo» (ninguno de los dos extremos es de la red local: tráfico que pasó por la captura, un tránsito).
Si un extremo es multicast se etiqueta aparte («Multicast»): no es ni adentro ni afuera.

La flecha va del CLIENTE al SERVIDOR, no del primer paquete visto: si la captura empezó a mitad de la
conversación el «origen» de la sesión puede estar invertido, y se corrige con la misma regla que usa la vista
de equipos (puerto de servicio y, si no alcanza, estar afuera de la red). Es una pista, no una prueba: «interno»
significa dirección privada (RFC 1918, ULA, link-local, loopback); no se conoce la topología real.


## dns_log.py

Tabla de DNS: qué nombres se consultaron, cuántas veces, qué respondieron y qué salió mal.

Es el equivalente simple del `dns.log` de Zeek (o de filtrar `dns` en Wireshark): una fila por nombre y
tipo de consulta (A, AAAA, MX...). Sirve para ver de un vistazo a qué se conectó un equipo, qué nombres
NO existen (NXDOMAIN) y qué nombres parecen generados al azar.

Límites (conscientes): una fila por (nombre, tipo) con topes (`MAX_ENTRIES`, listas cortas) para acotar la
memoria; solo DNS sobre UDP (el DNS sobre TCP, DoH y DoT no se ven aquí).


### Funciones y clases


**`_rr_answers`**: Direcciones y CNAME de un registro de respuesta; los de largo inválido (paquete raro o hostil) se ignoran.


### Notas del código

- `<módulo>`: bits por carácter del primer label a partir de los cuales "parece aleatorio"


## explain.py

«¿Qué pasó en esta sesión?» explicado en palabras simples, más un diagrama paso a paso de la conexión.

Es la parte didáctica: lo que un analista experto "lee" de los paquetes (el saludo de 3 pasos, un RST, un
keep-alive) escrito como frases, y la conversación dibujada como el «Flow Graph» de Wireshark.

Todo sale de las BANDERAS y los tamaños de los paquetes de la sesión; no se interpreta el contenido
(salvo reconocer HTTP o TLS por los primeros bytes). Las frases son orientativas: describen lo que se ve
en la captura, no prueban intenciones.


### Funciones y clases


**`_labels`**: (origen, destino) con el nombre del sitio pegado al SERVIDOR, que no siempre es el destino: si la captura empezó a mitad de la conversación el «origen» puede estar invertido.


**`_is_single_probe`**: Una sesión de pocos paquetes cuyo ÚNICO dato es 1 byte 00, sin saludo ni cierre: la forma de una sonda keep-alive.


**`explain_session`**: Resumen en frases y pasos de la conexión de `session`, a partir de SUS paquetes (en orden de captura).


## hosts.py

Vista por EQUIPO (IP) de una captura: quién es cada uno, con quién habla y cuánto.

Es la mirada que usan NetworkMiner o la pestaña "Conversaciones → IPv4" de Wireshark, pero resumida:
una fila por IP y un grafo "quién habla con quién". Todo sale de las sesiones ya calculadas, sin
volver a leer la captura.

Límites: se resume por SESIÓN (no por paquete); los bytes de una sesión cuentan para sus DOS extremos;
`MAX_PEERS` acota la memoria por equipo (un escaneo a miles de destinos no la hace crecer sin límite).


### Funciones y clases


**`_Acc.add`**: `service_port` y `name` solo llegan si este equipo es el SERVIDOR de la sesión; `client_service`, si es el CLIENTE.


**`_server_is_src`**: ¿El servidor es el extremo de ORIGEN? El "origen" es quien mandó el primer paquete VISTO: si la captura empezó a mitad de la conversación está al revés. Se decide por el puerto (uno bajo, como 443, es un servicio), y si no alcanza, por la red: el que está afuera de la red local es el servidor.


**`_host_mac`**: La MAC solo identifica al equipo si es de la red local y de UN equipo: se descartan las de grupo (multicast y broadcast, bit 0 del primer byte) y las de equipos remotos (serían la del router).


**`build_mac_groups`**: Agrupa los equipos por MAC: una fila por MAC con sus IP. Los grupos con varias IP van primero. Solo entran equipos de la red local con una MAC conocida; los demás no tienen MAC propia en la captura.


### Notas del código

- `Host`: Perfil: roles INFERIDOS de lo observado en esta captura (cliente DNS, servidor web, emisor de escaneos, top talker). Son pistas, no una auditoría: un equipo que no aparece no «no es» eso.
- `Host`: MAC más vista de este equipo (solo equipos de la red local: la MAC de un extremo remoto es la del router).
- `_to_host`: Un equipo de TU red no se llama como el sitio al que se conecta: el nombre es del servidor.
- `<módulo>`: destinos distintos que se recuerdan por equipo (después solo se cuenta)
- `<módulo>`: ...y solo si movieron al menos esta parte de los bytes de la captura
- `<módulo>`: acotada; se llama varias veces por sesión con pocas IP distintas
- `_Acc.__init__`: (protocolo, puerto) de los servicios a los que este equipo SE CONECTÓ


## http.py

Analizador de HTTP sin cifrar: qué pidió cada cliente y qué le respondieron, y los archivos que viajaron.

Trabaja sobre los bytes ya reconstruidos de cada sentido de una sesión TCP (`raw_directions`). Con HTTPS no
hay nada que leer: el contenido va cifrado.

Reglas de seguridad (a propósito):
- NUNCA se guardan valores de contraseñas ni tokens: de un formulario solo se informan los NOMBRES de los
  campos sensibles, y de una autenticación Basic solo el usuario.
- Los archivos extraídos se identifican por su huella SHA-256 y su tipo REAL (por los primeros bytes, no por
  la extensión). Si se descargan, es como `.bin`: son datos de la red y pueden ser malware.

Límites: HTTP/1.x (no HTTP/2); si faltan bytes en la captura, el intercambio se marca incompleto.


### Funciones y clases


**`_sensitive_fields`**: NOMBRES de campos con pinta de contraseña (en la URL o en un formulario). Los valores nunca se guardan.


**`_client_server`**: (bytes del cliente, bytes del servidor). El «origen» puede estar invertido si la captura empezó a mitad.


**`http_body`**: (cuerpo, nombre seguro) del archivo del intercambio `index`, o None si ese intercambio no tiene archivo.


### Notas del código

- `<módulo>`: Tipo real de un archivo según sus primeros bytes: (prefijo, descripción, ¿es ejecutable o peligroso?).
- `_messages`: ya no es HTTP (o se perdió el hilo): se corta en vez de inventar


## http_scan.py

Busca HTTP en TODA la captura (no solo en una sesión): una fila por petición, con su respuesta.

Para no leer el archivo una vez por sesión, se hace UNA pasada y se juntan los paquetes de las sesiones
candidatas. Como no se puede saber si una sesión es HTTP sin mirarla, los candidatos son las de TCP a los
puertos habituales de HTTP; para otro puerto se abre la sesión y se lee ahí. Hay topes (sesiones, bytes,
intercambios) y se informa cuando se alcanzan.


## names.py

Nombre del sitio de cada sesión, sacado de la PROPIA captura (sin consultar a nadie).

Dos fuentes, ambas visibles en claro dentro de una captura:
- las respuestas DNS ("example.com" -> 93.184.216.34): sirven para ponerle nombre a una IP;
- el SNI del saludo TLS (ClientHello): el nombre que el cliente le pide al servidor
  al iniciar una conexión HTTPS, aunque el resto vaya cifrado.

Límites (conscientes): una IP compartida (CDN) puede tener varios nombres y se guarda el
PRIMERO visto; con ECH o DNS cifrado (DoH/DoT) el nombre no es visible; un ClientHello
partido en varios segmentos TCP puede perder el SNI (solo se mira el primer paquete).


### Funciones y clases


**`_l4_full`**: (protocolo, puerto origen, puerto destino, IP origen, IP destino, clave de sesión, payload) de un paquete TCP/UDP, o None.


### Notas del código

- `_first_host_name`: Si el paquete se cortó DENTRO del nombre, devolver el pedazo daría un sitio falso (y un IOC falso).


## owners.py

Quién es una IP, SIN salir a internet: un rol (tu red, multicast, servidor público…) y, para unos pocos
proveedores grandes, el dueño del rango.

La tabla de dueños es CHICA y a propósito conservadora: solo rangos que pertenecen a una empresa conocida.
Es una pista, no una prueba: una IP de Amazon o de Microsoft puede estar alquilada a cualquiera (la nube se
alquila), y los rangos cambian con el tiempo. Por eso la pantalla lo muestra como «rango de …», nunca como
un hecho, y un nombre sacado de la propia captura (DNS o TLS) siempre le gana.


## remote_access.py

Acceso remoto: quién se conecta a SSH, Telnet, SMB, RDP, WinRM o VNC, y cómo le fue.

Agrupa por servicio las sesiones TCP cuyo puerto de servicio es uno de la tabla. Es la lista que un analista
revisa primero ante un posible movimiento lateral o fuerza bruta: ¿quién entra a quién, cuántas veces
reintentó y cuántas conexiones se cortaron con RST?

Las señales salen solo de las banderas TCP que cuenta el agrupador (`syn_packets`, `rst_packets`) y son
pistas: un RST puede ser un puerto cerrado, un firewall o un corte normal de la aplicación; varios SYN
seguidos pueden ser un reintento por pérdida de paquetes y no un ataque.


### Funciones y clases


**`normalize_service`**: Nombre canónico del servicio (sin distinguir mayúsculas), None si no se pidió; UnknownService si no existe.


**`service_of`**: (servicio, puerto) si la sesión es TCP a un puerto de acceso remoto, o None. El puerto de servicio es el del destino y, si la captura empezó a mitad de la conversación (origen invertido), el del origen.


**`remote_access`**: Sesiones de acceso remoto agrupadas por servicio. El `id` de cada una es su posición en `sessions` (el mismo id que usa el resto de la API). `service` limita a un servicio (UnknownService si no existe).


### Notas del código

- `<módulo>`: sesiones que se detallan por servicio (el resumen cuenta todas)


## stream.py

Reconstruye lo que se dijo en una sesión TCP ("Follow TCP Stream" de Wireshark).

Junta los datos de cada sentido en orden de número de secuencia, descarta
retransmisiones y marca los huecos (bytes que faltan en la captura). Con protocolos en
claro (FTP, HTTP, Telnet, SMTP) se lee la conversación entera; con TLS el contenido va
cifrado y solo se informa eso.

Límites (conscientes): se leen como máximo `MAX_BYTES` de datos y `MAX_PACKETS` paquetes;
un segmento que llega desordenado después de un hueco se muestra tal como llegó.


### Funciones y clases


**`_emit`**: Agrega datos: si el bloque anterior es del mismo sentido, se une (una conversación se lee por turnos).


**`raw_directions`**: Los bytes de cada sentido por separado y sin recortar (los analizadores de protocolo los necesitan enteros: una cabecera HTTP o un certificado TLS no se puede leer a pedazos).


### Notas del código

- `<módulo>`: un salto de secuencia mayor se toma como una conexión distinta, no como un hueco
- `Stream`: el primer dato parece un registro TLS: el contenido no se puede leer
- `RawDirections`: faltan bytes en la captura: lo reconstruido puede estar incompleto


## timeline.py

Tráfico a lo largo del tiempo: paquetes y bytes por intervalo, para dibujar un gráfico.

Sirve para ver de un vistazo picos, silencios y ritmos regulares (lo que delata un
beaconing). Solo usa el instante y el largo de cada paquete: no decodifica nada.

Memoria acotada: se agrupa por intervalos de `g` segundos y, si hay demasiados, `g` se
duplica y se fusionan; al final se reagrupa a lo sumo en `MAX_BINS` barras.


### Notas del código

- `<módulo>`: intervalos finos que se guardan antes de volverlos más gruesos


## tls.py

TLS sin descifrar: la huella JA4 del cliente, la versión negociada y el certificado del servidor.

Con TLS el contenido va cifrado, pero el SALUDO inicial viaja en claro y dice mucho:
- el ClientHello trae la lista de cifrados y extensiones del cliente: de ahí sale la huella **JA4**, una
  «firma» de cómo se presenta el programa (dos programas distintos casi nunca dan la misma);
- el ServerHello dice qué versión y cifrado se acordaron;
- en TLS 1.2 (y anteriores) el servidor manda su certificado en claro. En **TLS 1.3 el certificado va
  cifrado** y no se puede ver: la interfaz lo explica.

JA4 sigue la especificación pública de FoxIO (BSD-3). Se implementa a mano, sin dependencias: ver las pruebas
contra la implementación de referencia en docs/decisiones.md.

Límites: solo TCP (no QUIC); un saludo partido en segmentos se reconstruye con la sesión; la lectura de
certificados es mínima (sujeto, emisor, validez, nombres alternativos y huella) y nunca lanza.


### Funciones y clases


**`_is_grease`**: Valores «GREASE» (0x0a0a, 0x1a1a... 0xfafa): relleno que los clientes meten a propósito; JA4 los ignora.


**`_handshakes`**: Mensajes de handshake (tipo, cuerpo) de los registros 0x16 del flujo, ya unidos (un mensaje puede ocupar varios).


**`ja4`**: Huella JA4 del cliente: `t13d1516h2_<12>_<12>` (protocolo, versión, ¿nombre?, nº cifrados, nº extensiones, ALPN).


**`_name_attr`**: Valor del atributo `oid` (por ejemplo CN) dentro de un Name (SEQUENCE de SET de SEQUENCE{OID, valor}).


### Notas del código

- `ClientHello`: el saludo llegó entero: sin esto la huella JA4 sería incorrecta
- `ServerHello`: el NEGOCIADO (en TLS 1.3 sale de la extensión supported_versions)


## wireshark_filter.py

Filtros de visualización de Wireshark para una sesión, una IP o una alerta.

Es la «llave» para pasar de Tracewell a Wireshark: el analista copia el filtro, abre el `.pcap` y ve los
mismos paquetes. Funciones puras (sin I/O): reciben datos simples y devuelven texto.

Todo lo que viene del tráfico (nombres DNS, por ejemplo) se escapa antes de ir entre comillas: un nombre
hostil no puede cerrar la cadena y agregar condiciones al filtro.


### Funciones y clases


**`_quote`**: Cadena entre comillas para Wireshark: se escapan la barra y la comilla, y se descartan los controles.


**`alert_filter`**: Filtro de una alerta, derivado de su evidencia. Sin evidencia útil devuelve los dos extremos; con ella lo afina: nombre DNS (`dns.qry.name`), puertos de un escaneo, puerto de destino o la víctima de una inundación. Es una pista para llegar a los paquetes: el analista puede ampliarlo o recortarlo en Wireshark.

