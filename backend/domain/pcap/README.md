# Documentación de `backend/domain/pcap`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## Robustez ante archivos hostiles

`iter_indexed` traduce a `PcapError` los fallos internos de dpkt ante campos imposibles (longitud de bloque
pcapng menor a 8: dpkt leía un número negativo de bytes y escapaba un `ValueError` crudo, que la API devolvía como
500). Lo encontró el fuzz de archivo (`analysis/tests/test_fuzz_file.py`).

## Permisos de captura (`ScapySource`)

Si falta permiso, el error (`PermissionDenied`, `403`) ofrece alternativas a correr todo como administrador o root. En Linux: `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))` (aplica a ese intérprete y a todo lo que corra con él). En Windows: reinstalar Npcap y desmarcar "Restrict Npcap driver's access to Administrators only". El texto vive en `PERMISSION_HELP` (`live.py`).

## hexdump.py


### Funciones y clases


**`hexdump`**: Una línea por `width` bytes: offset | bytes en hex | ASCII imprimible. Por qué el panel ASCII: el analista busca texto legible (un USER/PASS, un dominio) dentro de los bytes; los no imprimibles se muestran como '.'.


### Notas del código

- `_hex_line`: Rellenamos a ancho fijo para que la columna ASCII quede alineada aunque la última línea tenga menos bytes.


## layers.py

Decodifica un paquete capa por capa, con el rango de bytes de cada campo.

Sirve para el panel de detalle (como el de Wireshark): cada campo trae su valor
legible, una pista en lenguaje simple y la posición `start:end` dentro del
paquete, para resaltar esos bytes en el hex dump.

Se decodifica a mano con `struct` (y no con dpkt) porque dpkt no informa en qué
byte empieza cada campo. Un paquete cortado o raro NUNCA lanza: se muestra lo que
se pueda leer y se marca la capa como incompleta.


### Funciones y clases


**`_ipv6_extensions`**: Salta cabeceras de extensión (salto a salto, enrutamiento, destino). (protocolo final o None, posición).


**`dissect`**: Capas del paquete (Ethernet, IP, TCP/UDP/ICMP/ARP, datos) con el rango de bytes de cada campo. Nunca lanza: ante cualquier problema devuelve las capas que pudo leer.


### Notas del código

- `_truncated`: start nunca pasa del final: el resaltado del hex dump depende de 0 <= start <= end <= largo.
- `_ipv6_extensions`: la extensión declara más bytes de los que hay: el paquete está cortado


## live.py

Captura en vivo desde una interfaz de red.

AISLAMIENTO (regla de diseño): todo lo que toca la red real vive acá y solo
acá. El resto del sistema recibe un archivo .pcap normal; la captura en vivo
es "un productor de pcaps", y todo lo demás (sesiones, reglas, API) ya sabe
leerlos. Por eso este módulo no se prueba contra la red real en CI: sus tests
usan una fuente simulada y la validación real va en docs/checklist_hardware.md.

Dos piezas:
- Una FUENTE de paquetes (`PacketSource`): la real usa Scapy; los tests usan
  una falsa. Scapy se importa recién cuando hace falta, así el resto de la app
  arranca aunque Scapy o Npcap no estén instalados.
- `LiveCapture`: gestiona hilos, límites y escritura del pcap, sin saber de
  dónde vienen los paquetes.


### Funciones y clases


**`ScapySource`**: Fuente real basada en Scapy. Por qué Scapy y no pcapy-ng: instala con pip en Windows/Linux/macOS sin compilar nada (pcapy-ng necesita headers de libpcap/Npcap SDK), y lista interfaces de forma portable. Costo: es una dependencia pesada para el ejecutable; por eso se importa de forma perezosa y solo se usa acá.


**`ScapySource._wait_started`**: Espera a que el hilo de Scapy abra el socket; si murió antes, relanza su error. Por qué: AsyncSniffer.start() vuelve YA, y los fallos de apertura (sin permisos, interfaz inexistente) ocurren después, dentro de su hilo. Sin esta espera la captura "empezaba bien" y terminaba con 0 paquetes y sin aviso.


**`cleanup_stale_temp_dirs`**: Borra las carpetas temporales de capturas que quedaron por un cierre abrupto. Si el programa se mata (cerrar la terminal, cortar el proceso) no corre la limpieza normal y la carpeta `tracewell_*` con el pcap queda en el disco del usuario. Esto se llama al arrancar. Es conservador a propósito: solo toca carpetas `tracewell_*` dentro de la carpeta temporal, con más de `max_age` segundos y que contengan únicamente `live.pcap`; nunca lanza por un fallo de disco (limpiar es opcional, arrancar no). Devuelve las rutas borradas.


**`LiveCapture`**: Captura de una fuente a un archivo .pcap, con límites y detención segura. Hilos: la fuente llama a `_on_packet` desde SU hilo; un hilo monitor es el único que llama a `source.stop()` y cierra el archivo. Detener desde el propio hilo del sniffer podría bloquearse esperándose a sí mismo.


**`LiveCapture.cleanup`**: Borra la carpeta temporal que creó esta captura (si la creó ella). No se puede llamar con la captura en curso. Las rutas que pasó el llamador (`out_path`) NUNCA se borran: no son nuestras.


**`LiveCapture._stop_source`**: Detiene la fuente SIN poder quedarse colgado más de STOP_TIMEOUT. `source.stop()` puede bloquearse (un driver que no responde, un join que nunca vuelve). Lo corremos en un hilo aparte y esperamos con tope: si vence, seguimos adelante y cerramos el archivo igual; los paquetes que lleguen después se ignoran porque `_done` ya está marcado.


**`LiveCapture._close_file`**: Vacía y cierra el pcap. Un error de E/S (disco lleno) queda en `error` y no impide marcar la captura como terminada: si se propagara desde el hilo monitor, `stop()` esperaría para siempre.


### Notas del código

- `<módulo>`: Límites por defecto: una captura olvidada no debe llenar el disco ni correr para siempre. El usuario puede subirlos explícitamente.
- `<módulo>`: Las carpetas temporales de captura empiezan con este prefijo (y la limpieza de restos viejos solo toca las que lo tienen). STALE_AFTER: 24 h, mucho más que lo que puede durar una captura (la API la limita a 1 h).
- `ScapySource.start.handle`: Escribimos el pcap como Ethernet (linktype 1). Un paquete de otra capa 2 (p. ej. loopback) se interpretaría mal: lo descartamos contando cuántos, en vez de escribir datos corruptos.
- `CaptureSummary`: Algo salió mal sin impedir cerrar el archivo (la fuente no se detuvo a tiempo, falló al detenerse, error de escritura). Sin esto, quien mire solo el resumen creería que todo terminó bien.
- `_is_finite_number`: isfinite: NaN no es <= 0 ni < 0 (toda comparación con NaN da False) y pasaría una validación de rango, dejando un "límite" que nunca vence.
- `_resolve_out_path`: Si no nos dan ruta, creamos una carpeta temporal PROPIA: la recordamos en `temp_dir` para poder borrarla con cleanup() (si no, cada captura dejaría una carpeta huérfana en el disco del usuario).
- `cleanup_stale_temp_dirs`: Con NaN todo contaba como "viejo" (borraba también las carpetas recientes); en una función que borra, un valor así tiene que fallar fuerte.
- `LiveCapture._stop_source.run`: Un fallo al detener la fuente no debe dejar un traceback suelto en el hilo ni impedir cerrar el archivo: lo guardamos en `error`.
- `LiveCapture._write_packet`: borde del hilo del sniffer: disco lleno, archivo cerrado, dato raro


## processes.py

Qué proceso tiene abierto cada socket (SOLO para la captura en vivo).

Por qué solo en vivo: un .pcap no dice qué programa generó cada paquete; esa
información la tiene únicamente el sistema operativo, y solo mientras la
conexión está abierta. Por eso, durante una captura en vivo, un hilo le pregunta
al sistema cada segundo "¿qué conexiones hay abiertas y de qué proceso son?" y
anota lo que ve. Al terminar, cada sesión se busca en esa tabla.

Límites (conscientes):
- Es una foto cada `SAMPLE_INTERVAL`: una conexión más corta que eso puede no verse.
- UDP sin "conexión" se identifica por el puerto local, que es menos preciso.
- psutil es OPCIONAL: sin él (o si falla) la función no existe y nada más se rompe.


### Funciones y clases


**`normalize_ip`**: IP en forma canónica, o None si no es una IP. Quita el sufijo de zona (`fe80::1%12`) y convierte IPv4-mapeada (`::ffff:1.2.3.4`, típica de sockets de doble pila) a IPv4, para que coincida con lo que el lector de capturas entrega.


**`ProcessTable.add`**: Anota una conexión. Gana la PRIMERA vista: un puerto reutilizado después por otro programa no debe reetiquetar sesiones anteriores.


### Notas del código

- `PsutilProvider._to_conn`: PID 0 (o None): conexiones sin dueño real, p. ej. TIME_WAIT. Windows las atribuye a "System Idle Process", que NO es quien las abrió: etiquetarlas así sería mentir.
- `<módulo>`: tope por tabla: acota la memoria en capturas con muchísimas conexiones
- `PsutilProvider.connections`: solo dentro de esta muestra: los PID se reutilizan entre muestras
- `PsutilProvider._name_of`: NoSuchProcess / AccessDenied / ZombieProcess: el nombre es opcional
- `ProcessSampler._sample_safely`: borde de hilo: esta función es OPCIONAL y no puede afectar la captura


## reader.py

Lectura de capturas .pcap / .pcapng en streaming.

Por qué streaming: un pcap puede pesar GB. Si lo cargáramos entero en memoria
con list(), una captura grande tumbaría la app. Con un generador, procesamos
de a un paquete y la memoria se mantiene constante.


### Funciones y clases


**`PcapError`**: Archivo inválido, vacío o truncado. Hereda de ValueError para que los llamadores puedan capturarlo sin importar detalles internos de dpkt (así `core` oculta su dependencia).


**`Packet.snaplen_limited`**: True si la captura guardó MENOS bytes que los que tenía el paquete. No es un archivo roto: quien capturó puso un `snaplen` bajo a propósito. Pero el payload está incompleto, y una regla que busque texto en él podría no encontrarlo aunque estuviera en el cable (falso negativo).


**`_TapFile`**: Envuelve el archivo y "espía" las lecturas que hace dpkt. Por qué: dpkt descarta caplen/origlen y no avisa si el payload quedó corto. Pero para leer pide, en orden: read(24) cabecera global, y por cada paquete read(16) cabecera + read(caplen) payload. Mirando esas lecturas recuperamos lo que dpkt tira, con UN solo lector (nada que sincronizar). Supuesto frágil: depende de ese patrón de lecturas de dpkt. Los tests de caracterización avisan si una versión futura lo cambia.


**`_BlockTap`**: Espía las lecturas de dpkt en un pcapng para detectar un archivo cortado. Por qué: dpkt corta el recorrido en silencio si el archivo termina a mitad de un bloque (o con una cabecera incompleta) y no avisa. dpkt lee cada bloque en dos pasos —8 bytes de cabecera y luego el resto—, así que una lectura que devuelve menos de lo pedido, salvo un fin de archivo limpio justo entre bloques (0 bytes en la cabecera), indica truncado. Supuesto frágil, igual que en `_TapFile`: depende del patrón de lecturas de dpkt.


**`_open`**: Abre el archivo, detecta el formato y devuelve (info, reader, tap). Detectamos por magic number y no por extensión: un .pcap puede ser en realidad un pcapng (pasa seguido al exportar desde Wireshark). Cada formato trae su `tap` para detectar un archivo cortado.


**`iter_packets`**: Devuelve un Packet por cada paquete del archivo, de a uno. Cada paquete tiene su propia cabecera de 16 bytes (timestamp, largo capturado, largo original); dpkt la consume y el tap recupera origlen.


**`_truncated_detail`**: Motivo legible del truncado: dpkt a veces lanza NeedData SIN mensaje y el error terminaba en "captura truncada: " con el motivo vacío.


**`get_packet`**: Devuelve el paquete número `index` (0 = el primero). Usa un índice disperso de posiciones en el archivo (una cada 4096 paquetes, ~8 B c/u): salta al punto de reanudación más cercano y lee a lo sumo 4096 paquetes. El índice se arma sobre la marcha (o durante `analyze`), se guarda para los últimos 4 archivos y se descarta si cambia el tamaño o la fecha del archivo. Un archivo truncado sigue sirviendo los paquetes anteriores al corte. IndexError si no existe.

**`iter_indexed`**: Como `iter_packets` pero entrega `(índice, posición del siguiente paquete, Packet)` y puede arrancar en una posición guardada (los taps cuentan los bytes leídos). `iter_packets` es esta función sin los dos primeros datos.


### Notas del código

- `<módulo>`: Los primeros 4 bytes del archivo identifican el formato ("magic number"). pcapng siempre empieza con un "Section Header Block" (0x0A0D0D0A). Los pcap clásicos usan 0xA1B2C3D4 (o su variante en otro endianness).
- `<módulo>`: Magic de pcap clásico -> endianness de las cabeceras. Cubre microsegundos y nanosegundos. Las variantes "modificadas" (cabecera de 24 bytes) quedan fuera: dpkt las lee igual, pero no las inspeccionamos (origlen = None).
- `Packet`: Largo original en el cable. None si el formato no nos lo deja ver (pcapng con dpkt, o magic pcap no estándar).
- `iter_packets`: Lo escuchamos ANTES de entregarlo: un paquete cortado es dato corrupto y no debe llegar a las reglas.
- `iter_packets`: float(): con magic de nanosegundos dpkt entrega Decimal, y mezclar Decimal con float rompe las restas (duración de sesión).
- `CaptureInfo`: 1 = Ethernet. Dice cómo interpretar los bytes de cada paquete.
- `CaptureInfo`: máx. bytes guardados por paquete (pcapng no lo expone en dpkt)
- `_bounded_read`: cada lectura se limita a lo que queda del archivo; un largo de paquete falso (~4 GB) no reserva memoria y se informa como paquete truncado.

