# Documentación de `backend/domain/pcap/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## test_layers.py

Tests de backend/domain/pcap/layers.py: disección capa por capa (paquetes armados con dpkt/bytes, sin red).


## test_live.py


### Notas del código

- `_timeout`: el default de _wait_started se fijó al definir la función: parchear la constante del módulo no lo cambia, hay que parchear __defaults__
- `test_scapy_excepcion_no_exception_se_traduce`: .exception con un objeto que no es excepción: 'raise' falla con TypeError, que se traduce igual a CaptureError (no se cuelga ni escapa un TypeError)
- `test_scapy_sniffer_sin_atributo_exception_se_traduce`: Un AsyncSniffer sin .exception/.thread (versión rara): AttributeError -> CaptureError claro
- `test_live_capture_propaga_permission_denied_y_permite_reintento`: start() NO borra la carpeta: lo hace cleanup() (la ruta de la API)


## test_live_errors.py

Errores en backend.domain.pcap.live: sniffer que falla, cierre del pcap con OSError, hilo del sniffer, logging.


### Notas del código

- `test_core_y_api_no_configuran_handlers_en_tracewell`: tras importar core y api, el logger "tracewell" no tiene handlers (a lo sumo NullHandler)


## test_live_stale_cleanup.py


### Notas del código

- `test_max_age_no_finito_lanza_valueerror_y_no_borra`: nan/inf/-inf -> ValueError que menciona max_age, y no se borra ninguna carpeta (vieja ni reciente)
- `test_capturas_de_livecapture_son_limpiables`: LiveCapture sin out_path crea tracewell_* en la raíz temporal; envejecida y con live.pcap se borra


## test_processes.py

Tests de backend/domain/pcap/processes.py: todo con psutil y proveedor FALSOS (nada del sistema real).


## test_reader.py


### Notas del código

- `test_payload_truncado_lanza_pcaperror`: Antes dpkt entregaba un buffer corto sin avisar (dato corrupto hacia las reglas). Ahora el reader lo detecta con el tap y lanza PcapError ANTES de entregar ese paquete; los anteriores si salen.
- `test_iter_packets_es_perezoso`: no abrio nada hasta el primer next(): una ruta inexistente no falla al crear el generador
- `test_pcapng_truncado_caracterizacion`: Se observa el comportamiento real al cortar un pcapng en distintos puntos. El contrato deseado: o PcapError o una lectura parcial; nunca otra excepcion.
- `test_snaplen_limitado_no_es_error`: Paquete con origlen (100) > caplen (4) en la cabecera: captura con snaplen bajo. Debe leerse sin error y marcarse snaplen_limited; el otro, normal.
- `test_ts_es_float_con_magic_nanosegundos`: Regresion: con magic de nanosegundos dpkt entrega Decimal; Packet.ts debe ser float exacto (no Decimal) o las restas de duracion de sesion rompen.
- `test_pcap_magic_modificado_origlen_none`: Magic 0xa1b2cd34 (cabecera de paquete de 24 bytes): dpkt lo lee, el tap no lo inspecciona -> origlen None, sin error ni snaplen_limited.
- `test_caracterizacion_patron_de_lecturas_de_dpkt`: Si dpkt cambia su patron (read(24); luego read(16)+read(caplen) por paquete), este test falla y avisa que el tap dejo de ser confiable.

