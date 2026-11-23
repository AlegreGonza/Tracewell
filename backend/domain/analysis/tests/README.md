# Documentación de `backend/domain/analysis/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## convo.py


### Funciones y clases


**`conversation`**: turns: [('c'|'s', bytes), ...] en orden. Devuelve [bytes de frame]. Los datos se parten en segmentos de `mss`.


## test_case_timeline.py

Cronología del caso: unión de alertas, DNS sospechoso, sesiones marcadas e IOC, en orden cronológico.


## test_direction.py


### Notas del código

- `test_los_rangos_de_documentacion_cuentan_como_privados`: Python trata 203.0.113.0/24 (TEST-NET) como no enrutable: la vista de equipos hace lo mismo
- `test_origen_invertido_por_captura_a_mitad_de_conversacion`: el primer paquete visto es la RESPUESTA del servidor: la dirección sigue siendo cliente -> servidor


## test_dns_log.py

Tests de backend/domain/analysis/dns_log.py y de NameBook.dns_log (relleno desde paquetes UDP con puerto 53).


## test_host_roles.py

Perfil de host: roles inferidos solo de lo observado (cliente DNS, servidor web, emisor de escaneos, top talker).


## test_hosts.py


### Funciones y clases


**`test_sesion_invertida_no_etiqueta_al_cliente`**: Captura a mitad: el 'origen' es el servidor 443. El nombre y el servicio van a SU lado, no al cliente.


### Notas del código

- `test_nombre_de_respaldo_por_dns_de_la_ip`: best_name(s) usa DNS del destino: ambos puertos altos y ambos internos -> destino es servidor


## test_http.py

Tests de backend/domain/analysis/http.py: HTTP/1.x en claro, archivos y secretos (bytes armados a mano).


## test_mac_groups.py


### Notas del código

- `test_origen_invertido_cada_mac_sigue_a_su_ip`: el primer paquete visto es la respuesta del servidor: la MAC de origen es la del servidor


## test_names.py

Tests de backend/domain/analysis/names.py: nombres de sitio desde DNS y SNI (paquetes armados con dpkt/bytes, sin red).


## test_stream.py

Tests de backend/domain/analysis/stream.py (follow stream) y analyzer.session_stream. Paquetes armados con dpkt.


## test_tls.py

Tests de backend/domain/analysis/tls.py: ClientHello/JA4, ServerHello, certificados X.509 y analyze_tls.


### Notas del código

- `test_client_hello_truncado_en_las_extensiones_es_incompleto`: cortamos el registro justo dentro del bloque de extensiones y ajustamos el largo del registro

