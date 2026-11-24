# Documentación de `backend/domain/export`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## html_report.py

Informe de triaje en HTML: una sola página autocontenida, lista para adjuntar a un ticket.

Todo lo que viene del tráfico o del analista se ESCAPA (`html.escape`): la
evidencia de una alerta puede ser hostil. Sin scripts ni recursos externos (una
política CSP lo refuerza). Del archivo solo va el NOMBRE, nunca la ruta.


### Funciones y clases


**`build_ticket_text`**: Texto plano del bloque «Para el ticket» (SIN escapar: quien lo muestre en HTML debe pasarlo por `_e`).


### Notas del código

- `<módulo>`: además de las anotadas, con IOC o de las alertas, se listan las más pesadas
- `<módulo>`: líneas de la línea de tiempo del ticket (un ticket no es un volcado)
- `<módulo>`: alertas con su evidencia en el ticket (las de mayor severidad)


## json_export.py

Exportación del análisis a JSON.

Por qué un módulo aparte: el formato de salida es un CONTRATO con quien lo
consuma (otro analista, un SIEM, un script). Lo aislamos para poder versionarlo
(`schema_version`) y cambiarlo sin tocar el análisis.


### Funciones y clases


**`_file_name`**: Solo el nombre del archivo, sea cual sea el estilo de la ruta. PureWindowsPath entiende `\` y `/`; `Path` en Linux no separaría `C:\Users\x\cap.pcap` y el reporte filtraría la carpeta del usuario.


**`build_report`**: Arma el reporte como dict (listo para json.dumps). - `sessions`: si se pasa (p. ej. ya filtradas), se exportan esas y las estadísticas se calculan sobre ellas, para que el reporte sea coherente consigo mismo. Los ids siguen siendo los del análisis completo. - `source`: se guarda solo el NOMBRE del archivo. Un reporte se comparte, y la ruta completa filtraría el nombre de usuario y la estructura de carpetas. - `generated_at` se inyecta para poder testear sin depender del reloj.


### Notas del código

- `_session_dict`: Armado a mano (no asdict): así un campo interno que agreguemos después a Session no se filtra al archivo exportado sin que lo decidamos.
- `_stats_for`: Aunque las cifras sean de lo filtrado, la bandera de "análisis parcial" es de la CAPTURA: un reporte filtrado de una captura truncada no puede decir que el análisis fue completo (quien lo reciba creería que vio todo).
- `to_json`: allow_nan=False: NaN/Infinity no son JSON válido; preferimos un error claro a un archivo que otros parsers rechazan. ensure_ascii=False: la evidencia puede traer texto no ASCII legible.


## pcap_export.py

Guarda un subconjunto de paquetes (una sesión, o lo que coincide con un filtro) como un .pcap nuevo.

Sirve para llevarse SOLO la conversación que importa: abrirla en Wireshark o adjuntarla a un ticket
sin arrastrar toda la captura. Los paquetes se copian tal cual; lo único que no se conserva es el
"largo original" de un paquete recortado por snaplen (el formato que escribe dpkt no lo permite).

Topes: en memoria se arma el archivo entero, así que se limita (`MAX_PACKETS`, `MAX_BYTES`); si se
alcanza un tope el archivo sale COMPLETO HASTA AHÍ y se avisa (`truncated`), nunca en silencio.


### Notas del código

- `<módulo>`: dpkt no recorta con este valor: es solo lo que se declara en la cabecera global

## siem.py

Exportación de alertas a un SIEM. Lógica pura: recibe `Alert` y devuelve texto, una línea por alerta. Ninguna
línea lleva rutas ni nombres de archivo ni del equipo; la evidencia ya viene sin secretos (la contraseña de FTP
va como `<oculta>`).

| Formato (`format=`) | Salida | Archivo |
|---|---|---|
| `ecs` (defecto) | NDJSON de Elastic Common Schema 8.11, un documento por línea (`application/x-ndjson`) | `tracewell-alerts.ndjson` |
| `cef` | ArcSight CEF:0 (`text/plain`) | `tracewell-alerts.cef` |
| `syslog` | syslog RFC 5424 (facilidad local0) con el CEF dentro, HOSTNAME `-` (`text/plain`) | `tracewell-alerts.log` |

### ECS

Campos: `@timestamp` (UTC, ms, `Z`), `ecs.version`, `event.{kind: alert, category, type, severity, module:
tracewell, dataset: tracewell.alert}`, `message`, `rule.{id,name,description}`, `source.ip`, `destination.ip`
(y `destination.port` si la evidencia trae `destination_port` o `port`), `threat.framework`
(`MITRE ATT&CK`), `threat.tactic.{id,name,reference}` (listas; `TA0043`...), `threat.technique.{id,name,reference}`
(listas) y `threat.technique.subtechnique.*` cuando el ID es `T####.###` (el padre sale del nombre
«Padre: Hija»). Lo propio de Tracewell va en `tracewell.severity` y `tracewell.evidence`; `tags: [tracewell]`.
`event.severity` usa los puntajes de riesgo de Elastic: low 21, medium 47, high 73, critical 99.

### CEF y syslog

`CEF:0|Tracewell|Tracewell|<versión de la app>|<rule_id>|<nombre>|<severidad 0-10>|<extensión>`. Severidad CEF:
low 3, medium 5, high 8, critical 10. Extensión: `rt` (epoch ms), `src`, `dst`, `dpt`, `cat` (táctica), `msg`
(descripción), `cs1` táctica, `cs2` ID de técnica, `cs3` nombre de técnica, `cs4` severidad, `cs5` evidencia en
JSON compacto (truncada a 900 caracteres, con `...`). Se escapan `\`, `|` en la cabecera y `\`, `=` y saltos de
línea en la extensión, y se reemplazan los demás caracteres de control. Syslog: `<PRI>1 <ISO8601> - tracewell -
ALERT - CEF:0|...` con PRI = 16*8 + severidad syslog (low 6, medium 5, high 4, critical 2).

`render(alertas, formato, versión, min_severity)` es la fachada que usa la API; `media_info(formato)` da el tipo
de contenido y el nombre del archivo; `filter_min_severity` conserva las alertas desde esa severidad.
