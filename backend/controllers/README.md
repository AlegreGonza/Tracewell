# Documentación de `backend/controllers`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## analysis.py

Controlador de «analysis»: la lógica que las rutas HTTP de `api/routes/analysis.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones.


### Funciones y clases


**`_session_item`**: Sesión serializada. La clave `process` solo existe si hay datos de procesos (captura en vivo): su ausencia significa "no aplica", y `null`, "no identificado".


**`_alert_item`**: Alerta serializada para la API. `wireshark_filter` y `guide` son claves EXTRA (no están en el JSON exportado). El filtro se omite si las IP de la alerta no son válidas, en vez de romper la lista entera.


### Notas del código

- `_session_item`: nombre del sitio (SNI o DNS de la propia captura); ausente si no se conoce


## insights.py

Controlador de «insights»: la lógica que las rutas HTTP de `api/routes/insights.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones.


## live.py

Controlador de «live»: la lógica que las rutas HTTP de `api/routes/live.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones.


### Funciones y clases


**`_finish_sampler`**: Detiene el muestreador y devuelve lo observado, o None si no hay datos (sin muestreador, o ninguna muestra salió bien: mejor no ofrecer una columna vacía).


### Notas del código

- `_release_previous`: La captura anterior ya terminó: si dejó una carpeta temporal y el análisis actual no depende de ella, se borra (si no, se acumulan).


## rules.py

Controlador de «rules»: panel de reglas (vista previa, guardado y listado). Sin FastAPI de por medio.


### Funciones y clases


**`preview_rule`**: YAML en vivo y, si hay una captura abierta, cuántas sesiones y alertas daría la regla (sin guardarla).


### Notas del código

- `list_rules`: la lista de reglas (`ctx.rules`) se lee del disco UNA vez, al crear la app, y se le suman las que se guardan desde el panel. Una regla borrada o editada a mano en `rules/` sigue activa y visible en `GET /api/rules` hasta reiniciar la aplicación (diseño intencional: no se vuelve a leer la carpeta en cada consulta).


## state.py

Estado compartido de la API y contexto que reciben las rutas.

Una app de escritorio tiene un solo usuario y una captura abierta a la vez,
así que guardamos UN análisis actual en memoria (`_State`). Las rutas lo
alcanzan por inyección de dependencias (`Ctx`), no por globales: cada
`create_app` tiene el suyo y los tests no se pisan entre sí.


### Funciones y clases


**`_session_id`**: Id de una sesión del análisis. Toda sesión que sale de `group_packets` tiene clave, así que un None acá es un bug de core: mejor un error claro que un id `null` en la respuesta.


**`summary`**: Resumen de un análisis para las respuestas de analyze/demo/capture. `processes`: si hay datos de procesos (solo captura en vivo): la interfaz muestra la columna.


**`clear_analysis`**: Vuelve al estado inicial (sin captura cargada). Si el análisis era de una captura en vivo, borra su carpeta temporal. Las notas, los procesos y la selección dependían de ese análisis; la lista de IOC no: sobrevive, igual que al cambiar de captura.


**`set_analysis`**: Reemplaza el análisis actual. `owned_dir` es una carpeta temporal que creamos nosotros y de la que depende el análisis (el pcap de una captura en vivo); se borra cuando el análisis se reemplaza, no antes: el detalle de paquetes relee ese archivo. `processes` (solo captura en vivo) se reemplaza junto con el análisis: los de un archivo nunca los tienen.


### Notas del código

- `_State.__init__`: procesos observados del análisis actual (solo captura en vivo)
- `_State.__init__`: notas del analista por id de sesión; valen para el análisis actual
- `set_analysis`: los ids de sesión cambian con cada análisis: las notas viejas apuntarían a otra cosa


## triage.py

Controlador de «triage»: la lógica que las rutas HTTP de `api/routes/triage.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones.


### Funciones y clases


**`_matched_ips`**: IP de las sesiones que coinciden con la lista. Cada IP distinta se compara UNA vez: con miles de sesiones repiten las mismas pocas IP.

