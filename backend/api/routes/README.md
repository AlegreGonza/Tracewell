# Documentación de `backend/api/routes`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## analysis.py

Rutas de análisis: cargar una captura y consultarla (sesiones, alertas, paquetes, export).

Cada ruta solo traduce HTTP <-> `core`; el estado y las dependencias llegan por `Ctx`.


### Funciones y clases


**`close_capture`**: Descarta el análisis actual (volver a la pantalla de inicio). Es idempotente: sin análisis tampoco falla.


### Notas del código

- `export`: Por defecto el reporte NO lleva procesos: se comparte, y los nombres de programas son datos del equipo.


## insights.py

Rutas de "entender la captura": equipos y grafo, tabla de DNS, explicación de una sesión, HTTP y archivos.

Son vistas de LECTURA sobre el análisis actual; el cálculo vive en `core`.


### Funciones y clases


**`case_timeline`**: Alertas, DNS sospechoso, sesiones marcadas e IOC en orden cronológico (opcional: solo los de una IP). Es una vista NUEVA: no reemplaza a `/api/timeline` (paquetes por intervalo).


**`http_file`**: Descarga el cuerpo (archivo) de un intercambio HTTP como `.bin`. Son datos de la red: pueden ser malware.


**`tls_of_session`**: Lo que se sabe de una sesión TLS sin descifrarla: huella JA4, versión y certificado (si va en claro).


### Notas del código

- `tls_of_session`: El «origen» puede estar invertido (captura iniciada a mitad): el cliente es quien manda el ClientHello.


## live.py


### Funciones y clases


**`_start_sampler`**: Arranca el muestreador de procesos si hay uno disponible. Es una función OPCIONAL: cualquier fallo se registra y la captura sigue sin la columna Proceso.


### Notas del código

- `_make_capture`: Un nombre único por captura: con un nombre fijo, una captura nueva pisaría el pcap del que todavía depende el análisis previo. uuid4 y no time_ns: en Windows el reloj puede repetir el valor.
- `live_stop`: Idempotente de verdad: la primera llamada detiene y analiza; las siguientes devuelven el MISMO resultado sin reanalizar y, sobre todo, sin pisar el análisis que el usuario pudo haber abierto después.
- `live_start`: un muestreador que quedó de una captura anterior no debe seguir corriendo


## support.py

Rutas de «Soporte de red → Red»: pruebas y consultas de red de SOLO LECTURA.

Ninguna cambia la configuración del equipo. Las pruebas que salen a la red las pide la persona a propósito (cada
pantalla dice a quién se contacta). Lo único con estado es el monitoreo de cortes, que arranca y para un hilo de
medición en memoria. El cálculo vive en `backend.domain.support`.


## system.py

Rutas de «Soporte de red → Sistema»: procesos, puertos, conexiones, servicios y programas de inicio.

TODAS son de LECTURA (GET): ninguna modifica ni termina nada en el equipo. El cálculo vive en `backend.domain.system`.
No dependen de que haya una captura cargada.


### Funciones y clases


**`_no_store`**: Lo que se ve del sistema cambia a cada segundo: que el navegador nunca reutilice una respuesta vieja.

