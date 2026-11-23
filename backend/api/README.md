# Documentación de `backend/api`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## app.py

API HTTP de Tracewell.

REGLA: este módulo solo ORQUESTA. Arma la app (reglas, contexto, ciclo de
vida, seguridad, errores, rutas, frontend); las rutas viven en `routes_*`, el
estado y casos de uso en `controllers`, y el análisis en `domain`. Si alguna vez te tienta poner
lógica de análisis acá, va en `domain`.


### Funciones y clases


**`_mount_frontend`**: Sirve el frontend compilado. Va al final: así "/" no tapa a /api. Si todavía no se compiló el frontend (Paso 8), la API funciona igual.


**`create_app`**: Fábrica de la app. Las dependencias externas (carpetas, fuente de captura, listado de interfaces, muestreo de procesos) se inyectan: así los tests no tocan la red real ni los archivos del usuario. `sampler_factory` en None desactiva la columna Proceso.


### Notas del código

- `create_app`: Se resuelve al llamar (no al crear): así `backend.api.app.analyze` sigue siendo parcheable.
- `_shutdown`: el monitoreo de cortes es un hilo de fondo: no debe sobrevivir al cierre


## errors.py


### Funciones y clases


**`_unexpected_handler`**: Red de seguridad: un fallo imprevisto responde JSON genérico (igual que el resto de la API) y el detalle va solo al log del servidor. El mensaje de `exc` NO se devuelve: podría traer rutas del usuario o datos internos.


## security.py


### Funciones y clases


**`install_local_only`**: Instala los chequeos de Host y de Origin. La API puede leer rutas locales (/api/analyze) y escuchar en localhost, y CUALQUIER página que el usuario abra en su navegador puede intentar pegarle a localhost (CSRF) o resolver su propio dominio a 127.0.0.1 (DNS rebinding). Dos defensas baratas: 1. Host: solo nombres locales (frena el DNS rebinding, que llega con el Host del dominio atacante). 2. Origin: si el navegador manda uno, debe ser local (frena el CSRF). Sin Origin (curl, TestClient, la propia app al navegar) se permite.


## server.py

Arranca la API en un hilo, en un puerto libre de esta misma máquina.

Por qué existe: la ventana de escritorio necesita la API corriendo en segundo
plano y poder pararla al cerrarse, sin bloquear la ventana. Esto es lo único
que sabe "levantar" la API; `main.py` solo lo usa y abre la ventana.

Dos decisiones de seguridad y robustez:
- Escucha SOLO en 127.0.0.1. La API puede leer archivos locales (`/api/analyze`):
  exponerla a la red sería regalar la lectura de archivos de la máquina.
- El puerto lo elige el sistema operativo (puerto 0) y el socket se entrega ya
  abierto a uvicorn: así no hay una "carrera" entre buscar un puerto libre y
  que otro proceso lo tome antes de que lo usemos.


### Funciones y clases


**`start_in_thread`**: Levanta la API en un hilo y devuelve cuando ya responde. `app_kwargs` se pasan a `create_app` (carpetas, fuente de captura...). Los hilos de uvicorn no instalan manejadores de señales: la señal la maneja el programa principal.


### Notas del código

- `start_in_thread`: La app se arma ANTES de abrir el socket: si las reglas están mal, no queda un socket abierto.

