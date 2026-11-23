# Documentación de `backend/domain/system`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## __init__.py

Mirada de SOLO LECTURA al sistema donde corre Tracewell (procesos, puertos, memoria, servicios, inicio).

Nada de este paquete modifica el sistema: no termina procesos, no cambia configuración, no escribe en el registro.
Todo sale de `psutil` (import perezoso y opcional) y, para unos pocos datos de Windows, de lecturas del registro
o de un único comando de consulta.


## common.py

Utilidades compartidas del paquete: acceso perezoso a psutil, lecturas tolerantes y pistas sobre rutas.


### Funciones y clases


**`safe`**: Ejecuta una lectura que puede fallar por permisos o porque el proceso ya terminó (AccessDenied, NoSuchProcess, OSError…): devuelve `default` en vez de romper. Un dato que falta es normal, no un error.


**`path_hints`**: Pistas (no veredictos) sobre dónde vive un programa. Cada una trae un texto que dice por qué mirarla.


### Notas del código

- `<módulo>`: Procesos propios de Windows y la carpeta donde viven de verdad: el mismo nombre en otro lado es la forma más común de disfrazar un programa ajeno.


## net.py


### Funciones y clases


**`_inet_connections`**: Sockets del sistema, o None si el sistema no deja listarlos (p. ej. macOS sin permisos de administrador).


## procs.py

Procesos: lista con memoria y procesador, detalle de uno, y la huella y firma de su archivo.

Cada lectura se hace con tolerancia a fallos: sin permisos de administrador algunos procesos (del sistema o de otros
usuarios) no dejan ver todo, y eso se muestra como «—», no como un error. NUNCA se modifica ni se termina un proceso.


### Funciones y clases


**`process_detail`**: Todo lo legible de UN proceso. Diccionario vacío si no existe. Lo que el sistema no deja ver va en null.


**`file_info`**: SHA-256 y firma digital del programa de un proceso. La ruta sale del PROPIO sistema, nunca del usuario.


**`file_signature`**: Firma digital (solo Windows). Consulta con un único comando de lectura; la ruta viaja en una variable de entorno, no dentro del texto del comando, así un nombre de archivo raro no puede inyectar nada.

