# Documentación de `backend/api/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## conftest.py

Fixtures compartidas de los tests de la API.

La app solo acepta Host local (TrustedHostMiddleware), pero TestClient usa por
defecto el Host "testserver". Este fixture autouse cambia el base_url por
defecto a http://127.0.0.1; los tests de seguridad lo pisan explícitamente.


## test_allow_downloads.py

main._allow_downloads: pywebview cancela las descargas por defecto; se activan sin romper versiones viejas.


## test_api.py


### Notas del código

- `test_export_con_filtros`: `direction` es una clave extra de la API: el JSON exportado no la lleva (contrato schema_version 1)


## test_app_helpers.py


### Notas del código

- `test_lifespan_via_testclient_limpia_al_cerrar`: con TestClient como context manager, al salir se borra el pcap temporal de la captura en vivo


## test_desktop_entry.py


### Notas del código

- `test_parse_args_puerto_invalido_sin_traceback`: fuera de rango / no numérico -> SystemExit(2) de argparse y el mensaje menciona el puerto
- `test_pick_file_sin_bind_falla_con_attributeerror`: sin bind(), _window es None: pick_file lanza AttributeError (comportamiento real, no controlado)
- `test_self_test_destruye_aunque_probe_explote`: try/except/finally: si la sonda explota, la ventana se destruye igual, ok queda False y error trae el mensaje
- `test_main_fallo_generico_de_ventana`: cualquier excepción al abrir la ventana: mensaje con --serve-only, 1, sin traceback, stop() igual


## test_error_policy.py


### Notas del código

- `test_fallo_de_arranque_cierra_socket_y_propaga`: si _launch / _wait_ready fallan, el socket real queda cerrado (fileno -1) y la excepción se propaga


## test_insights_api.py


### Funciones y clases


**`test_el_secreto_de_la_url_solo_aparece_como_parte_del_target`**: El valor del token viaja dentro de la URL pedida (es el pedido literal); los campos sensibles solo traen NOMBRES.


**`test_tls_con_el_origen_invertido`**: Captura iniciada a mitad: el primer paquete visto es del servidor, asi que el 'origen' es el servidor.


## test_live_api.py


### Notas del código

- `test_status_idle_no_falla_y_start_trae_la_clave`: idle sin captura: clave presente o ausente, pero nunca un error


## test_security.py


### Notas del código

- `test_origin_con_backslash_y_host_local_se_permite`: urlparse toma "evil.com\" como userinfo. Un navegador nunca serializa así un Origin (siempre es canónico), por eso no es explotable: se documenta.


## test_server.py

Servidor local en hilo (backend/api/server.py): puerto, loopback, ciclo de vida y errores de arranque.


## test_support_api.py

API de «Soporte de red → Red»: solo lectura; las funciones que salen a la red o a comandos se reemplazan por falsos.


### Funciones y clases


**`test_validacion_del_core_es_422`**: Sin falsos: valid_host / servidor de hora no permitido salen como 422 con el motivo, y sin tocar la red.


### Notas del código

- `test_monitor_get_a_post_es_405`: app mínima solo con el router: la app completa monta el frontend en «/» y esa montura tapa el 405 con un 404


## test_system_api.py

API de «Soporte de red → Sistema»: solo lectura, sin captura, con psutil falso (y un humo real al final).

