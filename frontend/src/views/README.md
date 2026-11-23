# Documentación de `frontend/src/views`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## CapturesView.close.test.jsx

- `loadFile`: "recarga": una App nueva consulta al servidor, que ya no tiene captura

## CapturesView.jsx

- `App`: `section` elige qué tarjetas se ven («all» = todas, el uso de siempre; la barra lateral pasa una por vez). `onNavigate` cambia de sección (p. ej. desde una alerta a las sesiones), `onCapture` avisa qué captura hay cargada.
- `App`: Descarta el análisis (también en el servidor, para que recargar la página no lo traiga de vuelta) y vuelve al inicio.
- `App`: Filtra la tabla de sesiones por una IP (desde el gráfico de equipos o la tabla de HTTP) y baja hasta ella.
- `App`: Un análisis nuevo reemplaza al anterior: se limpian filtros y selección, que podrían apuntar a sesiones que ya no existen.
- `App`: Si el servidor ya tiene un análisis (p. ej. se recargó la página), lo retomamos. Un 409 significa "todavía no hay nada": es el caso normal.
- `App`: Barra inferior fija: así la captura en vivo no le quita espacio al análisis.

## CapturesView.triage.test.jsx

- `viewSessionsBtn`: El caso guiado del demo repite ese texto en su propio botón: se busca el de la tabla de alertas.

## SupportView.jsx

- `GROUPS`: Dos grupos: «Sistema» (qué corre en este equipo) y «Red» (pruebas de red). Solo se monta la sección elegida; cada una pide sus datos al abrirse.
- `SupportApp`: Soporte de red: herramientas de SOLO LECTURA sobre el equipo («Sistema») y la red («Red»). Con `group` y `section` (los elige la barra lateral de la aplicación) la pantalla es «controlada»: sin pestañas propias. Sin ellos (uso suelto) se maneja sola con pestañas.

## SupportView.test.jsx

- `mounts`: Cada sección se reemplaza por un componente mínimo que cuenta cuántas veces se montó y qué `active` recibió.
