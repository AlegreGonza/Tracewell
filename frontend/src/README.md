# Documentación de `frontend/src`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## App.jsx

- `CAPTURE_SECTIONS`: Secciones de «Capturas» en la barra lateral: cada una muestra solo sus tarjetas (antes era una página larguísima).
- `App`: Marco de la aplicación: cabecera + barra lateral + contenido. «Capturas» y «Soporte de red» quedan montadas una vez abiertas (solo se ocultan), así cambiar de una a otra no pierde el análisis cargado ni lo que se estaba mirando.
- `App`: resumen de la captura cargada, para la cabecera y las insignias

## App.test.jsx

- `log`: Las dos pantallas se reemplazan por componentes mínimos que registran sus props y cuántas veces se montaron.
- `item`: El nombre accesible de un item puede llevar al final la insignia numérica (p. ej. «Alertas y ATT&CK3»).

## main.jsx

- `Root`: Raíz: elige la paleta de color (se recuerda) y arma el tema de Mantine; el modo claro/oscuro lo maneja Mantine ("auto" = el del sistema).

## theme.js

- `SCALES`: Escalas de acento de cada paleta (10 tonos). El tono 6 (claro) y el 4 (oscuro) son los mismos del acento de tokens.css.
- `buildTheme`: Tema de Mantine con la paleta elegida. Las superficies siguen las variables de tokens.css (ver styles.css).
