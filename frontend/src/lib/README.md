# Documentación de `frontend/src/lib`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## format.js

- `formatDuration`: Se compara el valor YA redondeado: 1023,99 KB se muestra "1024.0", y eso debe pasar a "1.00 MB" en vez de quedar en la unidad anterior.
- `formatTime`: Epoch en segundos -> "HH:MM:SS.mmm" en UTC. UTC a propósito: un analista que cruza capturas con logs de otros equipos necesita una hora sin ambigüedad.

## help.js

- `HELP`: Textos de ayuda en lenguaje simple. Cada tema explica QUÉ es lo que se ve, CÓMO leerlo y, cuando existe, y, cuando hace falta, CÓMO se relaciona con otras herramientas: el objetivo de Tracewell es que esto deje de dar miedo. Todo es texto plano (se muestra como texto, nunca como HTML).

## help.test.js

- `all`: Todas las pantallas y componentes: src/views y src/components/{captures,common,support}.
- `sources`: Solo cuentan los componentes que de verdad se usan (importados por App, main u otro componente): uno a medio hacer no rompe.
