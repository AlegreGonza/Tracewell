# Documentación de `frontend/src/controllers`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## useAction.js

- `useAction`: Ejecuta una acción a pedido (un botón), no al abrir la pantalla: guarda el resultado, el error y si está trabajando. Si se vuelve a ejecutar mientras la anterior sigue, descarta la vieja; al desmontar, cancela lo pendiente.

## useLoad.js

- `useLoad`: Carga datos con `fetcher(signal)` al montar y cada vez que se llama a `reload()`. Si `every` (ms) viene y `active` es true, recarga sola cada tanto (sin tapar la pantalla con «cargando»).

## usePalette.js

- `read`: El almacenamiento del navegador puede fallar (ventana privada, bloqueado): siempre se cae a la paleta por defecto.
- `usePalette`: Paleta de color elegida: se recuerda entre sesiones y se aplica como data-palette en <html> (ver tokens.css).
