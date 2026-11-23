# Documentación de `frontend/src/test`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## setup.js

- `<archivo>`: Todos los tests renderizan dentro del MantineProvider, como en la aplicación real (sin él, cualquier componente de Mantine falla), sin tener que cambiar cada test.
