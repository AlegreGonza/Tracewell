# Documentación de `frontend/src/api`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## client.js

- `<archivo>`: Cliente de la API. Un único lugar que conoce las URLs y cómo se traducen los errores: los componentes nunca llaman a fetch directamente.
- `normalizeDetail`: FastAPI responde `detail` como texto (nuestros errores) o como lista (errores de validación de parámetros). Lo normalizamos a un solo texto legible.
- `buildQuery`: Arma "?a=1&b=2" omitiendo valores vacíos (null, undefined, ""), así un filtro sin usar no viaja como "ip=" (que el servidor rechazaría por inválido).
- `api`: Entender la captura: equipos y grafo, DNS, HTTP, y la explicación en palabras simples de una sesión.
- `api`: Descargas de .pcap: SOLO los paquetes de una sesión, o de las sesiones que cumplen los filtros.
- `api`: Soporte de red → Red: pruebas de solo lectura. Las que salen a la red las pide la persona a propósito.
