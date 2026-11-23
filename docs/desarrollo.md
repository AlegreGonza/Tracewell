# Desarrollo: linter, finales de línea y cabeceras de seguridad

## Linter (ruff)

Solo se activan las reglas de pyflakes (`F`: imports sin usar, nombres sin definir...). No reformatea nada.
La configuración está en `pyproject.toml` (`[tool.ruff]`) y `ruff` viene en `requirements-dev.txt`.

```
python -m ruff check backend main.py
```

No hay integración continua (`.github/`) en el repositorio, por eso el comando se corre a mano antes de
entregar. Si se agrega CI, basta un paso con ese mismo comando.

## Finales de línea

`.gitattributes` define `* text=auto`: Git decide qué es texto, guarda LF en el repositorio y deja que
`core.autocrlf` (Windows: `true`) ponga CRLF al descargar. Los `.sh` son siempre LF (`eol=lf`) y los
binarios (`.pcap`, `.pcapng`, imágenes) no se tocan.

Estado heredado: hoy el índice mezcla archivos con CRLF (la mayoría) y con LF. Eso NO se corrige en masa. Al
editar un archivo se conserva el final de línea que ya tiene. Si algún día se quiere unificar, el
comando es `git add --renormalize .` en una confirmación aparte (convertiría a LF los archivos que
hoy están con CRLF en el índice; mide antes con un índice temporal, sin tocar el real).

## Cabeceras de seguridad

`backend/api/security.py` agrega a TODA respuesta (API, estáticos y rechazos 400/403/500) una CSP
(`default-src 'self'`, scripts solo propios, `style-src 'unsafe-inline'` porque Mantine pone estilos en línea,
`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y
`Referrer-Policy: no-referrer`. Si la interfaz necesita cargar algo de otro origen, se agrega ahí y se
prueba en un navegador real (los tests no ven los errores de CSP).

El Host admitido incluye `[::1]` (con o sin puerto); cualquier otro (`evil.com`) sigue dando 400.
