# Documentación de `backend/domain/export/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## test_html_report.py

Tests de backend/domain/export/html_report.py: escape de datos hostiles, secciones y ausencia de rutas.


### Notas del código

- `test_ticket_un_dato_hostil_no_puede_fingir_lineas`: el dato queda dentro de UNA línea de evidencia: ninguna línea nueva empieza con el título falso

