# Documentación de `backend/domain/rules/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## test_brute_force.py

Tests del detector de fuerza bruta (SSH/RDP) y de la regla personalizada por umbral, con pcap sintéticos.


## test_engine_limits.py


### Notas del código

- `test_scan_par_evictado_de_alerted_puede_volver_a_alertar`: Costo asumido y documentado: si el par alertado sale del LRU de _alerted (mas de MAX_TRACKED pares alertados) se olvida y puede alertar de nuevo.


## test_extra_detectors.py

Tests de backend/domain/rules/extra_detectors.py: los 5 detectores nuevos y sus validadores (frames con dpkt).


### Notas del código

- `test_reglas_reales_cargan_y_mapean_a_detectores_conocidos`: "threshold" es la regla que arma el analista desde la interfaz: no tiene una regla propia en rules/.


## test_iocs_formats.py

IOC en CSV y STIX 2.1: detección de formato, columnas, patrones y los mismos errores del formato de texto.


## test_rule_guide_fields.py

Campos explicativos opcionales de las reglas YAML: false_positives, investigation_steps, wireshark_filter.

