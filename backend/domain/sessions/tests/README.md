# Documentación de `backend/domain/sessions/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## test_grouper.py


### Notas del código

- `test_bytes_aleatorios_no_escapa_excepcion`: Caracterizacion: bytes basura de largo >= 14 se clasifican como non_ip o malformed (nunca excepcion). Semilla fija para que sea reproducible.
- `test_bytes_aleatorios_forzando_ip_no_escapa_excepcion`: Cabecera Ethernet valida (IPv4/IPv6) + cuerpo aleatorio: fuerza a dpkt a intentar parsear IP/TCP/UDP sobre basura. Solo se tolera UnpackError.
- `test_ipv6_esp_no_revienta_y_da_ip_50`: Regresion: IPv6 con nxt=50 (ESP) hacia que dpkt no seteara ip.p y _endpoints lanzara AttributeError. Ahora se usa ip.nxt: sesion "IP-50" (protocolo sin puertos conocidos) y puertos None.
- `test_ipv6_cabecera_extension_hop_by_hop_tcp`: IPv6 nxt=0 (hop-by-hop) -> TCP: el protocolo debe ser el del payload (TCP), no el de la cabecera de extension, y los puertos deben leerse bien.

