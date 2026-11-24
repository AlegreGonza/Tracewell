# Cambios

## 0.5.0

- **Mínimo privilegio en archivos:** por defecto solo se leen archivos de Descargas (ya no Documentos ni
  Escritorio enteros). El diálogo nativo «Examinar…» autoriza solo el archivo elegido. `/api/iocs` exige
  `.txt`, `.csv`, `.json`, `.stix` o `.ioc`. Para otras carpetas: `TRACEWELL_ALLOWED_DIRS`.
- **Captura sin privilegios en Linux:** usa `dumpcap` (con permiso solo para un grupo) y deja la API sin root;
  Scapy sigue de respaldo y en Windows.
- **Reglas con menos ruido:** `host_sweep` (regla nueva), `suspicious_ports` agrupa por origen, `port_scan`
  ignora puertos que respondieron, `syn_flood` con ritmo mínimo, `beaconing` ignora latidos de protocolos y
  `dns_suspicious` no marca consultas SRV de Active Directory. En el corpus sintético: precisión 68 % → 79 %.
- **Arreglos:** Servicios de Windows sin nombre ya no rompen la pantalla; las rutas largas se parten en las
  tablas de Sistema.
- **Seguridad:** bandit limpio, pruebas hostiles del constructor de reglas y anti-ReDoS de patrones STIX.

## 0.4.0

Interfaz nueva (shadcn-admin), exportes SIEM y reglas MITRE.
