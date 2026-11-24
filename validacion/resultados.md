# Resultados de validación (SINTÉTICO)

> SINTÉTICO: corpus generado por validacion/generar_corpus.py (semilla 20260101), diseñado por quien escribió las reglas. Estas cifras NO son precisión ni recall reales y no sustituyen la validación con tráfico real.

Pcaps analizados: 37 de 37.

## Métricas por regla

| Regla | TP | FP | FN | Precisión | Recall |
|---|---:|---:|---:|---:|---:|
| `beaconing` | 2 | 1 | 1 | 67% | 67% |
| `brute_force_remote` | 4 | 1 | 0 | 80% | 100% |
| `dga_nxdomain` | 0 | 0 | 0 | n/d | n/d |
| `dns_suspicious` | 3 | 2 | 0 | 60% | 100% |
| `dns_unusual_resolver` | 1 | 1 | 0 | 50% | 100% |
| `ftp_cleartext` | 3 | 0 | 0 | 100% | 100% |
| `host_sweep` | 2 | 0 | 0 | 100% | 100% |
| `icmp_tunnel` | 0 | 0 | 0 | n/d | n/d |
| `large_upload` | 1 | 1 | 0 | 50% | 100% |
| `malicious_ja4` | 0 | 0 | 0 | n/d | n/d |
| `port_scan` | 3 | 0 | 0 | 100% | 100% |
| `smb_rpc_lateral` | 0 | 0 | 0 | n/d | n/d |
| `suspicious_ports` | 2 | 0 | 0 | 100% | 100% |
| `syn_flood` | 1 | 0 | 0 | 100% | 100% |
| `tls_certificate` | 0 | 0 | 0 | n/d | n/d |
| `user_agent_scanner` | 0 | 0 | 0 | n/d | n/d |
| `user_agent_script` | 0 | 0 | 0 | n/d | n/d |
| **Total** | 22 | 6 | 1 | 79% | 96% |

## Detalle de fallos

- FN en `pos_beaconing_jitter` (pos_beaconing_jitter.pcap): `beaconing` (10.0.0.20 -> 104.21.45.12)
- FP en `ben_ssh_automatizado` (ben_ssh_automatizado.pcap): `brute_force_remote` (10.0.0.10 -> 10.0.0.5)
- FP en `ben_dns_label_largo` (ben_dns_label_largo.pcap): `dns_suspicious` (10.0.0.20 -> 10.0.0.1)
- FP en `ben_dns_hash_hex` (ben_dns_hash_hex.pcap): `dns_suspicious` (10.0.0.20 -> 10.0.0.1)
- FP en `ben_backup_nube` (ben_backup_nube.pcap): `large_upload` (10.0.0.20 -> 52.95.110.1)
- FP en `ben_monitoreo_periodico` (ben_monitoreo_periodico.pcap): `beaconing` (10.0.0.10 -> 10.0.0.20)
- FP en `ben_dns_proveedor` (ben_dns_proveedor.pcap): `dns_unusual_resolver` (10.0.0.20 -> 80.58.61.250)

## Hallazgos (causa probable)

Quedan 7 fallos del corpus sintético (6 falsos positivos y 1 falso negativo); son casos difíciles
que el corpus incluye a propósito. No dicen cuán frecuentes son en una red real, solo que cada uno
existe y se reproduce con el pcap citado.
(Esta sección se escribió a mano: `--salida` regenera solo lo de arriba.)

Etapa «menos ruido» (medida en este corpus, antes 68 % de precisión y 95 % de recall; ahora 79 % y 96 %).
Tres falsos positivos desaparecieron sin perder ningún positivo y se agregaron 4 casos (2 positivos y 2 benignos):

| Regla | Pcap | Qué se cambió |
|---|---|---|
| `syn_flood` | `ben_pico_visitas` | Ritmo mínimo `min_pps: 50`: 250 SYN en 8 s son ~31 por segundo, el flood sintético del corpus llega a ~100. |
| `port_scan` | `ben_login_dominio` | En la ventana corta solo cuentan los puertos que no respondieron SYN+ACK (antes solo en la larga). |
| `suspicious_ports` | `ben_servicio_9001` | El 9001 salió de la lista por defecto (Tor y servicios internos legítimos). |
| `host_sweep` (nueva) | `pos_barrido_vnc`, `pos_barrido_4444` | Un puerto probado en 20 o más equipos sin respuesta. `ben_muchos_sitios` (30 sitios que contestan) no alerta. |
| `suspicious_ports` | `pos_barrido_4444` | Un origen público da una alerta al tercer destino, no una por destino. |
| `beaconing` | `ben_latidos_protocolo` | Más de 3 pares con el mismo ritmo en un puerto se tratan como protocolo. |

Corregidos en esta etapa (eran falsos negativos; ahora son TP, sin nuevos falsos positivos):

| Regla | Pcap | Qué se cambió |
|---|---|---|
| `ftp_cleartext` | `pos_ftp_puerto_2121` | Detecta USER seguido de PASS en el mismo flujo en cualquier puerto TCP. En puertos fuera de `ports`, un PASS sin USER previo no alerta. POP3 (mismos comandos) se marca igual, con `protocol: POP3` si el servidor saludó con `+OK`. |
| `dns_suspicious` | `pos_dns_tunel_etiquetas_cortas` | Medida agregada sobre los subdominios sin el dominio registrable: >= 50 caracteres en 2 o más etiquetas y entropía >= 3,5. El conteo de subdominios únicos por dominio padre existe pero queda apagado (`min_unique_subdomains: 0`). |
| `port_scan` | `pos_escaneo_lento` | Segunda ventana de 900 s con umbral de 20 puertos; solo cuentan puertos que no respondieron SYN+ACK. |
| `brute_force_remote` | `pos_ssh_lento` | Segunda ventana de 300 s con umbral de 10 intentos. |

Compromisos medidos (corpus + pruebas unitarias): un monitoreo SSH cada 60 s da 5 intentos en 300 s
y no alerta, pero uno cada 30 s sí (10 en 300 s). Con 900 s la ventana larga de SSH habría
alertado a un chequeo cada 60 s (15 en 900 s), por eso se eligieron 300 s. En `port_scan`, un
cliente que usa 20 o más servicios distintos de un servidor sin que el servidor responda a todos
podría alertar; los puertos con SYN+ACK no cuentan, y 16 puertos de `ben_login_dominio` quedan bajo
el umbral de 20.

Falsos positivos (tráfico benigno que alerta; sin cambios):

| Regla | Pcap que lo reproduce | Causa probable |
|---|---|---|
| `brute_force_remote` | `ben_ssh_automatizado` | 14 conexiones SSH en 25 s de un script de administración (umbral 10 en 60 s). |
| `dns_suspicious` | `ben_dns_label_largo` | Etiqueta legible de 57 caracteres con guiones: solo cuenta la longitud (> 40). |
| `dns_suspicious` | `ben_dns_hash_hex` | Hash MD5 de 32 hex como etiqueta: entropía >= 3,5 con >= 20 caracteres. |
| `large_upload` | `ben_backup_nube` | Una copia de seguridad a un destino público es indistinguible de exfiltración por volumen. |
| `beaconing` | `ben_monitoreo_periodico` | Un agente de monitoreo cada 60 s es periódico por diseño; solo se ignoran puertos como 53/123. |
| `dns_unusual_resolver` | `ben_dns_proveedor` | El resolvedor del proveedor es público y no está en `allowed_resolvers`. |

Falso negativo que sigue abierto:

| Regla | Pcap que lo reproduce | Causa probable |
|---|---|---|
| `beaconing` | `pos_beaconing_jitter` | Variación del 35% supera `max_jitter` (0,15). |

Controles que pasaron: `ben_navegacion`, `ben_cdn_rafaga`, `ben_dns_normal` (incluye el ELB
ignorado y 8.8.8.8), `ben_backup_interno` (`external_only`), `ben_ssh_normal`, `ben_ntp_mdns_ssdp`.
Los 13 positivos "directos" (sin evasión) acertaron todos, incluidos los dos de beaconing y el ataque combinado.
