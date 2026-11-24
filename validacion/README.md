# Validación de la detección

Mide cuántos aciertos y errores dan las reglas de `rules/*.yaml` sobre pcaps con **verdad terreno**
(alertas que un analista espera ver). El motor se ejecuta tal cual: `backend.domain.analysis.analyzer.analyze`.
No modifica código de producción.

## Contenido

| Archivo | Para qué |
|---|---|
| `validar.py` | CLI: analiza cada pcap del manifiesto, compara y escribe un informe Markdown. |
| `generar_corpus.py` | Genera el corpus **sintético** (pcaps + `manifiesto_sintetico.yaml`) con semilla fija. |
| `manifiesto_sintetico.yaml` | Verdad terreno del corpus sintético (lo escribe el generador). |
| `resultados.md` | Último resultado sobre el corpus sintético, marcado como tal. |
| `volumen.py` | CLI para un pcap SIN etiquetas (por ejemplo MAWI): alertas por minuto, por regla y por origen. Sirve como guardia de ruido: `python validacion\volumen.py captura.pcap`. |
| `tests/` | Tests del arnés (`python -m pytest -q -p no:cacheprovider validacion`). |
| `corpus/` | Pcaps generados (~30 MB, ignorados por git: se regeneran). |

## Método

1. Cada pcap tiene una lista de alertas **esperadas**: regla, IP origen y IP destino (las IP son opcionales
   y actúan como comodín). Tráfico benigno: `esperadas: ninguna`.
2. Se analiza el pcap con todas las reglas de `rules/` (o de `--reglas`).
3. Las alertas obtenidas se agrupan por (regla, origen, destino) dentro del pcap: 40 consultas DNS
   sospechosas del mismo equipo cuentan como **una** detección.
4. Cada esperada consume como máximo una obtenida. El resultado, por regla:
   - **TP** (verdadero positivo): esperada y obtenida.
   - **FP** (falso positivo): obtenida que no estaba esperada (incluye toda alerta en tráfico benigno).
   - **FN** (falso negativo): esperada que no se obtuvo.
   - **Precisión** = TP / (TP + FP). **Recall** = TP / (TP + FN). Se muestra `n/d` si el divisor es 0.
5. Se imprime la tabla por regla y el detalle de cada FP/FN con el pcap que lo reproduce.
   Un pcap que no se puede leer se informa como ERROR y no tumba la corrida.

No hay TN por regla: en tráfico real "no alertar" no es contable, por eso no se calcula especificidad.

## Uso

```powershell
# Corpus sintético (genera, luego valida)
python validacion\generar_corpus.py            # --sin-grandes omite los 3 pcaps de ~10 MB
python validacion\validar.py validacion\manifiesto_sintetico.yaml

# Opciones: --reglas <carpeta> --salida informe.md --titulo "..." --nota "..."
#           --etiqueta benigno|positivo|evasion|dificil   --omitir-faltantes
```

## Formato del manifiesto

```yaml
version: 1
pcaps:
  - id: mi_captura_01                # único
    ruta: D:/datos-externos/a.pcap   # absoluta, o relativa a la carpeta del manifiesto
    descripcion: PortScan de CIC-IDS2017, miércoles 10:00-10:30
    etiquetas: [positivo]            # libres; el filtro --etiqueta las usa
    esperadas:
      - {regla: port_scan, origen: 172.16.0.1, destino: 192.168.10.50}
      - {regla: brute_force_remote, origen: 172.16.0.1}   # destino = cualquiera
  - id: trafico_oficina
    ruta: D:/datos-externos/oficina.pcap
    esperadas: ninguna               # tráfico benigno: cualquier alerta es FP
```

Las reglas desconocidas, claves extra e ids repetidos se rechazan al cargar. Los pcaps pueden estar
**fuera del repo**: solo hace falta una ruta válida.

## Agregar un pcap real

1. Guardalo fuera del repo (ver la advertencia de abajo) y anotá su hash SHA-256.
2. Construí la verdad terreno **antes** de mirar qué alerta Tracewell: con el origen de la captura
   (etiquetas del dataset, guion del laboratorio o revisión manual con Wireshark). Si miras primero las
   alertas, el resultado queda sesgado a favor de las reglas.
3. Agregá la entrada al manifiesto (copia de `manifiesto_sintetico.yaml` fuera del repo).
4. Corré `validar.py` y revisá cada FP/FN abriendo el pcap: a veces el error está en la verdad terreno.

## Advertencia: pcaps de malware = datos NO confiables

Los pcaps de malware o de ataques reales pueden contener cargas útiles, URL, binarios y nombres que
dañan a quien los abre o los interpreta.

- Guardarlos en una carpeta **aparte y fuera del repo** (nunca versionarlos ni subirlos).
- **Nunca ejecutar** nada extraído de ellos; no abrir archivos exportados con doble clic.
- Analizarlos en una VM o sandbox sin red hacia la LAN y con instantáneas, no en la máquina de trabajo.
- Tracewell solo lee los paquetes (no los reproduce ni los ejecuta), pero un visor, otra herramienta o
  un navegador sí podrían exponerte: ante la duda, VM.
- No publiques informes que incluyan IP o dominios de terceros sin revisar.

## Corpus sintético: qué es y qué NO es

`generar_corpus.py` crea 33 pcaps con `dpkt` y `random.Random(f"{semilla}:{id}")` (semilla 20260101):
salida byte a byte repetible. Reutiliza los constructores de paquetes de `samples/generate_demo.py`.

- 18 positivos (al menos uno por regla; 5 son **evasiones** realistas: escaneo lento, SSH lento,
  jitter, túnel DNS con etiquetas cortas y FTP en puerto no estándar).
- 15 benignos, 11 de ellos "difíciles": pico de visitas, script de administración por SSH,
  inicio de sesión de dominio, copia de seguridad a la nube, monitoreo periódico, NTP/mDNS, etc.
- 3 pcaps de ~10 MB (subidas grandes): `--sin-grandes` los omite; el manifiesto los lista igual,
  usá `--omitir-faltantes` para saltarlos.

**Son sintéticos y NO sustituyen la validación con tráfico real.** Los casos los diseñó quien conoce los
umbrales, así que las cifras de `resultados.md` no son precisión/recall reales: solo muestran que los
casos difíciles existen y cuáles reglas fallan en ellos. Los hallazgos se anotan, no se corrigen aquí.
`resultados.md` se regenera con `validar.py ... --salida`, pero la sección "Hallazgos" está escrita a mano.

## Mapeo de CIC-IDS2017 a reglas

El dataset (Canadian Institute for Cybersecurity) trae los pcaps por día y un CSV con etiquetas por
flujo (`Label`). Para armar `esperadas`, filtrá el CSV por `Label`, fecha/hora y IP, y escribí una
entrada por (origen, destino):

| Etiqueta CIC-IDS2017 | Regla esperada | Notas |
|---|---|---|
| `PortScan` | `port_scan` | Atacante 172.16.0.1 contra 192.168.10.50. Puede haber muchas variantes de nmap (SYN, FIN, etc.); las que no sean SYN puro no las ve la regla (FN esperable). |
| `FTP-Patator` | `ftp_cleartext` | Cada intento manda USER/PASS al puerto 21. |
| `SSH-Patator` | `brute_force_remote` | Conexiones al 22 desde 172.16.0.1. |
| `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` | `syn_flood` (solo si hay SYN masivos) | Son DoS de capa 7 (HTTP): lo normal es **no** esperar `syn_flood`; sirven para medir FP/FN honestos, decidí la verdad terreno por tipo. |
| `DDoS` (LOIC) | `syn_flood` | Varios orígenes contra el servidor web. |
| `Bot` (ARES) | `beaconing` | Beacon HTTP periódico a un C2 (miércoles/viernes). |
| `BENIGN` | `ninguna` | Todo lo demás: ideal para medir FP. Tomá ventanas de tiempo sin ataques. |
| `Web Attack`, `Infiltration`, `Heartbleed` | sin regla | Ninguna regla actual los cubre; no los incluyas como esperadas (serían FN por diseño, no por mala calidad). |

Las IP y fechas de la tabla vienen de la documentación del dataset (de memoria): verificalas contra el CSV. Los pcaps de CIC-IDS2017 son grandes (decenas de GB por día): recortalos por ventana de tiempo
(`editcap -A/-B` de Wireshark) y trabajá cada recorte como una entrada del manifiesto.

## Otros pcaps públicos sugeridos

- Malware-Traffic-Analysis.net (informes con indicadores; **malware**, ver advertencia).
- Stratosphere / CTU-13 y CTU-Malware-Capture (botnets: `beaconing`, `suspicious_ports`; etiquetas por flujo).
- MAWILab (tráfico benigno de backbone con anomalías anotadas; bueno para FP).
- Wireshark SampleCaptures (FTP, DNS, SSH; pequeños y seguros para casos de regla única).
- Capturas propias de tu red doméstica o laboratorio, **anonimizadas** o solo locales: el mejor tráfico benigno.

Verificá licencia y condiciones de uso de cada fuente antes de usarla; no las descargues dentro del repo.
