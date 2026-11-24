# Validación con tráfico real: plan

> **Estado: NO se midió todavía con tráfico real.** Las únicas cifras de precisión y recall que existen son las
> de `validacion/resultados.md`, obtenidas con un corpus **sintético** que genera el propio proyecto: sirven
> para detectar regresiones, no dicen nada sobre cómo se comportan las reglas en una red de verdad. Este
> documento describe cómo medirlo; no contiene resultados.

## Qué corpus usar

| Corpus | Qué aporta | Cómo obtenerlo | Cuidado |
|---|---|---|---|
| **Pcaps de ejemplo de Wireshark** (SampleCaptures) | Protocolos sueltos (DNS, HTTP, FTP, TLS, SMB...) y casos raros; casi todo benigno, buenos para falsos positivos | Wiki de Wireshark, página *SampleCaptures*: descarga directa de cada `.pcap` | Son chicos y de laboratorio; revisá la nota de cada archivo |
| **CIC-IDS2017** (Canadian Institute for Cybersecurity) | Una semana de tráfico con ataques etiquetados (fuerza bruta FTP/SSH, DoS, escaneo de puertos, botnet) y tráfico benigno | Sitio del CIC (UNB), formulario de descarga; los pcaps pesan decenas de GB por día | Trae CSV de flujos con etiquetas y horarios de cada ataque: de ahí sale la verdad terreno |
| **Stratosphere CTU-13 / CTU-Normal** | Capturas de botnets reales ejecutadas en un laboratorio, con flujos etiquetados, y capturas normales | Sitio del Stratosphere Laboratory (CTU Praga) | **Las capturas de botnet son tráfico de malware.** Se analizan como archivo (no se ejecuta nada), pero tratalas como hostiles |
| **MAWI** (WIDE, Japón) | Tráfico real de un enlace troncal, anonimizado; sirve para medir falsos positivos y rendimiento a escala | Repositorio MAWI, un archivo de 15 minutos por día | Casi sin etiquetas: mide *cuántas alertas salen en tráfico no etiquetado*, que luego se revisan a mano por muestreo |

Los enlaces exactos y los términos de uso hay que verificarlos en el sitio de cada corpus al descargar; no se
copian acá porque cambian. **No uses pcaps de malware-traffic-analysis para esto**: vienen en zips con
contraseña y contienen malware real.

## Preparación

1. Bajá cada corpus a una carpeta **fuera del repositorio** (por ejemplo `D:\datos-externos`). Los pcaps no se
   versionan.
2. Comprobá la integridad con el SHA-256 que publique el sitio, si lo hay.
3. Si la captura es enorme, recortá por ventana de tiempo (`editcap -A ... -B ...` de Wireshark) a la franja del
   ataque que describe la documentación del corpus.
4. Hacelo en una máquina donde abrir un pcap hostil no importe.

## Verdad terreno

Escribí un manifiesto YAML (formato en `validacion/README.md`) con, por pcap, las alertas **esperadas**: regla,
IP origen y destino según la documentación del corpus (por ejemplo, atacante y víctima del ataque de fuerza
bruta documentado en CIC-IDS2017). Para el tráfico benigno, `esperadas: ninguna`.

```yaml
version: 1
pcaps:
  - id: cic_ftp_patator
    ruta: D:/datos-externos/cic-ids2017/ftp-patator.pcap
    descripcion: FTP-Patator (franja documentada por el CIC)
    etiquetas: [positivo]
    esperadas:
      - {regla: brute_force_remote, origen: <IP atacante>, destino: <IP víctima>}
  - id: wireshark_http
    ruta: D:/datos-externos/wireshark/http.pcap
    etiquetas: [benigno]
    esperadas: ninguna
```

Las etiquetas de los corpus son de *flujos*, y Tracewell alerta por *regla, origen y destino*. Mapeá cada tipo
de ataque a la regla que debería saltar y dejá fuera lo que Tracewell no pretende detectar (un DoS volumétrico,
por ejemplo): contarlo como falso negativo mediría otra cosa.

## Cómo correr el validador

```powershell
python validacion\validar.py D:\datos-externos\manifiesto_real.yaml `
  --salida validacion\resultados_real.md `
  --titulo "Validación con tráfico real" `
  --nota "Corpus: CIC-IDS2017, Wireshark SampleCaptures. Commit de Tracewell: <hash>"
```

Opciones útiles: `--reglas <carpeta>`, `--etiqueta benigno|positivo|evasion|dificil`, `--omitir-faltantes`.
El validador ejecuta `backend.domain.analysis.analyzer.analyze` tal cual y no modifica código de producción.
Un pcap ilegible se informa como ERROR y no detiene la corrida.

## Cómo reportar precisión y recall

Por regla, con las definiciones de `validacion/README.md`: **TP** esperada y obtenida, **FP** obtenida no
esperada, **FN** esperada no obtenida; **precisión = TP / (TP + FP)** y **recall = TP / (TP + FN)**
(`n/d` si el divisor es 0). Al publicar un resultado, incluí siempre:

- el commit de Tracewell y de `rules/`, y la lista exacta de pcaps (con su SHA-256);
- los TP/FP/FN absolutos por regla (con 3 casos, un 100 % no significa nada);
- el detalle de cada FP y FN con el pcap que lo reproduce, y si el error es de la regla o de la etiqueta;
- qué se excluyó y por qué;
- que en MAWI y otros corpus sin etiquetas solo se mide **volumen de alertas por hora de tráfico** y una
  muestra revisada a mano, no precisión.

No se calcula especificidad: en tráfico real "no alertar" no es contable.

## Lo que este plan no resuelve

- Los corpus públicos son de laboratorio o de redes de otro país y otra época: una buena métrica no se traslada
  a la red de cada organización.
- Las reglas tienen umbrales fijos (ver `docs/en/limitations.md`): se esperan falsos positivos con CDN,
  escáneres de vulnerabilidades internos y similares; justamente para eso se mide.
- Ajustar umbrales mirando el mismo corpus con el que se mide sobreajusta: reservá capturas sin tocar para la
  medición final.
