# Checklist de validación en hardware real (captura en vivo)

La captura en vivo NO se prueba en CI (los tests usan una interfaz simulada).
Esta lista se ejecuta a mano, en una máquina real, antes de cada versión.

## Requisitos
- [ ] Windows: Npcap instalado (modo compatible con WinPcap NO necesario). Linux: libpcap y ejecutar como root o con `CAP_NET_RAW`.
- [ ] Tracewell ejecutado como administrador/root.

## Pruebas
- [ ] `GET /api/interfaces` lista las interfaces reales con nombre legible.
- [ ] Sin privilegios: iniciar captura devuelve 403 con mensaje claro (no un crash).
- [ ] Sin Npcap (Windows): error 503 con mensaje claro.
- [ ] Iniciar captura en la interfaz Wi-Fi/Ethernet activa y navegar unos segundos: `status` muestra paquetes creciendo.
- [ ] Detener: el análisis aparece (sesiones TCP/UDP/DNS reales).
- [ ] Límite `max_packets` pequeño (p. ej. 50): la captura termina sola con reason `max_packets`.
- [ ] Límite `max_seconds` pequeño (p. ej. 5): termina con reason `max_seconds`.
- [ ] Iniciar dos capturas a la vez: la segunda es rechazada (409).
- [ ] El pcap generado abre sin errores en Wireshark y `count_packets` coincide.
- [ ] Interfaz de loopback: los paquetes no Ethernet se descartan sin romper la captura (limitación conocida del MVP).
- [ ] Generar tráfico de prueba controlado contra una máquina propia (p. ej. `nmap -p 1-100 <host propio>`) y verificar que salta `port_scan`.
- [ ] Reiniciar la captura después de terminar una funciona.
- [ ] Cerrar la app con una captura en curso no deja procesos colgados.

## Resultado
Fecha / máquina / SO / versión de Npcap o libpcap / quién validó / observaciones:

## Ventana de escritorio (`python main.py`)
- [ ] `python main.py --self-test` termina con código 0 (la ventana oculta carga la interfaz, el selector nativo está disponible y el modo demo funciona).
- [ ] `python main.py` abre la ventana con el título "Tracewell" y el modo demo muestra las 3 alertas.
- [ ] El botón "Examinar…" aparece y abre el diálogo nativo de archivos filtrando `.pcap` / `.pcapng`; al elegir un archivo se analiza.
- [ ] Cancelar el diálogo no cambia nada y no muestra errores.
- [ ] Se puede seleccionar y copiar texto (evidencia de una alerta, volcado hexadecimal).
- [ ] Cerrar la ventana termina el proceso (no queda `python` colgado en el Administrador de tareas) y libera el puerto.
- [ ] Cerrar la ventana con una captura en vivo en curso la detiene y borra la carpeta temporal `tracewell_*` (en `%TEMP%`).
- [ ] Sin el runtime WebView2 (Windows muy antiguo) el mensaje de error es comprensible; `--serve-only` sigue funcionando.
- [ ] Linux / macOS: probar `python main.py` (backend GTK/WebKit o Qt de pywebview) y anotar el resultado. NO validado hasta ahora.
