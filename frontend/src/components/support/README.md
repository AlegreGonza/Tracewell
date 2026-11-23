# Documentación de `frontend/src/components/support`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## DevicesView.jsx

- `DevicesView`: «Dispositivos de la red»: quién está en tu red local. Al abrir muestra lo que tu PC ya conoce (tabla ARP); «Buscar en la red» manda un ping a cada dirección para que contesten todos los encendidos.

## InternetCheckView.jsx

- `InternetCheckView`: «¿Hay Internet?»: revisa capa por capa y dice dónde se corta. Los comandos que sugiere son solo texto.

## MonitorView.jsx

- `MonitorView`: «Monitoreo de cortes»: mide en segundo plano y anota cuándo y por qué se cortó la conexión.

## NetworkViews.jsx

- `PortsView`: «Puertos abiertos»: lo que escucha en este equipo, con su programa y quién puede llamarlo.

## ProcessDetail.jsx

- `ProcessDetail`: Detalle de UN proceso. Todo texto plano: nombres y rutas vienen del sistema y pueden ser cualquier cosa.

## ProcessesView.jsx

- `ProcessesView`: «Procesos»: lo que corre en este equipo, ordenable por RAM o procesador. Solo lectura: no se puede terminar nada.

## RefreshButton.jsx

- `RefreshButton`: Botón «Actualizar» con comprobante: muestra la hora de la última lectura (así se nota aunque los datos no hayan cambiado) y «Actualizando…» mientras trabaja.

## SystemOverview.jsx

- `Meter`: Una barra con el porcentaje en texto (el color solo refuerza: el número siempre está). `goodHigh`: cuando un valor ALTO es bueno (la señal del Wi-Fi), los colores se invierten.

## ToolsView.jsx

- `PingTool`: Ping continuo: un ping por segundo desde el navegador (así no hay nada que quede corriendo en el servidor).

## ToolsView.test.jsx

- `type`: Con timers falsos, userEvent necesita advanceTimers; se usa fireEvent para evitar enredos.

## WifiView.jsx

- `WifiView`: «Wi-Fi»: señal, canal y velocidad de la conexión actual, más el historial de conexiones y desconexiones.

## hints.js

- `HINT_LABEL`: Nombre corto de cada pista sobre un programa. El texto largo (el motivo) llega del servidor.
