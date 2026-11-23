# Documentación de `frontend/src/components/captures`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## AlertsTable.jsx

- `RuleGuide`: Guía opcional de la regla (falsos positivos, pasos y filtro). Todo texto: viene de un YAML local, nunca HTML.
- `AlertsTable`: Los paquetes de esa IP como un .pcap aparte (para Wireshark o un ticket).

## AttackMap.jsx

- `TACTICS`: Solo las tácticas de ATT&CK que se pueden ver en el tráfico de red, en el orden del ciclo de un ataque, con una frase simple cada una. Las demás (Ejecución, Persistencia, Evadir defensas...) pasan dentro del equipo y una captura de red no las ve: mostrarlas vacías haría creer que "no pasó nada". Una alerta de otra táctica igual aparece, en una columna extra.
- `groupByTactic`: Agrupa las alertas por táctica y técnica: { táctica: { técnica: {id, name, count, severity} } }.
- `AttackMap`: Mapa MITRE ATT&CK de la captura: las tácticas que dispararon alertas se iluminan. Es un MARCO para ordenar lo hallado.

## CaseTimeline.jsx

- `CaseTimeline`: «Cronología del caso»: alertas, DNS sospechoso, sesiones marcadas e IOC juntos, en orden de tiempo. Es distinta del gráfico de tráfico por intervalo. Todo es texto que viene de la captura: nunca HTML.

## CopyFilterButton.jsx

- `CopyFilterButton`: Botón «Copiar filtro Wireshark». El filtro llega ya armado (`filter`) o se pide al hacer clic (`load`). Si el portapapeles no está disponible, el filtro queda a la vista para copiarlo a mano. El filtro puede incluir texto del tráfico (nombres DNS): se muestra siempre como texto, nunca como HTML.

## DnsView.jsx

- `DnsView`: «DNS»: los nombres que se consultaron, cuántas veces, qué respondieron y qué salió mal. Se ve de un vistazo a qué se conectaron los equipos y qué nombres no existen.

## EmptySection.jsx

- `EMPTY_SECTIONS`: Qué muestra cada sección y con qué ícono. Se usa cuando todavía no hay una captura cargada.
- `EmptySection`: Aviso de una sección sin captura: en vez de repetir la pantalla de inicio, dice qué vas a ver acá y cómo empezar.

## ExplainView.jsx

- `Ladder`: Diagrama de la conexión paso a paso (como el «Flow Graph» de Wireshark): cada fila es un paquete importante y su flecha muestra quién se lo manda a quién. Todo es texto que viene del análisis: nunca se interpreta como HTML.

## GuidedCase.jsx

- `jumpTo`: Salta (con scroll suave) a una sección de la pantalla por su id; no hace nada si todavía no está.
- `STEPS`: Los pasos del caso del demo. Son texto fijo: describen la captura de ejemplo (samples/demo.pcap).
- `GuidedCase`: Recorrido guiado del demo: siete pasos para aprender a investigar. Se puede ocultar y los pasos se tildan.

## HostsView.jsx

- `RING_CAP`: equipos por anillo; si hay más, siguen en un segundo anillo más grande
- `SHAPE_OF`: Forma de cada nodo según su rol: círculo = equipo de tu red, cuadrado = multicast, rombo = servidor en internet, hexágono = proveedor conocido. Así el tipo se ve sin depender solo del color.
- `layoutGraph`: Disposición «telaraña»: tu red en el centro y el resto en anillos alrededor. El tamaño del dibujo NO depende de cuántos equipos haya (antes, en dos columnas, cada fila nueva achicaba todo).
- `layoutGraph`: Tu red: 1 equipo va al centro; si hay más, en hasta tres anillos chicos (10 + 20 + el resto) para que no se pisen.
- `nodeLabel`: Qué se muestra como nombre de un equipo y de dónde sale: lo de la captura (DNS/TLS) manda; si no hay, el dueño del rango (tabla local, es una pista) o qué es la dirección especial; si no, la IP.
- `ICONS`: Dibujitos de 24×24 por tipo de equipo. Son formas fijas: nunca se arma nada con datos de la captura.
- `HostsView`: «Equipos»: una fila por IP y un grafo de quién habla con quién (la red local a la izquierda, internet a la derecha). Todo se dibuja como texto/SVG a partir de números y nombres de la captura: nunca como HTML.
- `HostsView`: El hover cambia a cada pasada del ratón: el dibujo y los vecinos no se recalculan salvo que cambie el grafo/el equipo.
- `HostsView`: Perfil: roles inferidos de lo observado en la captura (pistas, no una auditoría).

## HostsView.owners.test.jsx

- `gnode`: Posible bug: iconOf busca en ICONS sin comprobar propiedad propia, así que "__proto__"/"constructor" no caen a pública. El servidor solo manda 4 roles fijos; si se corrige (Object.hasOwn) quitar el `.fails`.

## HttpView.jsx

- `HttpView`: «HTTP» de toda la captura: una fila por petición (sesiones TCP a los puertos habituales de HTTP). Solo aparece si hay HTTP.

## IocPanel.jsx

- `IocPanel`: Lista de indicadores de compromiso (IP, redes o dominios malos) cargada desde un archivo LOCAL. Las sesiones que coinciden se marcan en la tabla. Nada sale del equipo. `refreshKey` cambia con cada análisis nuevo: la lista de IOC sobrevive, pero cuántas sesiones coinciden no.

## LivePanel.jsx

- `LivePanel`: Sondeo mientras corre. Si la captura termina sola (por un límite) pedimos el análisis automáticamente en vez de dejar al usuario mirando un contador congelado.

## MacGroups.jsx

- `MacGroups`: «Equipos por MAC»: agrupa las IP de la red local que comparten la misma dirección física. Varias IP con una MAC suelen ser IPv4 + IPv6 del mismo equipo, o un router/NAT que reenvía otras redes. Es una pista, no una prueba. Todo es texto de la captura: nunca HTML.

## RemoteAccessView.jsx

- `ServiceGroup`: «Acceso remoto»: quién se conecta por SSH, Telnet, SMB, RDP, WinRM o VNC, agrupado por servicio. Las señales (RST, reintentos) son pistas: un RST puede ser un puerto cerrado o un corte normal. Todo es texto que viene de la captura: React lo escapa, nunca se usa HTML.

## RiskCard.jsx

- `RISK_WEIGHT`: Peso de cada alerta en el puntaje, por severidad. El puntaje es la SUMA de los pesos (tope 100): se muestra el porqué.
- `RiskCard`: «Puntaje de riesgo»: un número de 0 a 100 que resume las alertas, con la lista de motivos (nada de cajas negras).

## RulesPanel.jsx

- `toBody`: Convierte lo escrito en el formulario al cuerpo de la API; null si un número todavía no es válido.
- `RulesPanel`: «Reglas»: arma una alerta nueva (filtros + umbral), muestra el YAML en vivo y cuántas sesiones y alertas daría con la captura abierta ANTES de guardarla. Guardar crea un archivo nuevo en rules/; nunca toca las reglas existentes. Todo lo que viene del servidor o de la captura se muestra como texto (React lo escapa).
- `RulesPanel`: Vista previa en vivo: espera a que termines de escribir y consulta al servidor (sin guardar nada).

## SessionDetail.jsx

- `HEX_LINE`: Resalta offset y panel ASCII solo con spans de texto (nunca HTML). Las líneas que no tienen el formato esperado se muestran tal cual; el texto total no cambia.
- `HexBytes`: Cada byte hexadecimal va en su propio <span> para poder resaltar un campo; el texto total no cambia.
- `PacketLayers`: Árbol de capas (Ethernet, IP, TCP...). Pasar el mouse o dar foco a un campo resalta sus bytes en el hex dump; un clic lo deja fijo (para teclado y pantallas táctiles). Todo es texto: nunca HTML.
- `PacketView`: Los bytes vienen del tráfico: se muestran como texto, nunca como HTML.
- `NoteForm`: Nota del analista y marca "revisada". El texto lo escribe una persona: se guarda y se muestra como texto.
- `NoteForm`: Solo al cambiar de sesión: depender también de note/reviewed borraría el aviso "Guardada" justo después de guardar, porque guardar actualiza esos mismos valores.
- `SessionDetail`: La clave `process` solo existe en una captura en vivo: sin ella no se muestra nada.
- `SessionDetail`: Mismo tráfico en Wireshark: el filtro lo arma el servidor al pedirlo.

## SessionHttp.jsx

- `httpNotes`: Notas en lenguaje simple de un intercambio HTTP: lo que merece una mirada. Siempre texto.
- `SessionHttp`: Peticiones y respuestas HTTP (sin cifrar) de UNA sesión, y los archivos que viajaron. No se muestra si no hay HTTP.

## SessionsTable.jsx

- `KNOWN_PROTOCOLS`: Clase de color por protocolo. El texto siempre se muestra: el color ayuda a distinguir, nunca es lo único.
- `PALETTE_SIZE`: Un color por nombre de proceso (paleta de 8): el mismo programa se reconoce de un vistazo. Se asignan por orden de aparición (y no por una cuenta sobre el nombre): así los primeros 8 procesos nunca comparten color, y cada uno lo conserva en todas las páginas mientras la app está abierta. Del noveno en adelante se reutilizan.
- `TriageMarks`: Marcas del analista y coincidencias de IOC. Todo se muestra como texto (la nota la escribe una persona).
- `SessionsTable`: `showProcess`: solo hay datos de procesos en una captura en vivo; con un archivo la columna ni se ofrece. `triageVersion`: sube al guardar una nota o cambiar la lista de IOC; recarga la página actual SIN volver a la primera.
- `SessionsTable`: Borrador del formulario: se aplica al enviar, no en cada tecla. Así no disparamos una petición (y un error de IP inválida) por cada carácter.
- `SessionsTable`: La página va atada a los filtros con los que se eligió. Si los filtros (o el análisis) cambian, la página guardada deja de valer y se lee como 0 en el MISMO render: sin un efecto aparte que haga un render intermedio con filtros nuevos y página vieja (que dispararía una petición de más).
- `SessionsTable`: Un filtro inválido NO se muestra como "no hay sesiones": una tabla vacía se lee como "no hay tráfico", y es un falso negativo. Se muestra solo aquí, junto al filtro; el banner global duplicaría el mismo error.

## SessionsTable.test.jsx

- `lastParams`: Corregido: la página queda atada a los filtros; ya no se pide offset 25 con filtros nuevos.

## StreamView.jsx

- `StreamView`: "Seguir la conversación": lo que se dijo en una sesión TCP, por turnos (como Follow TCP Stream de Wireshark). Los datos vienen del tráfico y pueden ser hostiles: se muestran SIEMPRE como texto, nunca como HTML. Ojo: con protocolos en claro (FTP, HTTP, Telnet) esto muestra el contenido tal cual, contraseñas incluidas.

## Summary.jsx

- `PROTO_COLOR`: Color de cada protocolo en la dona y en las barras (colores de datos: la severidad conserva el suyo).

## Timeline.jsx

- `Timeline`: Gráfico de barras del tráfico en el tiempo (SVG, sin librerías). Picos, silencios y ritmos regulares se ven de un vistazo. Solo dibuja números: no interpreta ningún dato como HTML.
- `Timeline`: Si la respuesta viniera mal formada (otra longitud), se cae a paquetes en vez de romper el gráfico.

## Timeline.test.jsx

- `peaks`: getBarColor compara por valor: todos coinciden con el pico (0)
- `peaks`: el fetch real lo rechazaría con AbortError; aquí solo no debe romper

## TlsView.jsx

- `describeJa4`: Traduce la primera parte de una huella JA4 («t13d1516h2») a frases: así se aprende a leerla.
- `TlsView`: Lo que se ve de una sesión TLS sin descifrarla: sitio, versión, huella JA4 y certificado (solo si va en claro, TLS ≤ 1.2).

## Toolbar.jsx

- `useNativePicker`: Dentro de la ventana de escritorio pywebview expone un diálogo nativo para elegir archivo; en el navegador no existe y se escribe la ruta. pywebview inyecta `window.pywebview.api` DESPUÉS de cargar la página y lo avisa con el evento "pywebviewready": leerlo una sola vez al renderizar llegaría tarde y el botón "Examinar…" nunca aparecería.
- `Toolbar`: `onClose` + `closeLabel`: descartan el análisis y vuelven a la pantalla de inicio (solo se ofrecen con algo cargado).
- `Toolbar`: Un diálogo nativo que falla no debe quedar como un rechazo sin manejar: el usuario tiene que ver un aviso (y puede escribir la ruta a mano).
- `Toolbar`: Informe de triaje listo para un ticket: alertas, evidencia y notas.

## TopTalkers.jsx

- `TopTalkers`: «Quién más habla»: los equipos con más tráfico, como barras de colores. Un clic filtra las sesiones por ese equipo.

## Welcome.jsx

- `FEATURES`: Lo que se puede hacer con Tracewell, para que la entrada se vea como un tablero de inicio y no como un manual.
- `Welcome`: Pantalla de inicio (todavía no hay una captura cargada): explica las tres formas de empezar, deja la más rápida —el ejemplo— a un clic y muestra qué hay adentro de la herramienta.
