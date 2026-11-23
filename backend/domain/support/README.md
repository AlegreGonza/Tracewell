# Documentación de `backend/domain/support`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## __init__.py

Herramientas de soporte de red de SOLO LECTURA.

Ninguna cambia la configuración del equipo: no renuevan la IP, no limpian el DNS, no corrigen la hora, no tocan el
registro. Miden, consultan y explican; cuando detectan un problema, el resultado trae el comando que la persona
podría ejecutar por su cuenta (solo como texto).

Lo único que sale de la máquina son pruebas que el usuario pide a propósito (un ping, una conexión TCP, una consulta
de hora), y cada pantalla dice a quién se contacta.


## checks.py

Pruebas de conectividad: ¿hay Internet?, latencia, ping, traceroute, puertos, RDP y diferencia de hora.

Todas LEEN o MIDEN: abren conexiones o mandan un ping y cuentan lo que pasó. Ninguna cambia nada en el equipo.


### Funciones y clases


**`resolve`**: Resuelve un nombre con el DNS del sistema. `getaddrinfo` no tiene tiempo límite: se corre en un hilo aparte.


**`ping`**: Ping con el comando del sistema. Las respuestas se cuentan por la línea que trae `TTL=`, que es igual en cualquier idioma (el texto «tiempo»/«time» cambia, el TTL no).


**`_adapter_step`**: Primer paso: ¿hay un adaptador con IP válida? Devuelve el paso y si hay red local (IP que no sea 169.254).


**`internet_check`**: Revisa capa por capa (adaptador → puerta de enlace → Internet por IP → DNS) y dice dónde se corta. Contacta a 1.1.1.1 y 8.8.8.8 (solo abre y cierra una conexión TCP) y le pide a tu DNS la dirección de unos sitios conocidos.


**`_verdict`**: El primer paso que falla marca dónde se corta. Los comandos son SOLO texto: Tracewell no los ejecuta.


**`latency_test`**: Latencia medida con el tiempo de abrir conexiones TCP (se parece al ping y funciona aunque el ICMP esté bloqueado). Contacta a `host:port`. Además hace un ping corto al router para separar «mi red» de «Internet».


**`traceroute`**: Los saltos hasta un destino (tracert / traceroute). Puede tardar hasta un minuto si hay saltos sin respuesta.


**`rdp_check`**: Comprueba que un equipo ofrezca RDP y qué seguridad pide. Manda UNA solicitud de conexión y se corta: no intenta iniciar sesión ni prueba usuarios ni contraseñas.


### Notas del código

- `rdp_check`: TPKT (3, largo 19) + X.224 «Connection Request» + RDP_NEG_REQ pidiendo TLS, NLA y NLA temprana (0x0b).
- `<módulo>`: alcanza con que UNO resuelva: un solo nombre da falsos positivos
- `port_check`: Windows tarda ~2 s en admitir que un puerto local está cerrado


## common.py

Base de las herramientas de soporte: ejecutar comandos del sistema sin shell y validar lo que escribe el usuario.


### Funciones y clases


**`run`**: Ejecuta un comando SIN shell (los argumentos van como lista: nada se interpreta ni se concatena). La salida se decodifica con `_decode` (UTF-8 o la página de códigos del sistema), para que los acentos salgan bien.


**`_decode`**: Texto de un comando. Algunos (netsh, PowerShell) escriben en UTF-8 y otros (ping, ipconfig) en la página de códigos del sistema: se prueba UTF-8 estricto y, si no cierra, la del sistema, así no se rompen los acentos.


**`powershell_json`**: Ejecuta un guion de PowerShell que imprime JSON y lo devuelve ya convertido, o None si falló. Solo para guiones FIJOS de este paquete (consultas de lectura); nunca se arma uno con texto del usuario.


**`valid_host`**: Nombre de equipo o IP escritos por el usuario, ya validados. Lanza ValueError si no sirven. Se exige que empiece con letra o número (así nunca se interpreta como una opción de `ping -n`), que no tenga espacios ni caracteres de shell, y se limita el largo. Igualmente los comandos van sin shell.


## devices.py

Dispositivos de la red local: quién está, su MAC, la marca (por la MAC) y su nombre.

Dos fuentes: la tabla ARP del equipo (lo que ya conoce) y, si se pide, un barrido de pings por la subred para que
conteste todo el que esté encendido. Solo MIRA: un ping por equipo, nada más.


### Funciones y clases


**`is_random_mac`**: Bit «administrada localmente»: los teléfonos y PC modernos lo usan para una MAC privada que cambia por red.


**`_load_oui`**: Base de fabricantes (IEEE) desde `data/oui.csv`, si existe. Formato del registro de la IEEE: Registry, Assignment (6 hex), Organization Name, Organization Address. Sin el archivo, no hay marcas.


**`local_subnets`**: Subredes privadas del equipo. Con `only_routed`, solo las de adaptadores con puerta de enlace: la red real, sin las virtuales de WSL, VirtualBox o Docker (que además harían el barrido eterno).


**`sweep`**: Un ping a cada dirección de las subredes para que el sistema aprenda la MAC de quien conteste. Devuelve cuántas.


**`_resolve_names`**: Nombres por DNS inverso en paralelo y con tope de tiempo: un equipo que no contesta no cuelga la pantalla.


## dupip.py

IP duplicada: dos equipos con la misma dirección en la red (provoca cortes intermitentes difíciles de explicar).

Dos pistas, ambas de lectura: los avisos de conflicto que Windows ya registró (evento 4199 de Tcpip) y, si hay Npcap
y permisos, una sonda ARP que pregunta «¿quién tiene mi IP?» y mira si contesta alguien con OTRA dirección física.


### Funciones y clases


**`_arp_probe`**: Pregunta por ARP quién tiene `ip`. Si contesta una MAC distinta de la nuestra, hay otro equipo con esa IP.


## monitor.py

Monitoreo continuo: detecta cortes intermitentes (el Wi-Fi o Internet que «va y viene») y arma su cronología.

Un hilo de fondo mide cada pocos segundos tres cosas: el router (ping), Internet (conexión TCP a 1.1.1.1:443) y el
DNS (resolver un nombre conocido). Cuando algo deja de responder abre un «corte» con la capa que falló, y lo cierra
cuando vuelve todo. Solo corre mientras Tracewell está abierto, y todo queda en memoria (no escribe archivos).


### Funciones y clases


**`Monitor._track`**: Abre un corte tras `FAILS_TO_OPEN` fallos seguidos (contando desde el primero) y lo cierra al volver todo.


### Notas del código

- `<módulo>`: fallos seguidos para abrir un corte: un solo tropiezo no cuenta


## netinfo.py

Configuración de red del equipo: adaptadores, IP, máscara, puerta de enlace, DNS y si la IP es automática (DHCP).


### Funciones y clases


**`network_config`**: Configuración de red, con una caché de unos segundos: leerla llama a PowerShell (varios segundos) y una misma pantalla la pide más de una vez. `fresh=True` fuerza una lectura nueva (el botón «Actualizar»).


**`_read_config`**: Adaptadores con su configuración. Los datos de puerta de enlace y DNS salen de PowerShell (Windows) o de `ip` y /etc/resolv.conf (Linux); si no se pueden leer, quedan vacíos y el resto igual se muestra.


**`active_ipv4`**: Pares (adaptador, IPv4) de los adaptadores activos: sin loopback ni APIPA, y opcionalmente con MAC o puerta.


**`raw_config`**: La salida completa de `ipconfig /all` (Windows) o `ip addr` (Linux), tal cual, para quien quiera ver todo.


## wifi.py

Wi-Fi: estado de la conexión actual (señal, canal, velocidad) e historial de conexiones y desconexiones.

Solo LEE. En Windows usa `netsh wlan show interfaces` (cuyo texto cambia de idioma: se reconocen los nombres en
español e inglés y, si nada coincide, se muestra la salida cruda) y el registro de eventos de WLAN-AutoConfig.


### Funciones y clases


**`parse_netsh`**: Convierte la salida de `netsh wlan show interfaces` en un diccionario; None si no hay un adaptador Wi-Fi.


**`wifi_history`**: Conexiones y desconexiones de Wi-Fi que Windows anotó (más recientes primero). Llega hasta donde Windows guardó.

