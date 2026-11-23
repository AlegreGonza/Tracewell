// Textos de ayuda en lenguaje simple. Cada tema explica QUÉ es lo que se ve, CÓMO leerlo y, cuando existe,
// y, cuando hace falta, CÓMO se relaciona con otras herramientas: el objetivo de Tracewell es que esto deje de dar miedo.
// Todo es texto plano (se muestra como texto, nunca como HTML).

export const HELP = {
  riesgo: {
    title: "Puntaje de riesgo",
    text: "Un número de 0 a 100 que resume cuánto de preocupante hay en la captura. Se calcula sumando un peso por cada alerta según su severidad (crítica 35, alta 25, media 12, baja 5) con tope en 100, y la lista de al lado muestra qué suma cada una. No es una condena: es una guía para saber por dónde empezar, y un puntaje alto puede incluir falsos positivos.",
  },
  soporte_config: {
    title: "Configuración de red",
    text: "Cómo está configurada cada conexión de tu PC: su dirección IP, la máscara (qué tan grande es tu red local), la puerta de enlace (el router, por donde sale todo hacia Internet) y los servidores DNS (los que traducen nombres). «IP automática» quiere decir que el router se la da (DHCP). Una IP 169.254.x.x significa que la PC no consiguió IP del router.",
  },
  soporte_internet: {
    title: "¿Hay Internet?",
    text: "Revisa de abajo hacia arriba: si tu adaptador está conectado, si llegás al router, si salís a Internet por dirección IP y si se traducen los nombres (DNS). El primer paso que falla te dice dónde está el problema. Para probarlo abre una conexión corta a 1.1.1.1 y 8.8.8.8 y le pide a tu DNS la dirección de unos sitios conocidos. Los comandos que sugiere son solo texto: Tracewell no los ejecuta.",
  },
  soporte_latencia: {
    title: "Latencia",
    text: "Cuánto tarda en ir y volver un mensaje corto. Menos de 30 ms es excelente; 100 ms ya se nota en videollamadas. La «variación» (jitter) es cuánto cambia de un intento a otro: si es alta, las llamadas se entrecortan aunque el promedio sea bueno. Se mide abriendo conexiones a un servidor público y, aparte, con ping a tu router: si el router responde rápido y Internet lento, el problema está afuera de tu casa.",
  },
  soporte_dispositivos: {
    title: "Dispositivos de la red",
    text: "Los equipos de tu red local: su IP, su dirección física (MAC) y, si se conoce, la marca. La lista sale de la tabla ARP de tu PC (con quién habló hace poco). «Buscar en la red» le manda un ping a cada dirección para que contesten todos los que estén encendidos. Los teléfonos modernos usan una MAC privada que cambia por red, por eso no se puede saber su marca.",
  },
  soporte_wifi: {
    title: "Wi-Fi",
    text: "La señal de tu conexión inalámbrica: de 0 a 100 %. Arriba del 70 % es buena; debajo de 40 % se corta o va lenta. El canal y la banda importan: 5 GHz es más rápida pero llega menos lejos que 2,4 GHz. El historial muestra las veces que Windows se conectó o se desconectó: muchas desconexiones seguidas indican un problema de señal o del router.",
  },
  soporte_monitoreo: {
    title: "Monitoreo de cortes",
    text: "Mide cada pocos segundos el router, Internet y el DNS, y anota cada vez que algo deja de responder: cuándo empezó, cuánto duró y qué capa falló (red local, internet o DNS). Sirve para esos cortes que «van y vienen» y que nunca ocurren cuando te ponés a mirar. Solo funciona mientras Tracewell está abierto, y lo registrado se pierde al cerrarlo.",
  },
  soporte_herramientas: {
    title: "Herramientas",
    text: "Pruebas sueltas sobre un equipo o dirección que elijas: ping (¿responde?), traza de ruta (por qué routers pasa el camino), puertos (¿qué servicios acepta conexiones?), RDP (¿se puede acceder remotamente y con qué seguridad?), hora (¿el reloj de tu PC está en hora?) e IP duplicada. Ninguna cambia nada: solo miden.",
  },
  sistema_resumen: {
    title: "Resumen del equipo",
    text: "El estado general de esta computadora: cuánta memoria (RAM) y procesador se usan, el espacio en disco y cuánto lleva encendida. Es la primera mirada cuando algo anda lento: si la RAM está casi llena o un proceso se come el procesador, ya sabés por dónde seguir.",
  },
  sistema_procesos: {
    title: "Procesos",
    text: "Un proceso es un programa en marcha. Cada uno tiene un número (PID), un dueño (el usuario que lo lanzó) y consume RAM y procesador. Ordená por RAM o procesador para ver quién gasta más. «Notas» marca pistas, no veredictos: por ejemplo un programa que corre desde una carpeta temporal. Abrí uno para ver su ruta, de quién es hijo, con quién se conecta y la firma de su archivo. Sin permisos de administrador algunos datos de procesos del sistema aparecen como «—».",
  },
  sistema_puertos: {
    title: "Puertos abiertos",
    text: "Un puerto abierto («en escucha») es una puerta por la que un programa espera que le hablen. «Solo esta PC» significa que únicamente tu propio equipo puede llamar; «Toda la red» (0.0.0.0) que cualquier equipo de tu red puede intentarlo. Conviene que lo expuesto a toda la red sea lo que vos esperás: un servicio que no reconocés abierto a todos merece una mirada.",
  },
  sistema_conexiones: {
    title: "Conexiones activas",
    text: "Las conversaciones que tu equipo tiene abiertas ahora con otros equipos, y qué programa las abrió. «Dueño del rango» es una pista de quién es la IP remota (Google, Microsoft…) sacada de una tabla local; no es una consulta a internet ni una prueba. Una conexión a una IP pública sin dueño conocido, desde un programa que no esperás, es lo que hay que mirar.",
  },
  sistema_servicios: {
    title: "Servicios",
    text: "Los servicios son programas que Windows (o Linux) arranca solos y corren en segundo plano, sin ventana. Muchos son del sistema. Fijate en los que están en marcha y en su ruta: un servicio cuyo programa vive en una carpeta temporal o que no reconocés es una pista. Esta pantalla solo lee: no activa ni desactiva nada.",
  },
  sistema_inicio: {
    title: "Programas de inicio",
    text: "Lo que se ejecuta cada vez que arranca la sesión: entradas del registro de Windows (Run) y las carpetas de Inicio. Es el lugar clásico donde un programa malicioso se instala para sobrevivir a un reinicio, y también donde lo hacen muchos programas legítimos (OneDrive, Teams). Solo se lee.",
  },
  resumen: {
    title: "Resumen",
    text: "Los números gordos de la captura: cuántas conversaciones (sesiones), paquetes y bytes hay. «Sin IP» son paquetes como ARP, que no pertenecen a ninguna conversación; «Dañados» son paquetes cortados o ilegibles. Paquetes + Sin IP + Dañados da el total de la captura: si no cierra, algo se perdió.",
  },
  tiempo: {
    title: "Tráfico en el tiempo",
    text: "Cada barra es un intervalo de tiempo y su altura, cuánto tráfico hubo. Un pico es una ráfaga; un silencio, que no pasó nada; barras parejas y repetidas pueden ser un ritmo regular (típico de un programa que «llama a casa»).",
  },
  alertas: {
    title: "Alertas",
    text: "Cuando el tráfico coincide con un patrón conocido, Tracewell avisa. Abrí una alerta para ver qué significa, la evidencia exacta y a qué técnica MITRE ATT&CK corresponde. Una alerta NO es una condena: puede ser un falso positivo, y la tarea del analista es decidirlo.",
  },
  attack: {
    title: "Mapa MITRE ATT&CK",
    text: "MITRE ATT&CK es el «diccionario» de cómo atacan los delincuentes. Las columnas son las tácticas (el objetivo del atacante en cada etapa) que se pueden ver en el tráfico de red: reconocimiento, exploración, movimiento lateral, comando y control y exfiltración. Los casilleros son las técnicas concretas. Las que se iluminan son las que dispararon alertas en esta captura.",
  },
  rules: {
    title: "Crear una alerta",
    text: "Una regla dice qué tráfico mirar (protocolo, IP de origen o destino, puerto) y cuántas veces tiene que repetirse en una ventana de tiempo para que salte una alerta. Antes de guardarla ves cuántas sesiones y alertas daría con la captura abierta. Se guarda como un archivo YAML nuevo en la carpeta rules/ y no cambia las reglas que ya existen.",
  },
  ioc: {
    title: "Indicadores de compromiso (IOC)",
    text: "Una lista de IP, redes o dominios que ya se sabe que son maliciosos. La cargás desde un archivo de texto (uno por línea) y Tracewell marca las sesiones que coinciden. Todo ocurre en tu equipo: no se consulta ningún servicio externo.",
  },
  sesiones: {
    title: "Sesiones",
    text: "Una sesión es una conversación entre dos extremos (IP y puerto de cada lado) con un protocolo. Cuenta los paquetes de ida y de vuelta. El «origen» es quien mandó el primer paquete visto. Hacé clic en el número para ver los paquetes, la conversación y los detalles.",
  },
  conversacion: {
    title: "Conversación",
    text: "Reconstruye lo que se dijeron los dos lados en una sesión TCP, por turnos y sin los datos repetidos. Con protocolos sin cifrar (HTTP, FTP, Telnet) se lee como un chat. Con HTTPS va cifrado y solo se ven los metadatos.",
  },
  capas: {
    title: "Capas del paquete",
    text: "Un paquete son cajas dentro de cajas: Ethernet contiene a IP, IP contiene a TCP o UDP, y TCP contiene los datos. Pasá el mouse por un campo y se resaltan sus bytes en el volcado hexadecimal de arriba.",
  },
  hexdump: {
    title: "Volcado hexadecimal",
    text: "Los bytes del paquete tal cual. A la izquierda la posición, en el medio cada byte en hexadecimal (00 a ff) y a la derecha los mismos bytes como texto: un punto significa «no imprimible».",
  },
  equipos: {
    title: "Equipos",
    text: "Una fila por cada IP que aparece en la captura: cuántas conversaciones tuvo, con cuántos equipos habló, cuánto tráfico movió y qué servicios ofrece (los puertos a los que otros se conectaron). El gráfico muestra quién habla con quién: tu red a la izquierda, internet a la derecha, y la línea es más gruesa cuanto más tráfico. Hacé clic en un equipo para ver sus sesiones.",
  },
  dns: {
    title: "DNS",
    text: "Antes de conectarse a un sitio, un equipo le pregunta al DNS «¿cuál es la IP de este nombre?». Esta tabla junta esas preguntas y respuestas. Mirá los NXDOMAIN (nombres que no existen: muchos seguidos pueden ser malware probando dominios al azar), los nombres que parecen generados al azar y las respuestas con TTL muy bajo.",
  },
  http: {
    title: "HTTP",
    text: "Las peticiones web SIN cifrar de la captura: qué pidió cada cliente (GET para pedir, POST para enviar datos) y qué le respondió el servidor (200 = bien, 404 = no existe, 302 = redirige). Si el sitio usa HTTPS no se ve nada de esto, porque va cifrado. Ojo con los POST que envían una contraseña sin cifrar.",
  },
  archivos: {
    title: "Archivos que viajaron",
    text: "Cuando una respuesta HTTP trae un archivo, Tracewell calcula su huella SHA-256 (un identificador único del contenido) y reconoce su tipo REAL mirando los primeros bytes, porque la extensión se puede falsear. Si la huella aparece en un servicio como VirusTotal, sabés si es conocido. Descargarlo es opcional y se guarda como .bin: puede ser malware, no lo abras.",
  },
  explicacion: {
    title: "En palabras simples",
    text: "Lo que un analista con experiencia «lee» de los paquetes, escrito como frases: quién habló con quién, si la conexión se abrió bien, se cortó o fue rechazada, cuánto se dijeron y si el contenido va cifrado. Debajo, el diagrama paso a paso: cada flecha es un paquete importante (SYN, SYN+ACK, ACK, datos, FIN, RST). Son pistas sobre lo que se VE en la captura, no pruebas de intenciones.",
  },
  tls: {
    title: "TLS (la conexión cifrada)",
    text: "HTTPS y muchos otros servicios van cifrados con TLS. Aunque no se pueda leer el contenido, el saludo inicial viaja en claro y dice mucho: qué sitio se pidió (SNI), qué versión se acordó y la «huella» JA4, que identifica cómo se presenta el programa cliente (dos programas distintos casi nunca dan la misma). En TLS 1.2 se ve además el certificado del servidor; en TLS 1.3 el certificado va cifrado.",
  },
  ja4: {
    title: "Huella JA4",
    text: "Un identificador del cliente TLS armado con su lista de cifrados y extensiones. Se lee en tres partes separadas por guion bajo: la primera resume la conexión (protocolo, versión, si pide un sitio por nombre, cuántos cifrados y extensiones, y el protocolo de aplicación), las otras dos son huellas de las listas. Sirve para reconocer QUÉ PROGRAMA habla aunque el contenido esté cifrado, y para comparar con huellas conocidas de malware.",
  },
  pcap: {
    title: "Descargar .pcap",
    text: "Guarda SOLO los paquetes de esta sesión como un archivo nuevo, para abrirlo en Wireshark o adjuntarlo a un ticket sin arrastrar toda la captura.",
  },
};

// Glosario: palabras que asustan, explicadas sin vueltas.
export const GLOSSARY = [
  ["Paquete", "Un «sobre» de datos que viaja por la red. Una página web se reparte en muchos paquetes."],
  ["Sesión (flujo)", "Todos los paquetes de una misma conversación entre dos extremos, en los dos sentidos."],
  ["IP", "La dirección de un equipo en la red, como 192.168.1.10. Las que empiezan con 192.168, 10. o 172.16–31 son privadas (de tu red); el resto, públicas."],
  ["Puerto", "El «número de puerta» de un servicio dentro de un equipo: 443 es HTTPS, 80 HTTP, 53 DNS, 21 FTP, 22 SSH."],
  ["TCP", "Protocolo que asegura que los datos lleguen completos y en orden. Empieza con un saludo y termina con un cierre."],
  ["UDP", "Protocolo más rápido y simple: manda y no confirma. Lo usan DNS, videollamadas y juegos."],
  ["ICMP", "Mensajes de control de la red. El «ping» es ICMP."],
  ["Handshake (saludo de 3 pasos)", "Cómo empieza una conexión TCP: SYN («¿hablamos?»), SYN+ACK («sí, hablemos») y ACK («perfecto»)."],
  ["SYN / ACK / FIN / RST", "Banderas de TCP. SYN pide abrir; ACK confirma; FIN cierra con educación; RST corta de golpe."],
  ["Keep-alive", "Mensajes mínimos que un programa manda cada tanto para mantener viva una conexión. No es un ataque."],
  ["TTL", "«Tiempo de vida» de un paquete: cada router le resta 1. Su valor inicial orienta sobre el sistema (64 Linux/Mac, 128 Windows)."],
  ["DNS", "La «agenda» de internet: traduce nombres (example.com) a direcciones IP."],
  ["NXDOMAIN", "La respuesta de DNS que dice «ese nombre no existe». Muchos seguidos pueden indicar malware que prueba dominios al azar."],
  ["HTTP / HTTPS", "El protocolo de la web. HTTPS es HTTP dentro de un túnel cifrado (TLS)."],
  ["TLS", "El cifrado de HTTPS. Con TLS solo se ven los metadatos: quién habla con quién, cuándo y cuánto."],
  ["SNI", "El nombre del sitio que el cliente pide al iniciar una conexión TLS. Va en claro aunque todo lo demás esté cifrado."],
  ["JA4", "Una «huella digital» del cliente TLS (cómo se presenta). Permite reconocer qué programa habla aunque vaya cifrado."],
  ["Certificado TLS", "El «documento de identidad» del servidor. Si es autofirmado o vencido, es una pista."],
  ["Hex dump (volcado hexadecimal)", "Los bytes de un paquete mostrados en base 16, con su versión en texto al costado."],
  ["pcap / pcapng", "Formatos de archivo para guardar capturas de red. Se abren con Wireshark."],
  ["snaplen", "El máximo de bytes que se guardó por paquete. Si es chico, los paquetes están recortados."],
  ["IOC", "Indicador de compromiso: una IP, dominio o archivo (hash) que se sabe malicioso."],
  ["MITRE ATT&CK", "El catálogo público de tácticas y técnicas que usan los atacantes. Ordena y da nombre a lo que ves."],
  ["Beaconing", "Un programa que se conecta a su servidor a intervalos muy regulares para recibir órdenes."],
  ["C2 (comando y control)", "El servidor desde el que un atacante maneja equipos infectados."],
  ["Falso positivo", "Una alerta que salta aunque no haya nada malo. Aprender a reconocerlos es gran parte del trabajo."],
  ["PID", "El número que el sistema le da a cada proceso en marcha. Cambia cada vez que el programa se abre."],
  ["Proceso", "Un programa mientras se está ejecutando. Un mismo programa (como Chrome) puede tener muchos procesos."],
  ["RAM", "La memoria de trabajo del equipo. Lo que un programa tiene cargado ahora ocupa RAM; si se llena, el equipo se vuelve lento."],
  ["Puerto en escucha", "Un puerto donde un programa espera que otros se conecten. Se ve en «Puertos abiertos»."],
  ["0.0.0.0", "«Todas las direcciones de este equipo». Un servicio escuchando ahí acepta conexiones de toda la red; en 127.0.0.1 solo acepta las de la propia PC."],
  ["Servicio", "Un programa que el sistema arranca solo y corre en segundo plano, sin ventana."],
  ["Firma digital", "Un sello con el que el autor de un programa certifica que es suyo y que nadie lo modificó. Un programa sin firma no es malo por eso, pero pide más cuidado."],
  ["Hash (SHA-256)", "Una «huella» de un archivo: si el archivo cambia un solo byte, cambia el hash. Sirve para reconocer archivos conocidos."],
];
