# Guía didáctica: de Wireshark a Tracewell

**La idea del proyecto:** Wireshark es una herramienta excelente, pero su primera impresión es una pared de filtros, paneles y siglas. Tracewell busca **bajar esa barrera**: mostrar lo mismo que ve un analista experto, pero explicado, ordenado y con ayuda en cada paso. No reemplaza a Wireshark: te prepara para usarlo.

## Qué hace Tracewell para que no asuste
| Idea | Cómo se ve |
|---|---|
| **Ayuda en cada sección** | Un botón **?** junto a cada título explica qué estás viendo y, cuando existe, **«En Wireshark: …»** (qué menú o filtro equivale). |
| **Glosario con buscador** | El botón **Glosario** de la barra explica TCP, SYN, TTL, DNS, SNI, JA4, hash... en una o dos frases. |
| **«En palabras simples»** | Cada sesión se cuenta como frases: quién habló con quién, si la conexión se abrió bien, se cortó o fue rechazada, cuánto se dijeron y si va cifrada. |
| **Diagrama de la conexión** | Debajo, los pasos importantes con flechas: `SYN →`, `← SYN+ACK`, `ACK →`, datos, `FIN`. Es el «Flow Graph» de Wireshark, sin buscarlo en un menú. |
| **Capas con pistas** | El paquete se abre en Ethernet → IP → TCP/UDP → datos; cada campo trae su explicación y, al pasar el mouse, **se resaltan sus bytes** en el volcado hexadecimal. |
| **Mapa MITRE ATT&CK** | Las alertas se ordenan por táctica del atacante, con una frase simple por cada una. |
| **Caso guiado** | Al abrir el demo aparece un recorrido de 7 pasos para investigar como un analista. |
| **Colores que ayudan, nunca lo único** | Cada protocolo y cada programa tienen su color, pero siempre acompañado de texto. |

## Equivalencias: qué querés hacer → dónde está
| Querés... | En Wireshark | En Tracewell |
|---|---|---|
| Ver las conversaciones | Estadísticas → Conversaciones | Tabla **Sesiones** |
| Ver quién habla con quién | Estadísticas → Puntos finales | **Equipos** (tabla y grafo) |
| Leer lo que se dijeron en TCP | Seguir → Flujo TCP | **Conversación** (dentro de la sesión) |
| Ver el diálogo de una conexión | Estadísticas → Gráfico de flujo | **En palabras simples** + diagrama |
| Ver los campos de un paquete | Panel «Detalles del paquete» | **Capas** |
| Ver los bytes | Panel «Bytes del paquete» | **Volcado hexadecimal** |
| Ver tráfico en el tiempo | Estadísticas → Gráficos de E/S | **Tráfico en el tiempo** |
| Filtrar DNS | Filtro `dns` | Tabla **DNS** |
| Filtrar HTTP / sacar archivos | Filtro `http` / Exportar objetos | **HTTP sin cifrar** y **Archivos** (con SHA-256) |
| Saber qué cliente TLS es | Plugin JA4 | **TLS** con la huella **JA4** |
| Ver el certificado | `tls.handshake.certificate` | **TLS → certificado** (solo TLS ≤ 1.2) |
| Guardar solo una conversación | Exportar paquetes especificados | **Descargar .pcap de esta sesión** |
| Saber qué programa generó el tráfico | No lo hace | Columna **Proceso** (captura en vivo) |
| Detectar patrones sospechosos | No lo hace (es un IDS) | **Alertas** + mapa ATT&CK |

## Cómo leer un paquete (la receta de 30 segundos)
Un paquete son **cajas dentro de cajas**:
1. **Ethernet:** de qué tarjeta a qué tarjeta va (MAC) y qué viene dentro.
2. **IP:** de qué equipo a qué equipo (IP de origen y destino), el **TTL** y el protocolo siguiente.
3. **TCP o UDP:** de qué puerta a qué puerta (puertos). En TCP, las **banderas** dicen el momento de la conexión (SYN abrir, ACK confirmar, FIN cerrar, RST cortar).
4. **Datos:** lo que se dijeron. Si el puerto es 443, va cifrado (TLS): solo se ven metadatos.

## Camino de aprendizaje sugerido
1. Abrí el **demo** y seguí el **caso guiado**.
2. En cada sección, tocá el **?** y leé el «En Wireshark».
3. Abrí tres sesiones distintas y compará su **diagrama de conexión**.
4. Leé una **conversación FTP** y notá que la contraseña viaja en claro.
5. Hacé una **captura propia** (en vivo o con Wireshark) y repetí el recorrido.
6. Recién entonces abrí **Wireshark** con el mismo `.pcap` (botón *Descargar .pcap*): ya vas a reconocer lo que ves.

## Lo que Tracewell no hace (límites honestos)
- **No descifra HTTPS.** Con TLS se ven los metadatos (sitio pedido, huella JA4, tamaños, tiempos), no el contenido.
- **No reemplaza a Wireshark** para análisis profundo de protocolos poco comunes.
- **Las explicaciones son orientativas:** describen lo que se ve en la captura, no prueban intenciones. Un falso positivo es posible, y decidirlo es el trabajo del analista.
- **Solo Ethernet**, y una captura iniciada a mitad de una conversación no muestra cómo empezó.
