import { ThemeIcon } from "@mantine/core";
import { IconAlertTriangle, IconHistory, IconListDetails, IconPlugConnected, IconShieldSearch, IconTopologyStar3, IconWorldWww } from "@tabler/icons-react";

// Qué muestra cada sección y con qué ícono. Se usa cuando todavía no hay una captura cargada.
export const EMPTY_SECTIONS = {
  alertas: { icon: IconAlertTriangle, color: "orange", title: "Alertas y ATT&CK", shows: "las alertas que detectó Tracewell, con su evidencia, y el mapa MITRE ATT&CK de las técnicas involucradas" },
  equipos: { icon: IconTopologyStar3, color: "teal", title: "Equipos", shows: "quién habló con quién, con el dueño de cada IP, el programa que abrió cada conexión y un grafo de conversaciones" },
  trafico: { icon: IconWorldWww, color: "violet", title: "DNS y HTTP", shows: "las consultas DNS y los pedidos HTTP sin cifrar, con los archivos que viajaron y su huella SHA-256" },
  remoto: { icon: IconPlugConnected, color: "grape", title: "Acceso remoto", shows: "quién se conectó por SSH, Telnet, SMB, RDP, WinRM o VNC, agrupado por servicio, con los rechazos (RST) y reintentos" },
  cronologia: { icon: IconHistory, color: "indigo", title: "Cronología del caso", shows: "las alertas, el DNS sospechoso, tus sesiones marcadas y los IOC en un solo hilo de tiempo, para contar el caso de principio a fin" },
  sesiones: { icon: IconListDetails, color: "cyan", title: "Sesiones", shows: "todas las conversaciones de la captura, con su explicación en palabras simples, los paquetes y la conversación completa" },
  indicadores: { icon: IconShieldSearch, color: "pink", title: "Indicadores (IOC)", shows: "la lista de IP, redes y dominios maliciosos que cargues, para marcar las sesiones que coincidan" },
};

// Aviso de una sección sin captura: en vez de repetir la pantalla de inicio, dice qué vas a ver acá y cómo empezar.
export default function EmptySection({ section, onDemo, onHome }) {
  const info = Object.hasOwn(EMPTY_SECTIONS, section) ? EMPTY_SECTIONS[section] : null;
  if (!info) return null;
  const Icon = info.icon;
  return (
    <section className="empty-section card" aria-labelledby="empty-title">
      <ThemeIcon size={56} radius="xl" variant="light" color={info.color} aria-hidden="true">
        <Icon size={30} />
      </ThemeIcon>
      <h2 id="empty-title">{info.title}</h2>
      <p>
        Todavía no hay una captura cargada. Cuando cargues una, acá vas a ver {info.shows}.
      </p>
      <div className="empty-actions">
        <button type="button" className="button-primary" onClick={onDemo}>Cargar el ejemplo</button>
        <button type="button" onClick={onHome}>Abrir un archivo o capturar</button>
      </div>
    </section>
  );
}
