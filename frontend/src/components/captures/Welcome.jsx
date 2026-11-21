import { ThemeIcon } from "@mantine/core";
import {
  IconActivity, IconAlertTriangle, IconFileSearch, IconNetwork, IconPlayerPlay, IconRadar2, IconTopologyStar3, IconWorldWww,
} from "@tabler/icons-react";

// Lo que se puede hacer con Tracewell, para que la entrada se vea como un tablero de inicio y no como un manual.
const FEATURES = [
  { icon: IconAlertTriangle, color: "orange", title: "Alertas con MITRE ATT&CK", text: "Escaneos, contraseñas en claro y DNS raro, con la evidencia y la técnica." },
  { icon: IconTopologyStar3, color: "teal", title: "Equipos y conversaciones", text: "Quién habló con quién, con el dueño de cada IP y el programa que lo hizo." },
  { icon: IconWorldWww, color: "violet", title: "DNS, HTTP y TLS", text: "Nombres, pedidos, archivos con huella SHA-256 y la huella JA4 del cliente." },
  { icon: IconNetwork, color: "cyan", title: "Soporte de red", text: "Procesos, puertos, Wi-Fi, latencia y un monitor de cortes. Todo de solo lectura." },
];

// Pantalla de inicio (todavía no hay una captura cargada): explica las tres formas de empezar, deja la más rápida
// —el ejemplo— a un clic y muestra qué hay adentro de la herramienta.
export default function Welcome({ onDemo, onOpenSupport }) {
  return (
    <section className="start" aria-labelledby="start-title">
      <header className="start-head">
        <ThemeIcon className="start-logo" size={64} radius="xl" variant="light" aria-hidden="true">
          <IconActivity size={34} stroke={2} />
        </ThemeIcon>
        <h2 id="start-title">Empezá analizando una captura</h2>
        <p className="start-lead">
          Tracewell agrupa los paquetes en sesiones y marca la actividad sospechosa con reglas
          basadas en MITRE ATT&amp;CK.
        </p>
      </header>

      <ol className="start-steps">
        <li className="start-step">
          <ThemeIcon className="start-ico" size="lg" radius="md" variant="light" color="teal" aria-hidden="true">
            <IconPlayerPlay size={20} />
          </ThemeIcon>
          <span className="start-num" aria-hidden="true">01</span>
          <strong className="start-title">Probar con un ejemplo</strong>
          <p className="start-text">
            Una captura de muestra que dispara las tres reglas: escaneo de puertos, FTP en texto
            claro y DNS sospechoso.
          </p>
          <button type="button" className="button-primary" onClick={onDemo}>
            Cargar el ejemplo
          </button>
        </li>
        <li className="start-step">
          <ThemeIcon className="start-ico" size="lg" radius="md" variant="light" color="violet" aria-hidden="true">
            <IconFileSearch size={20} />
          </ThemeIcon>
          <span className="start-num" aria-hidden="true">02</span>
          <strong className="start-title">Abrir un archivo</strong>
          <p className="start-text">
            Escribí la ruta de un <code>.pcap</code> o <code>.pcapng</code> en la barra de arriba
            (o usá Examinar…) y tocá Analizar.
          </p>
        </li>
        <li className="start-step">
          <ThemeIcon className="start-ico" size="lg" radius="md" variant="light" color="orange" aria-hidden="true">
            <IconRadar2 size={20} />
          </ThemeIcon>
          <span className="start-num" aria-hidden="true">03</span>
          <strong className="start-title">Capturar tráfico</strong>
          <p className="start-text">
            Abrí el panel de arriba, elegí tu interfaz de red (Wi-Fi o Ethernet) y empezá. Requiere
            ejecutar como administrador.
          </p>
        </li>
      </ol>

      <h3 className="start-sub">Qué vas a encontrar</h3>
      <ul className="start-features">
        {FEATURES.map((f) => {
          const Icon = f.icon;
          return (
            <li key={f.title} className="start-feature">
              <ThemeIcon size="lg" radius="md" variant="light" color={f.color} aria-hidden="true">
                <Icon size={20} />
              </ThemeIcon>
              <div>
                <strong>{f.title}</strong>
                <p>{f.text}</p>
                {f.icon === IconNetwork && onOpenSupport && (
                  <button type="button" className="link" onClick={onOpenSupport}>Abrir soporte de red</button>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      <p className="start-note">El análisis es local: las capturas no salen de tu equipo.</p>
    </section>
  );
}
