import { useState } from "react";

// Salta (con scroll suave) a una sección de la pantalla por su id
export const jumpTo = (id) => document.getElementById(id)?.scrollIntoView?.({ behavior: "smooth", block: "start" });

// Los pasos del caso del demo
export const STEPS = [
  {
    title: "Mirá el panorama",
    text: "Arriba tenés el Resumen: 32 sesiones y 45 paquetes. El gráfico muestra cuándo hubo tráfico y la tabla de Equipos, quién habló con quién. Tocá los «?» de cada sección para que te explique qué estás viendo.",
    action: { label: "Ir al resumen", jump: "summary-title", section: "panorama" },
  },
  {
    title: "Alertas: ¿qué encontró Tracewell?",
    text: "Hay 3 alertas. Abrí «Escaneo de puertos»: la IP 192.168.1.66 mandó un SYN a 25 puertos de 192.168.1.5 en una fracción de segundo. Es alguien «tocando todas las puertas» para ver cuáles están abiertas. En el mapa ATT&CK se ilumina la táctica Exploración.",
    action: { label: "Ir a las alertas", jump: "alerts-title", section: "alertas" },
  },
  {
    title: "Mirá un escaneo en la tabla de sesiones",
    text: "Filtrá por 192.168.1.66: son decenas de sesiones de 1 solo paquete de 54 bytes. Abrí una y leé «En palabras simples»: «Intentó conectarse y nadie respondió». Un paquete, sin saludo, sin respuesta: esa es la cara de un escaneo.",
    action: { label: "Filtrar por 192.168.1.66", ip: "192.168.1.66" },
  },
  {
    title: "Encontrá una contraseña en claro",
    text: "Filtrá por 192.168.1.20, abrí la sesión al puerto 21 (FTP) y tocá «Ver la conversación». Vas a leer el diálogo completo, incluido «PASS hunter2». FTP no cifra nada: cualquiera en la red puede ver esa contraseña.",
    action: { label: "Filtrar por 192.168.1.20", ip: "192.168.1.20" },
  },
  {
    title: "Leé una petición HTTP",
    text: "En «HTTP sin cifrar» vas a ver un GET a www.example.com con su respuesta 200. Si la respuesta trae un archivo, Tracewell calcula su huella SHA-256 y reconoce qué es realmente por sus primeros bytes.",
    action: { label: "Ir a HTTP", jump: "httpall-title", section: "trafico" },
  },
  {
    title: "Un nombre DNS que no cierra",
    text: "En la tabla de DNS aparece un nombre larguísimo y aleatorio terminado en evil-c2.example, sin respuesta. Es lo que haría un malware que busca su servidor de control. Tracewell lo marca con una pista.",
    action: { label: "Ir a DNS", jump: "dns-title", section: "trafico" },
  },
  {
    title: "Decidí como un analista",
    text: "Escaneo desde 192.168.1.66: investigar ese equipo y bloquearlo. Contraseña FTP en claro: cambiarla y migrar a un servicio cifrado. Nombre DNS sospechoso: bloquear el dominio y buscar qué programa lo pidió. Anotalo en la nota de cada sesión y generá el Informe HTML.",
  },
];

// Recorrido guiado del demo: siete pasos para aprender a investigar
export default function GuidedCase({ onFilterIp, onJump }) {
  const [open, setOpen] = useState(true);
  const [done, setDone] = useState(() => new Set());
  const toggle = (i) =>
    setDone((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });

  return (
    <section className="card guided" aria-labelledby="guided-title">
      <div className="card-head">
        <h2 id="guided-title">Caso guiado: investigá este demo</h2>
        <span className="muted">{done.size} de {STEPS.length} pasos</span>
        <button type="button" className="link" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? "Ocultar" : "Mostrar"}
        </button>
      </div>
      {open && (
        <ol className="guided-steps">
          {STEPS.map((s, i) => (
            <li key={s.title} className={done.has(i) ? "done" : ""}>
              <label className="inline">
                <input type="checkbox" checked={done.has(i)} onChange={() => toggle(i)} />
                <strong>{s.title}</strong>
              </label>
              <p>{s.text}</p>
              {s.action && (
                <button type="button" onClick={() => (s.action.ip ? onFilterIp?.(s.action.ip) : onJump ? onJump(s.action.section, s.action.jump) : jumpTo(s.action.jump))}>
                  {s.action.label}
                </button>
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
