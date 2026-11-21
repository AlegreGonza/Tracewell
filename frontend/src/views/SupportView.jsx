import { useState } from "react";
import { Tabs } from "@mantine/core";
import { ServicesView, StartupView } from "../components/support/AutostartViews.jsx";
import DevicesView from "../components/support/DevicesView.jsx";
import InternetCheckView from "../components/support/InternetCheckView.jsx";
import LatencyView from "../components/support/LatencyView.jsx";
import MonitorView from "../components/support/MonitorView.jsx";
import NetConfigView from "../components/support/NetConfigView.jsx";
import { ConnectionsView, PortsView } from "../components/support/NetworkViews.jsx";
import ProcessesView from "../components/support/ProcessesView.jsx";
import SystemOverview from "../components/support/SystemOverview.jsx";
import ToolsView from "../components/support/ToolsView.jsx";
import WifiView from "../components/support/WifiView.jsx";

// Dos grupos: «Sistema» (qué corre en este equipo) y «Red» (pruebas de red). Solo se monta la sección elegida;
// cada una pide sus datos al abrirse.
export const GROUPS = [
  {
    id: "sistema",
    label: "Sistema",
    note: "Todo lo que se ve acá es de solo lectura: Tracewell mira tu equipo, no cambia ni termina nada. Algunos datos de procesos del sistema requieren abrirlo como administrador.",
    sections: [
      { id: "resumen", label: "Resumen", Component: SystemOverview },
      { id: "procesos", label: "Procesos", Component: ProcessesView },
      { id: "puertos", label: "Puertos abiertos", Component: PortsView },
      { id: "conexiones", label: "Conexiones", Component: ConnectionsView },
      { id: "servicios", label: "Servicios", Component: ServicesView },
      { id: "inicio", label: "Programas de inicio", Component: StartupView },
    ],
  },
  {
    id: "red",
    label: "Red",
    note: "Pruebas de solo lectura: miden y explican, nunca cambian la configuración. Las que salen a la red las pedís vos con un botón y cada una dice a quién se contacta. Si detectan un problema, te muestran el comando por si querés ejecutarlo vos.",
    sections: [
      { id: "config", label: "Configuración", Component: NetConfigView },
      { id: "internet", label: "¿Hay Internet?", Component: InternetCheckView },
      { id: "latencia", label: "Latencia", Component: LatencyView },
      { id: "dispositivos", label: "Dispositivos", Component: DevicesView },
      { id: "wifi", label: "Wi-Fi", Component: WifiView },
      { id: "monitoreo", label: "Monitoreo de cortes", Component: MonitorView },
      { id: "herramientas", label: "Herramientas", Component: ToolsView },
    ],
  },
];

// Soporte de red: herramientas de SOLO LECTURA sobre el equipo («Sistema») y la red («Red»).
// Con `group` y `section` (los elige la barra lateral de la aplicación) la pantalla es «controlada»: sin pestañas propias.
// Sin ellos (uso suelto) se maneja sola con pestañas.
export default function SupportApp({ active = true, group: groupProp, section: sectionProp }) {
  const controlled = groupProp !== undefined;
  const [groupId, setGroupId] = useState("sistema");
  const [sections, setSections] = useState({ sistema: "resumen", red: "config" });
  const group = GROUPS.find((g) => g.id === (controlled ? groupProp : groupId)) ?? GROUPS[0];
  const wanted = controlled ? sectionProp : sections[group.id];
  const current = group.sections.find((s) => s.id === wanted) ?? group.sections[0];
  const { Component } = current;

  return (
    <div className="support">
      <header className="support-head">
        <h1>
          Soporte de red{controlled && <span className="muted"> · {group.label} · {current.label}</span>}
        </h1>
        {!controlled && (
          <Tabs value={group.id} onChange={(id) => id && setGroupId(id)} variant="pills" radius="sm" className="support-groups">
            <Tabs.List aria-label="Áreas de soporte">
              {GROUPS.map((g) => (
                <Tabs.Tab key={g.id} value={g.id}>{g.label}</Tabs.Tab>
              ))}
            </Tabs.List>
          </Tabs>
        )}
        <p className="muted">{group.note}</p>
        {!controlled && (
          <Tabs
            value={current.id}
            onChange={(id) => id && setSections((prev) => ({ ...prev, [group.id]: id }))}
            variant="default"
            className="support-tabs"
          >
            <Tabs.List aria-label={`Secciones de ${group.label}`}>
              {group.sections.map((s) => (
                <Tabs.Tab key={s.id} value={s.id}>{s.label}</Tabs.Tab>
              ))}
            </Tabs.List>
          </Tabs>
        )}
      </header>
      <main className="support-body">
        <Component key={`${group.id}-${current.id}`} active={active} />
      </main>
    </div>
  );
}
