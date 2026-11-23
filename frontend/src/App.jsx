import { useCallback, useState } from "react";
import { AppShell, Badge, Burger, Group, Menu, NavLink, SegmentedControl, Text, useMantineColorScheme } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconActivity, IconAlertTriangle, IconCheck, IconCpu, IconFile, IconLayoutDashboard, IconListDetails, IconNetwork,
  IconHistory, IconPalette, IconRulerMeasure, IconPlugConnected, IconShieldSearch, IconTopologyStar3, IconWorldWww,
} from "@tabler/icons-react";
import { PALETTES } from "./theme.js";
import CapturesView from "./views/CapturesView.jsx";
import SupportView, { GROUPS } from "./views/SupportView.jsx";

// Secciones de «Capturas» en la barra lateral: cada una muestra solo sus tarjetas (antes era una página larguísima).
export const CAPTURE_SECTIONS = [
  { id: "panorama", label: "Panorama", icon: IconLayoutDashboard },
  { id: "alertas", label: "Alertas y ATT&CK", icon: IconAlertTriangle },
  { id: "equipos", label: "Equipos", icon: IconTopologyStar3 },
  { id: "trafico", label: "DNS y HTTP", icon: IconWorldWww },
  { id: "remoto", label: "Acceso remoto", icon: IconPlugConnected },
  { id: "cronologia", label: "Cronología del caso", icon: IconHistory },
  { id: "sesiones", label: "Sesiones", icon: IconListDetails },
  { id: "indicadores", label: "Indicadores (IOC)", icon: IconShieldSearch },
  { id: "reglas", label: "Reglas", icon: IconRulerMeasure },
];
const GROUP_ICON = { sistema: IconCpu, red: IconNetwork };

// Selector de apariencia: paleta de color y modo claro/oscuro/automático.
function ThemeMenu({ palette, onPalette }) {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  return (
    <Menu shadow="md" width={240} position="bottom-end" withinPortal>
      <Menu.Target>
        <button type="button" className="theme-btn" aria-label="Cambiar la apariencia">
          <IconPalette size={18} />
          <span>Apariencia</span>
        </button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Paleta</Menu.Label>
        {PALETTES.map((p) => (
          <Menu.Item
            key={p.id}
            onClick={() => onPalette?.(p.id)}
            leftSection={<span className="swatch" style={{ background: p.swatch }} />}
            rightSection={palette === p.id ? <IconCheck size={14} /> : null}
          >
            {p.label}
          </Menu.Item>
        ))}
        <Menu.Divider />
        <Menu.Label>Modo</Menu.Label>
        <div className="scheme-pick">
          <SegmentedControl
            size="xs"
            fullWidth
            value={colorScheme}
            onChange={setColorScheme}
            data={[
              { value: "auto", label: "Auto" },
              { value: "light", label: "Claro" },
              { value: "dark", label: "Oscuro" },
            ]}
          />
        </div>
      </Menu.Dropdown>
    </Menu>
  );
}

// Marco de la aplicación: cabecera + barra lateral + contenido. «Capturas» y «Soporte de red» quedan montadas una vez
// abiertas (solo se ocultan), así cambiar de una a otra no pierde el análisis cargado ni lo que se estaba mirando.
export default function App({ palette = "esmeralda", onPalette }) {
  const [opened, { toggle, close }] = useDisclosure(false); // menú en pantallas chicas (se abre encima)
  const [desktopOpened, { toggle: toggleDesktop }] = useDisclosure(true); // en pantallas grandes se puede ocultar para ganar ancho
  const [area, setArea] = useState("capturas");
  const [section, setSection] = useState("panorama");
  const [support, setSupport] = useState({ group: "sistema", section: "resumen" });
  const [supportOpened, setSupportOpened] = useState(false);
  const [meta, setMeta] = useState(null); // resumen de la captura cargada, para la cabecera y las insignias

  const goCapture = useCallback((id) => {
    setArea("capturas");
    setSection(id);
    close();
  }, [close]);
  const goSupport = (group, id) => {
    setArea("soporte");
    setSupportOpened(true);
    setSupport({ group, section: id });
    close();
  };

  return (
    <AppShell
      header={{ height: 52 }}
      navbar={{ width: 236, breakpoint: "sm", collapsed: { mobile: !opened, desktop: !desktopOpened } }}
      padding={0}
      className="shell"
    >
      <AppShell.Header className="app-header">
        <Group h="100%" px="md" gap="sm" wrap="nowrap">
          <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" aria-label="Abrir o cerrar el menú" aria-expanded={opened} />
          <Burger opened={desktopOpened} onClick={toggleDesktop} visibleFrom="sm" size="sm" aria-label="Mostrar u ocultar el menú lateral" aria-expanded={desktopOpened} />
          <h1 className="brand">
            <IconActivity size={20} stroke={2.2} aria-hidden="true" />
            Tracewell
          </h1>
          {meta && (
            <span className="file-chip" title={meta.source}>
              <IconFile size={14} aria-hidden="true" />
              {meta.source} · {meta.stats?.packets?.toLocaleString("es-AR") ?? "—"} paquetes
            </span>
          )}
          <span style={{ flex: 1 }} />
          <ThemeMenu palette={palette} onPalette={onPalette} />
        </Group>
      </AppShell.Header>

      <AppShell.Navbar className="app-nav" aria-label="Secciones de Tracewell">
        <nav className="nav-scroll">
          <Text className="nav-title">Capturas</Text>
          {CAPTURE_SECTIONS.map((s) => {
            const Icon = s.icon;
            const active = area === "capturas" && section === s.id;
            return (
              <NavLink
                key={s.id}
                component="button"
                type="button"
                label={s.label}
                active={active}
                aria-current={active ? "page" : undefined}
                leftSection={<Icon size={18} stroke={1.8} />}
                rightSection={s.id === "alertas" && meta?.alerts > 0 ? <Badge size="sm" color="orange" circle>{meta.alerts}</Badge> : null}
                onClick={() => goCapture(s.id)}
              />
            );
          })}
          <Text className="nav-title">Soporte de red</Text>
          {GROUPS.map((g) => {
            const Icon = GROUP_ICON[g.id] ?? IconNetwork;
            return (
              <NavLink
                key={g.id}
                component="button"
                type="button"
                label={g.label}
                leftSection={<Icon size={18} stroke={1.8} />}
                defaultOpened={g.id === "sistema"}
                childrenOffset={14}
              >
                {g.sections.map((s) => {
                  const active = area === "soporte" && support.group === g.id && support.section === s.id;
                  return (
                    <NavLink
                      key={s.id}
                      component="button"
                      type="button"
                      label={s.label}
                      active={active}
                      aria-current={active ? "page" : undefined}
                      onClick={() => goSupport(g.id, s.id)}
                    />
                  );
                })}
              </NavLink>
            );
          })}
        </nav>
      </AppShell.Navbar>

      <AppShell.Main className="app-main">
        <div hidden={area !== "capturas"}>
          <CapturesView section={section} onNavigate={goCapture} onCapture={setMeta} onOpenSupport={() => goSupport("sistema", "resumen")} />
        </div>
        {supportOpened && (
          <div hidden={area !== "soporte"}>
            <SupportView active={area === "soporte"} group={support.group} section={support.section} />
          </div>
        )}
      </AppShell.Main>
    </AppShell>
  );
}
