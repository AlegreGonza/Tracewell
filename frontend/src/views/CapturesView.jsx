import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client.js";
import Toolbar from "../components/captures/Toolbar.jsx";
import ErrorBanner from "../components/common/ErrorBanner.jsx";
import LivePanel from "../components/captures/LivePanel.jsx";
import Summary from "../components/captures/Summary.jsx";
import AlertsTable from "../components/captures/AlertsTable.jsx";
import SessionsTable from "../components/captures/SessionsTable.jsx";
import SessionDetail from "../components/captures/SessionDetail.jsx";
import IocPanel from "../components/captures/IocPanel.jsx";
import Timeline from "../components/captures/Timeline.jsx";
import AttackMap from "../components/captures/AttackMap.jsx";
import RiskCard from "../components/captures/RiskCard.jsx";
import TopTalkers from "../components/captures/TopTalkers.jsx";
import HostsView from "../components/captures/HostsView.jsx";
import MacGroups from "../components/captures/MacGroups.jsx";
import DnsView from "../components/captures/DnsView.jsx";
import HttpView from "../components/captures/HttpView.jsx";
import CaseTimeline from "../components/captures/CaseTimeline.jsx";
import RemoteAccessView from "../components/captures/RemoteAccessView.jsx";
import Glossary from "../components/common/Glossary.jsx";
import GuidedCase from "../components/captures/GuidedCase.jsx";
import EmptySection from "../components/captures/EmptySection.jsx";
import Welcome from "../components/captures/Welcome.jsx";

const NO_FILTERS = { protocol: "", ip: "", port: "" };

// `section` elige qué tarjetas se ven («all» = todas, el uso de siempre; la barra lateral pasa una por vez).
// `onNavigate` cambia de sección (p. ej. desde una alerta a las sesiones), `onCapture` avisa qué captura hay cargada.
export default function App({ section = "all", onNavigate, onCapture, onOpenSupport } = {}) {
  const show = (name) => section === "all" || section === name;
  const [capture, setCapture] = useState(null); // resumen del análisis actual
  const [version, setVersion] = useState(0); // sube con cada análisis nuevo: obliga a recargar las tablas
  const [filters, setFilters] = useState(NO_FILTERS);
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [triageVersion, setTriageVersion] = useState(0); // sube al guardar una nota o cambiar los IOC
  const [showGlossary, setShowGlossary] = useState(false);

  useEffect(() => {
    onCapture?.(capture);
  }, [capture, onCapture]);

  const fail = useCallback((msg) => setError(msg), []);
  const refreshTriage = useCallback(() => setTriageVersion((v) => v + 1), []);

  // Descarta el análisis (también en el servidor, para que recargar la página no lo traiga de vuelta) y vuelve al inicio.
  async function closeAnalysis() {
    setBusy(true);
    try {
      await api.closeCapture();
      setCapture(null);
      setFilters(NO_FILTERS);
      setSelected(null);
      setError(null);
      setVersion((v) => v + 1);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  // Filtra la tabla de sesiones por una IP (desde el gráfico de equipos o la tabla de HTTP) y baja hasta ella.
  const filterByIp = useCallback((ip) => {
    setFilters({ protocol: "", ip, port: "" });
    setSelected(null);
    onNavigate?.("sesiones");
    setTimeout(() => document.getElementById("sessions-title")?.scrollIntoView?.({ behavior: "smooth", block: "start" }), 0);
  }, []);

  // Desde una alerta: filtra la tabla por la IP de origen y baja hasta ella.
  const viewSessions = useCallback((alert) => {
    setFilters({ protocol: "", ip: alert.src_ip, port: "" });
    setSelected(null);
    onNavigate?.("sesiones");
    setTimeout(() => document.getElementById("sessions-title")?.scrollIntoView?.({ behavior: "smooth", block: "start" }), 0);
  }, []);

  // Un análisis nuevo reemplaza al anterior: se limpian filtros y selección,
  // que podrían apuntar a sesiones que ya no existen.
  const adopt = useCallback((summary) => {
    setCapture(summary);
    setFilters(NO_FILTERS);
    setSelected(null);
    setVersion((v) => v + 1);
  }, []);

  async function run(action) {
    setBusy(true);
    setError(null);
    try {
      adopt(await action());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  // Si el servidor ya tiene un análisis (p. ej. se recargó la página), lo
  // retomamos. Un 409 significa "todavía no hay nada": es el caso normal.
  useEffect(() => {
    const ctl = new AbortController();
    api
      .capture(ctl.signal)
      .then(adopt)
      .catch((e) => {
        if (e.name !== "AbortError" && e.status !== 409) setError(e.message);
      });
    return () => ctl.abort();
  }, [adopt]);

  // Solo se exportan filtros con valor; el puerto vacío no viaja.
  const activeFilters = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== ""));

  return (
    <div className="app">
      <Toolbar
        busy={busy}
        loaded={capture !== null}
        filters={activeFilters}
        onDemo={() => run(api.demo)}
        onAnalyze={(path) => run(() => api.analyze(path))}
        onError={fail}
        onGlossary={() => setShowGlossary((v) => !v)}
        onClose={closeAnalysis}
        closeLabel={capture?.source === "demo.pcap" ? "Salir del demo" : "Cerrar captura"}
      />
      <main>
        <ErrorBanner error={error} onClose={() => setError(null)} />
        {showGlossary && <Glossary onClose={() => setShowGlossary(false)} />}

        {busy && (
          <p role="status" className="banner banner-info">
            Analizando la captura…
          </p>
        )}

        {capture === null && !busy ? (
          section === "all" || section === "panorama" ? (
            <Welcome onDemo={() => run(api.demo)} onOpenSupport={onOpenSupport} />
          ) : (
            <EmptySection section={section} onDemo={() => run(api.demo)} onHome={() => onNavigate?.("panorama")} />
          )
        ) : (
          capture && (
            <div className={selected && show("sesiones") ? "layout with-detail" : "layout"}>
              <div className="col">
                {show("panorama") && <Summary capture={capture} />}
                {show("panorama") && <Timeline refreshKey={version} onError={fail} />}
                {show("panorama") && (
                  <div className="panorama-grid">
                    <RiskCard refreshKey={version} onError={fail} />
                    <TopTalkers refreshKey={version} onError={fail} onFilterIp={filterByIp} />
                  </div>
                )}
                {show("panorama") && capture.source === "demo.pcap" && <GuidedCase onFilterIp={filterByIp} onJump={onNavigate ? (sec, id) => { onNavigate(sec); setTimeout(() => document.getElementById(id)?.scrollIntoView?.({ behavior: "smooth", block: "start" }), 60); } : undefined} />}
                {show("alertas") && <AlertsTable refreshKey={version} onError={fail} onViewSessions={viewSessions} />}
                {show("alertas") && <AttackMap refreshKey={version} onError={fail} />}
                {show("equipos") && <HostsView refreshKey={version} onError={fail} onFilterIp={filterByIp} />}
                {show("equipos") && <MacGroups refreshKey={version} onError={fail} onFilterIp={filterByIp} />}
                {show("trafico") && <DnsView refreshKey={version} onError={fail} />}
                {show("trafico") && <HttpView refreshKey={version} onError={fail} onFilterIp={filterByIp} />}
                {show("remoto") && <RemoteAccessView refreshKey={version} onError={fail} onFilterIp={filterByIp} />}
                {show("cronologia") && <CaseTimeline refreshKey={version} triageVersion={triageVersion} onError={fail} onFilterIp={filterByIp} />}
                {show("indicadores") && <IocPanel refreshKey={version} onChange={refreshTriage} onError={fail} />}
                {show("sesiones") && (
                <SessionsTable
                  refreshKey={version}
                  triageVersion={triageVersion}
                  filters={filters}
                  onFilters={setFilters}
                  selectedId={selected?.id ?? null}
                  onSelect={setSelected}
                  showProcess={capture.processes === true}
                />
                )}
              </div>
              {selected && show("sesiones") && (
                <SessionDetail
                  session={selected}
                  onClose={() => setSelected(null)}
                  onError={fail}
                  onNoteSaved={(updated) => {
                    setSelected(updated);
                    refreshTriage();
                  }}
                />
              )}
            </div>
          )
        )}
      </main>
      {/* Barra inferior fija: así la captura en vivo no le quita espacio al análisis. */}
      <LivePanel
        disabled={busy}
        onError={fail}
        onAnalyzed={(summary) => {
          setError(null);
          adopt(summary);
        }}
      />
    </div>
  );
}
