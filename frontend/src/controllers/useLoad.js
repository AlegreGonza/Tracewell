import { useCallback, useEffect, useRef, useState } from "react";

// Carga datos con `fetcher(signal)` al montar y cada vez que se llama a `reload()`.
// Si `every` (ms) viene y `active` es true, recarga sola cada tanto (sin tapar la pantalla con «cargando»).
export function useLoad(fetcher, { every = 0, active = true, deps = [] } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null); // cuándo llegaron los últimos datos
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const ctlRef = useRef(null);

  const reload = useCallback(() => {
    ctlRef.current?.abort();
    const ctl = new AbortController();
    ctlRef.current = ctl;
    setLoading(true);
    fetcherRef
      .current(ctl.signal)
      .then((d) => {
        setData(d);
        setError(null);
        setUpdatedAt(new Date());
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      })
      .finally(() => {
        if (ctlRef.current === ctl) setLoading(false);
      });
  }, []);

  // `deps`: valores que, al cambiar, vuelven a pedir los datos (p. ej. el orden elegido).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    reload();
    return () => ctlRef.current?.abort();
  }, [reload, ...deps]);

  useEffect(() => {
    if (!every || !active) return undefined;
    const id = setInterval(reload, every);
    return () => clearInterval(id);
  }, [every, active, reload]);

  return { data, error, loading, reload, updatedAt };
}
