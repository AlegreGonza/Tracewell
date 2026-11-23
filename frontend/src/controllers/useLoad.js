import { useCallback, useEffect, useRef, useState } from "react";

// Carga datos con `fetcher(signal)` al montar y cada vez que se llama a `reload()`
export function useLoad(fetcher, { every = 0, active = true, deps = [] } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null); // cuándo llegaron los últimos datos
  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher; // React: no se escribe un ref durante el render
  });
  const ctlRef = useRef(null);

  const reload = useCallback(() => {
    ctlRef.current?.abort();
    const ctl = new AbortController();
    ctlRef.current = ctl;
    setLoading(true);
    fetcherRef
      .current(ctl.signal)
      .then((d) => {
        if (ctlRef.current !== ctl) return; // llegó tarde: ya hay una carga más nueva
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
  useEffect(() => {
    reload();
    return () => ctlRef.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, ...deps]);

  useEffect(() => {
    if (!every || !active) return undefined;
    const id = setInterval(reload, every);
    return () => clearInterval(id);
  }, [every, active, reload]);

  return { data, error, loading, reload, updatedAt };
}
