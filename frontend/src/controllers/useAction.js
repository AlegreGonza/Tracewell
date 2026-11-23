import { useCallback, useEffect, useRef, useState } from "react";

// Ejecuta una acción a pedido (un botón), no al abrir la pantalla
export function useAction(fn) {
  const [state, setState] = useState({ loading: false, result: null, error: null });
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn; // React: no se escribe un ref durante el render
  });
  const ctlRef = useRef(null);

  const run = useCallback(async (...args) => {
    ctlRef.current?.abort();
    const ctl = new AbortController();
    ctlRef.current = ctl;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const result = await fnRef.current(...args, ctl.signal);
      if (ctlRef.current === ctl) setState({ loading: false, result, error: null });
      return result;
    } catch (e) {
      if (e.name !== "AbortError" && ctlRef.current === ctl) setState((s) => ({ ...s, loading: false, error: e.message }));
      return null;
    }
  }, []);

  const reset = useCallback(() => {
    ctlRef.current?.abort();
    setState({ loading: false, result: null, error: null });
  }, []);

  useEffect(() => () => ctlRef.current?.abort(), []);
  return { ...state, run, reset };
}
