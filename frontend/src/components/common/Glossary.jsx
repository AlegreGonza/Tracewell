import { useState } from "react";
import { GLOSSARY } from "../../lib/help.js";

// Glosario con buscador: las palabras que asustan, explicadas sin vueltas. Contenido fijo de help.js.
export default function Glossary({ onClose }) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const items = GLOSSARY.filter(([term, text]) => !q || term.toLowerCase().includes(q) || text.toLowerCase().includes(q));
  return (
    <section className="card glossary" aria-labelledby="glossary-title">
      <div className="card-head">
        <h2 id="glossary-title">Glosario</h2>
        <button type="button" className="link" onClick={onClose}>Cerrar</button>
      </div>
      <div className="glossary-body">
        <label className="sr-only" htmlFor="glossary-search">Buscar en el glosario</label>
        <input
          id="glossary-search"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Buscar un término (por ejemplo: SYN, TTL, DNS)"
          autoComplete="off"
        />
        {items.length === 0 ? (
          <p className="empty">Ningún término coincide.</p>
        ) : (
          <dl className="glossary-list">
            {items.map(([term, text]) => (
              <div key={term}>
                <dt>{term}</dt>
                <dd>{text}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    </section>
  );
}
