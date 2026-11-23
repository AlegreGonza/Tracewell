# Documentación de `frontend/src/components/common`

Notas completas movidas desde el código. En los archivos quedan solo comentarios cortos.


## ErrorBoundary.jsx

- `<archivo>`: Un error al RENDERIZAR (un dato inesperado de la API, un bug) desmonta todo el árbol de React y deja la pantalla en blanco. Un Error Boundary lo atrapa y muestra un aviso. Tiene que ser una clase: React no ofrece equivalente con hooks. No atrapa errores de eventos ni de código asíncrono: esos se manejan con try/catch en cada handler. Ver react.dev/reference/react/Component

## ErrorBoundary.test.jsx

- `mockReload`: React reporta el error del handler al window; lo absorbemos para que no falle la corrida.

## Glossary.jsx

- `Glossary`: Glosario con buscador: las palabras que asustan, explicadas sin vueltas. Contenido fijo de help.js.

## HelpTip.jsx

- `HelpTip`: Botón «?» que despliega una explicación en lenguaje simple. El contenido sale de help.js: texto fijo, nunca datos de la captura.

## HelpTip.test.jsx

- `<archivo>`: Posible bug de producción: HELP[topic] busca también en Object.prototype ("constructor", "toString"...). Hoy ningún componente pasa esos nombres; si se corrige (Object.hasOwn), quitar el `.fails`.
