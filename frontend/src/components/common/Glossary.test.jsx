import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Glossary from "./Glossary.jsx";
import { GLOSSARY } from "../../lib/help.js";

const show = (onClose = vi.fn()) => {
  render(<Glossary onClose={onClose} />);
  return { onClose, box: screen.getByLabelText("Buscar en el glosario") };
};
const terms = () => screen.queryAllByRole("term").map((t) => t.textContent);

describe("Glossary", () => {
  it("muestra todos los términos al inicio", () => {
    show();
    expect(screen.getByRole("heading", { name: "Glosario" })).toBeInTheDocument();
    expect(terms()).toEqual(GLOSSARY.map(([t]) => t));
    expect(screen.queryByText("Ningún término coincide.")).toBeNull();
  });

  it("filtra por término sin distinguir mayúsculas", async () => {
    const { box } = show();
    await userEvent.type(box, "ttl");
    expect(terms()).toContain("TTL");
    expect(terms().length).toBeLessThan(GLOSSARY.length);
    await userEvent.clear(box);
    await userEvent.type(box, "TTL");
    expect(terms()).toContain("TTL");
  });

  it("filtra también por el texto de la explicación", async () => {
    const { box } = show();
    await userEvent.type(box, "agenda");
    expect(terms()).toContain("DNS"); // «la agenda de internet»
    expect(terms()).not.toContain("TTL");
  });

  it("ignora espacios alrededor de la búsqueda", async () => {
    const { box } = show();
    await userEvent.type(box, "   ttl  ");
    expect(terms()).toContain("TTL");
  });

  it("solo espacios equivale a no filtrar", async () => {
    const { box } = show();
    await userEvent.type(box, "    ");
    expect(terms()).toHaveLength(GLOSSARY.length);
  });

  it("sin coincidencias: 'Ningún término coincide.' y ninguna lista", async () => {
    const { box } = show();
    await userEvent.type(box, "zzzz-no-existe");
    expect(screen.getByText("Ningún término coincide.")).toBeInTheDocument();
    expect(terms()).toEqual([]);
  });

  it("borrar la búsqueda restaura la lista", async () => {
    const { box } = show();
    await userEvent.type(box, "zzzz");
    await userEvent.clear(box);
    expect(terms()).toHaveLength(GLOSSARY.length);
  });

  it("caracteres especiales de regex no rompen la búsqueda", async () => {
    const { box } = show();
    fireEvent.change(box, { target: { value: "(.*[" } });
    expect(screen.getByText("Ningún término coincide.")).toBeInTheDocument();
  });

  it("buscar texto con HTML no crea elementos", async () => {
    const { box } = show();
    await userEvent.type(box, "<img src=x onerror=alert(1)>");
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("Ningún término coincide.")).toBeInTheDocument();
  });

  it("'Cerrar' llama a onClose", async () => {
    const { onClose } = show();
    await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("cada término se muestra con su explicación", () => {
    show();
    const dts = screen.getAllByRole("term");
    const [term, text] = GLOSSARY[0];
    expect(dts[0]).toHaveTextContent(term);
    expect(dts[0].nextElementSibling).toHaveTextContent(text);
  });
});
