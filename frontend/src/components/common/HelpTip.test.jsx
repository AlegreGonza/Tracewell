import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import HelpTip from "./HelpTip.jsx";
import { HELP } from "../../lib/help.js";

describe("HelpTip", () => {
  it("un tema desconocido no renderiza nada", () => {
    for (const topic of ["no-existe", "", undefined, null, 42]) {
      const { container, unmount } = render(<HelpTip topic={topic} />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });

  // Posible bug de producción: HELP[topic] busca también en Object.prototype ("constructor", "toString"...).
  // Hoy ningún componente pasa esos nombres; si se corrige (Object.hasOwn), quitar el `.fails`.
  it("temas heredados de Object.prototype tampoco deberían renderizar un botón", () => {
    const { container } = render(<HelpTip topic="constructor" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("botón con aria-label 'Ayuda: <título>', cerrado al inicio", () => {
    render(<HelpTip topic="resumen" />);
    const b = screen.getByRole("button", { name: `Ayuda: ${HELP.resumen.title}` });
    expect(b).toHaveClass("help-btn");
    expect(b).toHaveAttribute("type", "button");
    expect(b).toHaveAttribute("aria-expanded", "false");
    expect(b).toHaveAttribute("aria-controls");
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("un clic abre una nota con el texto (sin 'En Wireshark'); otro clic la cierra", async () => {
    render(<HelpTip topic="resumen" />);
    const b = screen.getByRole("button");
    await userEvent.click(b);
    const note = screen.getByRole("note");
    expect(note).toHaveTextContent(HELP.resumen.text);
    expect(note).not.toHaveTextContent("En Wireshark");
    expect(b).toHaveAttribute("aria-expanded", "true");
    expect(note.id).toBe(b.getAttribute("aria-controls"));
    await userEvent.click(b);
    expect(screen.queryByRole("note")).toBeNull();
    expect(b).toHaveAttribute("aria-expanded", "false");
  });

  it("se puede operar con el teclado", async () => {
    render(<HelpTip topic="tiempo" />);
    await userEvent.tab();
    expect(screen.getByRole("button")).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(screen.getByRole("note")).toBeInTheDocument();
    await userEvent.keyboard(" ");
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("cada tema de help.js se abre y muestra su texto", async () => {
    for (const [id, h] of Object.entries(HELP)) {
      const { unmount } = render(<HelpTip topic={id} />);
      await userEvent.click(screen.getByRole("button", { name: `Ayuda: ${h.title}` }));
      expect(screen.getByRole("note")).toHaveTextContent(h.text);
      unmount();
    }
  });

  it("ningún tema tiene la clave `wireshark` ni su nota dice 'En Wireshark'", async () => {
    for (const [id, h] of Object.entries(HELP)) {
      expect("wireshark" in h, id).toBe(false);
      const { unmount } = render(<HelpTip topic={id} />);
      await userEvent.click(screen.getByRole("button", { name: `Ayuda: ${h.title}` }));
      const note = screen.getByRole("note");
      expect(note.textContent, id).not.toMatch(/En Wireshark/);
      expect(note.textContent, id).not.toMatch(/Wireshark:/);
      expect(note).toHaveTextContent(h.text);
      unmount();
    }
  });

  it("dos ayudas en la misma pantalla tienen ids distintos y se abren por separado", async () => {
    render(
      <>
        <HelpTip topic="resumen" />
        <HelpTip topic="tiempo" />
      </>,
    );
    const [a, b] = screen.getAllByRole("button");
    expect(a.getAttribute("aria-controls")).not.toBe(b.getAttribute("aria-controls"));
    await userEvent.click(a);
    expect(screen.getAllByRole("note")).toHaveLength(1);
    expect(b).toHaveAttribute("aria-expanded", "false");
  });

  it("el texto se muestra como texto: los símbolos < > & no crean elementos", async () => {
    const { container } = render(<HelpTip topic="ioc" />);
    await userEvent.click(screen.getByRole("button"));
    expect(container.querySelector(".help-body").children).toHaveLength(1);
    expect(container.querySelector("img, script")).toBeNull();
  });
});
