import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Welcome from "./Welcome.jsx";

describe("Welcome", () => {
  it("muestra el título y la nota de privacidad", () => {
    render(<Welcome onDemo={() => {}} />);
    expect(screen.getByRole("heading", { level: 2, name: "Empezá analizando una captura" })).toBeInTheDocument();
    expect(screen.getByText("El análisis es local: las capturas no salen de tu equipo.")).toBeInTheDocument();
  });

  it("muestra los tres pasos en orden", () => {
    render(<Welcome onDemo={() => {}} />);
    const items = Array.from(document.querySelectorAll(".start-steps > li"));
    expect(items).toHaveLength(3);
    ["Probar con un ejemplo", "Abrir un archivo", "Capturar tráfico"].forEach((t, i) =>
      expect(within(items[i]).getByText(t)).toBeInTheDocument()
    );
  });

  it("la sección está etiquetada por su título", () => {
    render(<Welcome onDemo={() => {}} />);
    const region = screen.getByRole("region", { name: "Empezá analizando una captura" });
    expect(region).toHaveAttribute("aria-labelledby", "start-title");
    expect(document.getElementById("start-title")).toHaveTextContent("Empezá analizando una captura");
  });

  it("el SVG decorativo y los números de paso están ocultos a lectores de pantalla", () => {
    const { container } = render(<Welcome onDemo={() => {}} />);
    const svgs = container.querySelectorAll("svg");
    expect(svgs.length).toBeGreaterThan(0);
    svgs.forEach((svg) => expect(svg.closest('[aria-hidden="true"]')).not.toBeNull());
    container.querySelectorAll(".start-num").forEach((n) => expect(n).toHaveAttribute("aria-hidden", "true"));
  });

  it("sin onOpenSupport hay un único botón y no duplica el nombre accesible 'Modo demo'", () => {
    render(<Welcome onDemo={() => {}} />);
    expect(screen.getAllByRole("button")).toHaveLength(1);
    expect(screen.queryByRole("button", { name: /Modo demo/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Abrir soporte de red" })).toBeNull();
    expect(screen.getByRole("button", { name: "Cargar el ejemplo" })).toHaveAttribute("type", "button");
  });

  it("«Qué vas a encontrar» muestra 4 tarjetas", () => {
    render(<Welcome onDemo={() => {}} />);
    expect(screen.getByRole("heading", { level: 3, name: "Qué vas a encontrar" })).toBeInTheDocument();
    const items = document.querySelectorAll(".start-features > li");
    expect(items).toHaveLength(4);
    ["Alertas con MITRE ATT&CK", "Equipos y conversaciones", "DNS, HTTP y TLS", "Soporte de red"].forEach((t) =>
      expect(screen.getByText(t)).toBeInTheDocument()
    );
  });

  it("cada paso y cada tarjeta traen un ícono decorativo oculto", () => {
    const { container } = render(<Welcome onDemo={() => {}} />);
    expect(container.querySelectorAll(".start-steps svg").length).toBeGreaterThanOrEqual(3);
    expect(container.querySelectorAll(".start-features svg").length).toBeGreaterThanOrEqual(4);
  });

  it("con onOpenSupport aparece «Abrir soporte de red» y lo llama una vez", async () => {
    const onOpenSupport = vi.fn();
    render(<Welcome onDemo={() => {}} onOpenSupport={onOpenSupport} />);
    expect(screen.getAllByRole("button")).toHaveLength(2);
    await userEvent.click(screen.getByRole("button", { name: "Abrir soporte de red" }));
    expect(onOpenSupport).toHaveBeenCalledTimes(1);
  });

  it("el botón llama a onDemo exactamente una vez por clic", async () => {
    const onDemo = vi.fn();
    render(<Welcome onDemo={onDemo} />);
    const btn = screen.getByRole("button", { name: "Cargar el ejemplo" });
    await userEvent.click(btn);
    expect(onDemo).toHaveBeenCalledTimes(1);
    await userEvent.click(btn);
    expect(onDemo).toHaveBeenCalledTimes(2);
  });

  it("se activa con Enter y con Espacio (una vez cada uno)", async () => {
    const onDemo = vi.fn();
    render(<Welcome onDemo={onDemo} />);
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "Cargar el ejemplo" })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(onDemo).toHaveBeenCalledTimes(1);
    await userEvent.keyboard(" ");
    expect(onDemo).toHaveBeenCalledTimes(2);
  });

  it("renderiza sin onDemo y hacer clic no rompe", async () => {
    render(<Welcome />);
    expect(screen.getByRole("region", { name: "Empezá analizando una captura" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cargar el ejemplo" }));
    expect(screen.getByRole("button", { name: "Cargar el ejemplo" })).toBeInTheDocument();
  });
});
