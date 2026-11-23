import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("../api/client.js", () => ({
  api: {
    rules: vi.fn(), previewRule: vi.fn(), saveRule: vi.fn(),
    capture: vi.fn(), iocs: vi.fn(), interfaces: vi.fn(), liveStatus: vi.fn(),
    exportUrl: vi.fn(() => "/api/export"), reportUrl: vi.fn(() => "/api/report"),
  },
}));
import { api } from "../api/client.js";
import CapturesView from "./CapturesView.jsx";

beforeEach(() => {
  vi.clearAllMocks();
  api.rules.mockResolvedValue({ items: [], example: null });
  api.capture.mockRejectedValue(Object.assign(new Error("409"), { status: 409 }));
  api.liveStatus.mockResolvedValue({ state: "idle" });
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue({ loaded: false });
});

describe("CapturesView · sección Reglas", () => {
  it("muestra el panel de reglas aunque no haya una captura cargada", async () => {
    render(<CapturesView section="reglas" />);
    expect(await screen.findByRole("heading", { name: "Crear una alerta nueva" })).toBeInTheDocument();
    expect(screen.queryByText(/Todavía no hay una captura cargada/)).toBeNull();
  });
});
