import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`), sessionPackets: vi.fn(), packet: vi.fn(), stream: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionDetail from "./SessionDetail.jsx";

const session = { id: 7, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80, packets: 3, bytes: 4096 };

beforeEach(() => {
  vi.clearAllMocks();
  api.sessionPackets.mockResolvedValue({ items: [], has_more: false });
  api.stream.mockResolvedValue({
    chunks: [{ from: "origen", bytes: 3, text: "hey" }], origin_bytes: 3, destination_bytes: 0, encrypted: false, truncated: false,
  });
});

const renderIt = (s = session) => render(<SessionDetail session={s} onClose={() => {}} onError={() => {}} />);

describe("SessionDetail: conversación (StreamView)", () => {
  it("aparece después del formulario de nota y no pide nada hasta el clic", async () => {
    renderIt();
    const note = await screen.findByLabelText("Nota del analista");
    const btn = screen.getByRole("button", { name: "Ver la conversación" });
    expect(note.compareDocumentPosition(btn) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(api.stream).not.toHaveBeenCalled();
    await userEvent.click(btn);
    expect(await screen.findByText("→ Origen · 3 B")).toBeInTheDocument();
    expect(api.stream).toHaveBeenCalledWith(7);
  });

  it("una sesión UDP no muestra la sección", async () => {
    renderIt({ ...session, protocol: "UDP" });
    await screen.findByLabelText("Nota del analista");
    expect(screen.queryByRole("heading", { name: /^Conversación/ })).toBeNull();
  });

  it("con `api.stream` ausente (mock viejo) la vista no se rompe hasta el clic", async () => {
    delete api.stream;
    renderIt();
    expect(await screen.findByRole("button", { name: "Ver la conversación" })).toBeInTheDocument();
  });
});
