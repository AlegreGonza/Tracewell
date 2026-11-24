// Un esquema zod por respuesta de la API (derivados de backend/api/routes/*.py y datos reales).
// Son tolerantes a propósito: `looseObject` conserva campos nuevos del backend y lo que puede
// faltar es opcional/nulo. Si un campo obligatorio no calza, `request()` lanza ApiSchemaError.
import { z } from 'zod'

const obj = z.looseObject
const nullishStr = z.string().nullish()
const nullishNum = z.number().nullish()

export const severitySchema = z.enum(['low', 'medium', 'high', 'critical'])
export type Severity = z.infer<typeof severitySchema>

/* ------------------------------ captura cargada ----------------------------- */

export const protocolStatsSchema = obj({
  sessions: z.number(),
  packets: z.number(),
  bytes: z.number(),
})

export const statsSchema = obj({
  sessions: z.number(),
  packets: z.number(),
  bytes: z.number(),
  by_protocol: z.record(z.string(), protocolStatsSchema),
  non_ip: z.number().optional(),
  malformed: z.number().optional(),
  truncated: z.boolean().optional(),
  untracked_packets: z.number().optional(),
})
export type Stats = z.infer<typeof statsSchema>

export const ruleSummarySchema = obj({
  id: z.string(),
  name: z.string(),
  severity: severitySchema,
})

/** Respuesta de /api/analyze, /api/demo, /api/capture y /api/live/stop. */
export const captureSchema = obj({
  source: z.string(),
  format: z.string(),
  linktype: z.number().nullish(),
  snaplen: z.number().nullish(),
  stats: statsSchema,
  alerts: z.number(),
  rules: z.array(ruleSummarySchema).default([]),
  processes: z.boolean().default(false),
})
export type Capture = z.infer<typeof captureSchema>

export const clearedSchema = obj({ cleared: z.boolean() })

/* --------------------------------- sesiones --------------------------------- */

export const sessionSchema = obj({
  id: z.number(),
  protocol: z.string(),
  src_ip: z.string(),
  src_port: nullishNum,
  dst_ip: z.string(),
  dst_port: nullishNum,
  packets: z.number(),
  bytes: z.number(),
  first_ts: z.number(),
  last_ts: z.number(),
  duration: z.number(),
  direction: nullishStr,
  host: nullishStr,
  note: nullishStr,
  reviewed: z.boolean().nullish(),
  process: obj({ pid: z.number().nullish(), name: nullishStr }).nullish(),
})
export type Session = z.infer<typeof sessionSchema>

export const sessionsPageSchema = obj({
  total: z.number(),
  items: z.array(sessionSchema),
})
export type SessionsPage = z.infer<typeof sessionsPageSchema>

export const timelineSchema = obj({
  start: z.number().nullish(),
  bucket_seconds: z.number(),
  packets: z.array(z.number()),
  bytes: z.array(z.number()),
})
export type Timeline = z.infer<typeof timelineSchema>

/* ---------------------------------- alertas --------------------------------- */

export const alertGuideSchema = obj({
  false_positives: z.array(z.string()).default([]),
  investigation_steps: z.array(z.string()).default([]),
  wireshark_filter: nullishStr,
})

export const alertSchema = obj({
  rule_id: z.string(),
  name: z.string(),
  severity: severitySchema,
  description: z.string().default(''),
  src_ip: nullishStr,
  dst_ip: nullishStr,
  first_ts: nullishNum,
  evidence: z.record(z.string(), z.unknown()).default({}),
  guide: alertGuideSchema.nullish(),
  wireshark_filter: nullishStr,
  // MITRE ATT&CK (los agrega el backend; pueden faltar en reglas sin técnica)
  mitre_technique: nullishStr,
  mitre_name: nullishStr,
  mitre_tactic: nullishStr,
})
export type Alert = z.infer<typeof alertSchema>
export const alertsSchema = z.array(alertSchema)

/* ----------------------------- equipos y conexiones ---------------------------- */

export const hostServiceSchema = obj({
  protocol: z.string(),
  port: z.number(),
  sessions: z.number(),
})

export const hostSchema = obj({
  ip: z.string(),
  kind: z.string(),
  sessions: z.number(),
  packets: z.number(),
  bytes: z.number(),
  initiated: z.number().optional(),
  received: z.number().optional(),
  peers: z.number().optional(),
  protocols: z.array(z.string()).default([]),
  services: z.array(hostServiceSchema).default([]),
  name: nullishStr,
  alerts: z.number().default(0),
  alert_rules: z.array(z.string()).default([]),
  ioc: z.array(z.unknown()).default([]),
  role: nullishStr,
  role_label: nullishStr,
  owner: nullishStr,
  note: nullishStr,
  roles: z.array(z.string()).default([]),
  mac: nullishStr,
})
export type Host = z.infer<typeof hostSchema>

export const hostsSchema = obj({
  total: z.number(),
  items: z.array(hostSchema),
})

export const macGroupSchema = obj({
  mac: z.string(),
  ips: z.array(z.string()),
  names: z.array(z.string()).default([]),
  sessions: z.number(),
  bytes: z.number(),
  shared: z.boolean().optional(),
  hint: nullishStr,
})
export const hostsByMacSchema = obj({
  total: z.number(),
  items: z.array(macGroupSchema),
})

export const graphNodeSchema = obj({
  ip: z.string(),
  kind: z.string(),
  label: z.string(),
  bytes: z.number(),
  sessions: z.number(),
  alerts: z.number().default(0),
  ioc: z.boolean().default(false),
  name: nullishStr,
  role: nullishStr,
  role_label: nullishStr,
  owner: nullishStr,
  note: nullishStr,
})
export const graphEdgeSchema = obj({
  a: z.string(),
  b: z.string(),
  bytes: z.number(),
  sessions: z.number(),
  protocols: z.array(z.string()).default([]),
})
export const graphSchema = obj({
  nodes: z.array(graphNodeSchema),
  edges: z.array(graphEdgeSchema),
  truncated: z.boolean().default(false),
})

/* ------------------------------ DNS, HTTP, remoto ----------------------------- */

export const dnsItemSchema = obj({
  name: z.string(),
  qtype: z.string(),
  queries: z.number(),
  responses: z.number(),
  rcodes: z.record(z.string(), z.number()).default({}),
  answers: z.array(z.string()).default([]),
  clients: z.array(z.string()).default([]),
  first_ts: nullishNum,
  last_ts: nullishNum,
  min_ttl: nullishNum,
  hints: z.array(z.string()).default([]),
})
export const dnsSchema = obj({
  summary: obj({
    names: z.number(),
    queries: z.number(),
    responses: z.number(),
    nxdomain: z.number().default(0),
    flagged: z.number().default(0),
    dropped: z.number().default(0),
  }),
  items: z.array(dnsItemSchema),
})

export const httpFileSchema = obj({
  direction: nullishStr,
  name: nullishStr,
  size: nullishNum,
  sha256: nullishStr,
  kind: nullishStr,
  risky: z.boolean().nullish(),
  content_type: nullishStr,
  complete: z.boolean().nullish(),
})

export const httpExchangeSchema = obj({
  index: z.number(),
  method: nullishStr,
  target: nullishStr,
  host: nullishStr,
  user_agent: nullishStr,
  auth: nullishStr,
  sensitive_fields: z.array(z.string()).default([]),
  request_bytes: nullishNum,
  request_type: nullishStr,
  status: nullishNum,
  reason: nullishStr,
  response_type: nullishStr,
  response_bytes: nullishNum,
  location: nullishStr,
  server: nullishStr,
  encoding: nullishStr,
  complete: z.boolean().nullish(),
  file: httpFileSchema.nullish(),
  truncated: z.boolean().nullish(),
})

export const httpOverviewItemSchema = httpExchangeSchema.extend({
  session_id: z.number(),
  src_ip: nullishStr,
  dst_ip: nullishStr,
  src: nullishStr,
  dst: nullishStr,
})
export const httpOverviewSchema = obj({
  scanned: z.number(),
  capped: z.boolean().default(false),
  items: z.array(httpOverviewItemSchema),
})

export const sessionHttpSchema = obj({
  exchanges: z.array(httpExchangeSchema),
  incomplete: z.boolean().default(false),
})

export const tlsSchema = obj({
  tls: z.boolean(),
  incomplete: z.boolean().optional(),
  client: obj({
    ja4: nullishStr,
    sni: nullishStr,
    alpn: nullishStr,
    ciphers: nullishNum,
    complete: z.boolean().nullish(),
  }).nullish(),
  server: obj({ version: nullishStr, cipher: nullishStr }).nullish(),
  certificate: z.record(z.string(), z.unknown()).nullish(),
  certificate_hidden: z.boolean().nullish(),
})

export const remoteItemSchema = obj({
  id: z.number(),
  service: z.string(),
  port: z.number(),
  client_ip: z.string(),
  server_ip: z.string(),
  direction: nullishStr,
  packets: z.number(),
  bytes: z.number(),
  first_ts: z.number(),
  duration: z.number(),
  syn_packets: z.number().optional(),
  syn_retries: z.number().optional(),
  rst_packets: z.number().optional(),
  signals: z.array(z.string()).default([]),
})
export const remoteAccessSchema = obj({
  total: z.number(),
  services: z.array(
    obj({
      service: z.string(),
      ports: z.array(z.number()),
      sessions: z.number(),
      clients: z.number(),
      servers: z.number(),
      with_rst: z.number().default(0),
      retries: z.number().default(0),
      bytes: z.number(),
      truncated: z.boolean().default(false),
      items: z.array(remoteItemSchema),
    })
  ),
})

export const caseTimelineSchema = obj({
  host: nullishStr,
  total: z.number(),
  truncated: z.boolean().default(false),
  items: z.array(
    obj({
      ts: z.number(),
      kind: z.string(),
      title: z.string(),
      detail: nullishStr,
      ips: z.array(z.string()).default([]),
      severity: severitySchema.nullish(),
      rule_id: nullishStr,
      qtype: nullishStr,
    })
  ),
})

/* ------------------------- detalle de sesión y paquetes ------------------------ */

export const explainSchema = obj({
  protocol: z.string(),
  outcome: z.string(),
  summary: z.array(z.string()),
  steps: z.array(
    obj({
      who: z.string(),
      label: z.string(),
      detail: nullishStr,
      packet: nullishNum,
      ts: nullishNum,
    })
  ),
  wireshark_filter: nullishStr,
})

export const packetsPageSchema = obj({
  items: z.array(
    obj({
      index: z.number(),
      ts: z.number(),
      caplen: z.number(),
      origlen: z.number(),
      snaplen_limited: z.boolean().default(false),
    })
  ),
  has_more: z.boolean(),
})

export const streamSchema = obj({
  chunks: z.array(
    obj({ from: z.string(), bytes: z.number(), text: z.string() })
  ),
  origin_bytes: z.number(),
  destination_bytes: z.number(),
  encrypted: z.boolean().default(false),
  truncated: z.boolean().default(false),
})

export const packetDetailSchema = obj({
  index: z.number(),
  ts: z.number(),
  caplen: z.number(),
  origlen: z.number(),
  snaplen_limited: z.boolean().default(false),
  session_id: nullishNum,
  endpoints: z.unknown().nullish(),
  hexdump: z.string(),
  layers: z.array(
    obj({
      name: z.string(),
      start: z.number(),
      end: z.number(),
      note: nullishStr,
      fields: z.array(
        obj({
          label: z.string(),
          value: z.string(),
          start: z.number(),
          end: z.number(),
          hint: nullishStr,
        })
      ),
    })
  ),
})

export const wiresharkFilterSchema = obj({
  ip: z.string(),
  wireshark_filter: z.string(),
})

/* ------------------------------ captura en vivo ------------------------------ */

export const interfacesSchema = z.array(
  obj({ name: z.string(), description: nullishStr })
)

export const liveStatusSchema = obj({
  state: z.string(), // idle | running | finished
  packets: z.number(),
  bytes: z.number(),
  seconds: z.number(),
  reason: nullishStr,
  warning: nullishStr,
})
export type LiveStatus = z.infer<typeof liveStatusSchema>

/* ----------------------------- reglas, IOC y notas ---------------------------- */

export const ruleSchema = obj({
  id: z.string(),
  name: z.string(),
  severity: severitySchema,
  detector: nullishStr,
  custom: z.boolean().default(false),
})
export const rulesSchema = obj({
  items: z.array(ruleSchema),
  example: z.record(z.string(), z.unknown()).nullish(),
})

export const rulePreviewSchema = obj({
  id: z.string(),
  yaml: z.string(),
  exists: z.boolean().default(false),
  matches: obj({
    sessions: z.number(),
    alerts: z.number(),
    sample: z.array(z.record(z.string(), z.unknown())).default([]),
  }).nullish(),
})

/** POST /api/rules (201): la regla guardada; el backend puede sumar campos. */
export const savedRuleSchema = z.record(z.string(), z.unknown())

export const iocStatusSchema = obj({
  loaded: z.boolean(),
  source: nullishStr,
  ips: z.number().default(0),
  networks: z.number().default(0),
  domains: z.number().default(0),
  sessions: z.number().default(0),
})

export const noteSchema = obj({
  id: z.number(),
  note: z.string().default(''),
  reviewed: z.boolean().default(false),
})

export const downloadTicketSchema = obj({
  ticket: z.string(),
  query: z.string(),
})

export const healthSchema = obj({
  status: z.string(),
  version: z.string().optional(),
})

/* ----------------------------- soporte: sistema ----------------------------- */

export const systemOverviewSchema = obj({
  cpu_percent: nullishNum,
  cpu_count: nullishNum,
  cpu_physical: nullishNum,
  memory: obj({
    total: z.number(),
    available: z.number(),
    used: z.number(),
    percent: z.number(),
  }).nullish(),
  swap: obj({
    total: z.number(),
    used: z.number(),
    percent: z.number(),
  }).nullish(),
  disks: z
    .array(
      obj({
        mount: z.string(),
        fstype: nullishStr,
        total: z.number(),
        used: z.number(),
        percent: z.number(),
      })
    )
    .default([]),
  network_total: obj({ sent: z.number(), received: z.number() }).nullish(),
  battery: z.unknown().nullish(),
  uptime_seconds: nullishNum,
  process_count: nullishNum,
})

export const processSchema = obj({
  pid: z.number(),
  ppid: nullishNum,
  name: z.string(),
  user: nullishStr,
  cpu: nullishNum,
  rss: nullishNum,
  threads: nullishNum,
  status: nullishStr,
  started: nullishNum,
  exe: nullishStr,
  cmdline: nullishStr,
  connections: nullishNum,
  hints: z.array(z.string()).default([]),
})
export const processesSchema = obj({
  total: z.number(),
  ncpu: z.number().nullish(),
  items: z.array(processSchema),
})

export const processDetailSchema = obj({
  pid: z.number(),
  name: z.string(),
  exe: nullishStr,
  user: nullishStr,
  status: nullishStr,
  cmdline: nullishStr,
  cwd: nullishStr,
  started: nullishNum,
  threads: nullishNum,
  rss: nullishNum,
  vms: nullishNum,
  parent: obj({ pid: z.number(), name: z.string() }).nullish(),
  children: z.array(obj({ pid: z.number(), name: z.string() })).default([]),
  io: obj({ read: z.number(), written: z.number() }).nullish(),
  hints: z.array(z.string()).default([]),
  open_files: z.array(z.unknown()).default([]),
  modules: z.array(z.unknown()).default([]),
  connections: z
    .array(
      obj({
        local: nullishStr,
        remote: nullishStr,
        status: nullishStr,
        owner: nullishStr,
      })
    )
    .default([]),
})

/** /api/system/processes/{pid}/file: metadatos del ejecutable (forma abierta). */
export const processFileSchema = z.record(z.string(), z.unknown())

export const portsSchema = obj({
  total: z.number(),
  items: z.array(
    obj({
      proto: z.string(),
      ip: z.string(),
      port: z.number(),
      pid: nullishNum,
      process: nullishStr,
      exposure: nullishStr,
      exposure_text: nullishStr,
      service: nullishStr,
    })
  ),
})

export const connectionsSchema = obj({
  total: z.number(),
  items: z.array(
    obj({
      pid: nullishNum,
      process: nullishStr,
      local: z.string(),
      remote: nullishStr,
      remote_ip: nullishStr,
      status: nullishStr,
      owner: nullishStr,
      scope: nullishStr,
      service: nullishStr,
    })
  ),
})

export const servicesSchema = obj({
  supported: z.boolean(),
  total: z.number().default(0),
  items: z
    .array(
      obj({
        name: z.string(),
        display: nullishStr,
        status: nullishStr,
        start: nullishStr,
        pid: nullishNum,
        user: nullishStr,
        path: nullishStr,
        hints: z.array(z.string()).default([]),
      })
    )
    .default([]),
})

export const startupSchema = obj({
  supported: z.boolean(),
  total: z.number().default(0),
  items: z
    .array(
      obj({
        where: z.string(),
        name: z.string(),
        command: nullishStr,
        hints: z.array(z.string()).default([]),
      })
    )
    .default([]),
})

/* ------------------------------- soporte: red ------------------------------- */

export const netConfigSchema = obj({
  adapters: z.array(
    obj({
      name: z.string(),
      description: nullishStr,
      up: z.boolean().nullish(),
      speed_mbps: nullishNum,
      mtu: nullishNum,
      mac: nullishStr,
      ipv4: z.array(obj({ ip: z.string(), mask: nullishStr })).default([]),
      ipv6: z.array(z.string()).default([]),
      gateway: z.array(z.string()).default([]),
      dns: z.array(z.string()).default([]),
      dhcp: z.boolean().nullish(),
      apipa: z.boolean().nullish(),
      loopback: z.boolean().nullish(),
    })
  ),
})

export const netConfigRawSchema = obj({
  available: z.boolean(),
  command: nullishStr,
  text: nullishStr,
})

export const wifiSchema = obj({
  available: z.boolean(),
  connected: z.boolean().nullish(),
  quality: nullishStr,
  interface: nullishStr,
  state: nullishStr,
  ssid: nullishStr,
  band: nullishStr,
  channel: nullishNum,
  radio: nullishStr,
  auth: nullishStr,
  rx: nullishNum,
  tx: nullishNum,
  signal: nullishNum,
})

export const wifiHistorySchema = obj({
  available: z.boolean(),
  events: z
    .array(obj({ time: z.string(), kind: z.string(), message: z.string() }))
    .default([]),
})

export const internetCheckSchema = obj({
  steps: z.array(
    obj({
      code: z.string(),
      title: z.string(),
      ok: z.boolean(),
      detail: nullishStr,
      ms: nullishNum,
    })
  ),
  ok: z.boolean(),
  layer: nullishStr,
  summary: z.string(),
  advice: nullishStr,
  command: nullishStr,
})

export const latencySchema = obj({
  host: z.string(),
  port: z.number().nullish(),
  samples: z.number(),
  failed: z.number(),
  times: z.array(z.number()),
  min: nullishNum,
  max: nullishNum,
  avg: nullishNum,
  jitter: nullishNum,
  router: obj({
    host: z.string(),
    avg: nullishNum,
    loss_pct: nullishNum,
  }).nullish(),
})

export const pingSchema = obj({
  available: z.boolean().optional(),
  host: z.string(),
  sent: z.number().nullish(),
  received: z.number().nullish(),
  loss_pct: nullishNum,
  times: z.array(z.number()).default([]),
  min: nullishNum,
  max: nullishNum,
  avg: nullishNum,
  timed_out: z.boolean().nullish(),
})

/** Herramientas con resultado de forma abierta (traceroute, RDP, hora, dispositivos). */
export const toolResultSchema = z.record(z.string(), z.unknown())

export const portScanSchema = obj({
  host: z.string(),
  results: z.array(
    obj({
      port: z.number(),
      service: nullishStr,
      state: z.string(),
      ms: nullishNum,
      detail: nullishStr,
    })
  ),
})

export const duplicateIpSchema = obj({
  summary: z.string(),
  duplicate: z.boolean(),
  probes: z.array(z.record(z.string(), z.unknown())).default([]),
  conflicts: z.array(z.unknown()).default([]),
  advice: nullishStr,
})

export const monitorSchema = obj({
  running: z.boolean(),
  interval: z.number(),
  started_at: nullishNum,
  total: z.number(),
  availability_pct: nullishNum,
  current: nullishStr,
  gateway: z.unknown().nullish(),
  wifi: z.unknown().nullish(),
  latency: obj({
    last: nullishNum,
    avg: nullishNum,
    max: nullishNum,
  }).nullish(),
  samples: z.array(z.unknown()).default([]),
  outages: z.array(z.unknown()).default([]),
  outage_count: z.number().default(0),
  downtime_seconds: z.number().default(0),
})
export type MonitorStatus = z.infer<typeof monitorSchema>
