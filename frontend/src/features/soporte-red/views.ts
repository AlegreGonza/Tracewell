// Lecturas tipadas de lo que los esquemas compartidos dejan abierto (campos extra).
import { z } from 'zod'

const str = z.string().nullish()
const num = z.number().nullish()

export const configExtra = z.looseObject({ hostname: str })

export const wifiExtra = z.looseObject({ reason: str, bssid: str })

export const wifiHistoryExtra = z.looseObject({
  reason: str,
  disconnections: num,
})

export const monitorExtra = z.looseObject({
  gateway: str.catch(null),
  wifi: z.looseObject({ signal: num, ssid: str }).nullish().catch(null),
  samples: z.array(z.looseObject({ ms: num, layer: str })).catch([]),
  outages: z
    .array(
      z.looseObject({
        start: z.number(),
        duration: num,
        layer: str,
        ongoing: z.boolean().nullish(),
        signal: num,
      })
    )
    .catch([]),
})

export const traceView = z.looseObject({
  available: z.boolean().nullish(),
  reason: str,
  hops: z
    .array(
      z.looseObject({
        n: z.number(),
        ips: z.array(z.string()).catch([]),
        times: z.array(z.number()).catch([]),
      })
    )
    .catch([]),
})

export const rdpView = z.looseObject({ summary: z.string().catch('') })

export const timeView = z.looseObject({
  available: z.boolean().nullish(),
  reason: str,
  summary: str,
  offset_seconds: num,
  command: str,
})

export const devicesView = z.looseObject({
  available: z.boolean().nullish(),
  reason: str,
  vendor_db: z.boolean().nullish(),
  subnets: z.array(z.string()).catch([]),
  devices: z
    .array(
      z.looseObject({
        ip: z.string(),
        hostname: str,
        mac: str,
        vendor: str,
        random_mac: z.boolean().nullish(),
        is_gateway: z.boolean().nullish(),
        is_self: z.boolean().nullish(),
      })
    )
    .catch([]),
})

export const duplicateView = z.looseObject({
  probes: z
    .array(
      z.looseObject({
        adapter: str,
        ip: str,
        probed: z.boolean().nullish(),
        duplicate: z.boolean().nullish(),
        reason: str,
        other_macs: z.array(z.string()).catch([]),
      })
    )
    .catch([]),
  conflicts: z.array(z.looseObject({ time: str, message: str })).catch([]),
})

/** Lee `data` con el esquema; si no calza, null (la pantalla muestra un aviso). */
export function view<S extends z.ZodType>(
  schema: S,
  data: unknown
): z.infer<S> | null {
  const r = schema.safeParse(data)
  return r.success ? r.data : null
}

export const ms = (v: number | null | undefined) =>
  v == null ? '—' : `${v} ms`

// Veredicto simple de la latencia hacia un servidor público (umbrales orientativos).
export function latencyVerdict(avg: number | null | undefined) {
  if (avg == null) return 'No se pudo medir.'
  if (avg < 30) return 'Excelente: se nota instantáneo.'
  if (avg < 80) return 'Buena para casi todo.'
  if (avg < 150)
    return 'Aceptable, pero las videollamadas y los juegos pueden sentirse lentos.'
  return 'Alta: todo va a sentirse lento.'
}
