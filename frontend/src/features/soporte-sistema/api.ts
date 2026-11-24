// Consultas de «Soporte · Sistema». Los esquemas de lib/api/schemas.ts dan las pistas (hints)
// como texto, pero el backend manda { code, text }: acá se corrigen sin tocar lo compartido.
import { useQuery } from '@tanstack/react-query'
import { z } from 'zod'
import { buildQuery, request } from '@/lib/api/client'
import {
  connectionsSchema,
  portsSchema,
  systemOverviewSchema,
} from '@/lib/api/schemas'

const nullishStr = z.string().nullish()
const nullishNum = z.number().nullish()

const hintSchema = z.looseObject({
  code: z.string(),
  text: nullishStr,
})
export type Hint = z.infer<typeof hintSchema>
const hints = z.array(hintSchema).default([])

const overviewSchema = systemOverviewSchema.extend({
  battery: z
    .looseObject({ percent: z.number(), plugged: z.boolean().nullish() })
    .nullish(),
})

const processRow = z.looseObject({
  pid: z.number(),
  name: nullishStr,
  user: nullishStr,
  cpu: nullishNum,
  rss: nullishNum,
  exe: nullishStr,
  connections: nullishNum,
  hints,
})
const processesSchema = z.looseObject({
  total: z.number(),
  items: z.array(processRow),
})

const withLimited = { limited: z.boolean().default(false) }
const portsFull = portsSchema.extend(withLimited)
const connectionsFull = connectionsSchema.extend(withLimited)

const servicesSchema = z.looseObject({
  supported: z.boolean(),
  reason: nullishStr,
  total: z.number().default(0),
  items: z
    .array(
      z.looseObject({
        name: z.string(),
        display: nullishStr,
        status: nullishStr,
        start: nullishStr,
        user: nullishStr,
        path: nullishStr,
        hints,
      })
    )
    .default([]),
})

const startupSchema = z.looseObject({
  supported: z.boolean(),
  reason: nullishStr,
  total: z.number().default(0),
  items: z
    .array(
      z.looseObject({
        where: z.string(),
        name: z.string(),
        command: nullishStr,
        hints,
      })
    )
    .default([]),
})

const key = (part: string, extra?: unknown) =>
  ['soporte-sistema', part, extra ?? null] as const

type Poll = { refetchInterval?: number | false }

export const useOverview = (poll: Poll = {}) =>
  useQuery({
    queryKey: key('overview'),
    queryFn: ({ signal }) =>
      request('/api/system/overview', { schema: overviewSchema, signal }),
    ...poll,
  })

type ProcessSort = 'ram' | 'cpu' | 'name' | 'pid'
export const useProcessList = (sort: ProcessSort, poll: Poll = {}) =>
  useQuery({
    queryKey: key('processes', sort),
    queryFn: ({ signal }) =>
      request(`/api/system/processes${buildQuery({ sort, limit: 600 })}`, {
        schema: processesSchema,
        signal,
      }),
    ...poll,
  })

export const useOpenPorts = () =>
  useQuery({
    queryKey: key('ports'),
    queryFn: ({ signal }) =>
      request('/api/system/ports', { schema: portsFull, signal }),
  })

export const useActiveConnections = (poll: Poll = {}) =>
  useQuery({
    queryKey: key('connections'),
    queryFn: ({ signal }) =>
      request('/api/system/connections', { schema: connectionsFull, signal }),
    ...poll,
  })

export const useServiceList = () =>
  useQuery({
    queryKey: key('services'),
    queryFn: ({ signal }) =>
      request('/api/system/services', { schema: servicesSchema, signal }),
  })

export const useStartupList = () =>
  useQuery({
    queryKey: key('startup'),
    queryFn: ({ signal }) =>
      request('/api/system/startup', { schema: startupSchema, signal }),
  })
