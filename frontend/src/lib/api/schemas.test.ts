import { type z } from 'zod'
import { fixtures } from '@/test/fixtures'
import { describe, expect, it } from 'vitest'
import * as S from './schemas'

// Contrato: cada respuesta de ejemplo (la misma que sirve MSW) calza con su esquema.
const cases: Array<[string, z.ZodType, unknown]> = [
  ['capture', S.captureSchema, fixtures.capture],
  ['stats', S.statsSchema, fixtures.stats],
  ['sessions', S.sessionsPageSchema, fixtures.sessions],
  ['timeline', S.timelineSchema, fixtures.timeline],
  ['alerts', S.alertsSchema, fixtures.alerts],
  ['hosts', S.hostsSchema, fixtures.hosts],
  ['hostsByMac', S.hostsByMacSchema, fixtures.hostsByMac],
  ['graph', S.graphSchema, fixtures.graph],
  ['dns', S.dnsSchema, fixtures.dns],
  ['http', S.httpOverviewSchema, fixtures.http],
  ['remoteAccess', S.remoteAccessSchema, fixtures.remoteAccess],
  ['caseTimeline', S.caseTimelineSchema, fixtures.caseTimeline],
  ['explain', S.explainSchema, fixtures.explain],
  ['sessionHttp', S.sessionHttpSchema, fixtures.sessionHttp],
  ['sessionTls', S.tlsSchema, fixtures.sessionTls],
  ['sessionPackets', S.packetsPageSchema, fixtures.sessionPackets],
  ['stream', S.streamSchema, fixtures.stream],
  ['packet', S.packetDetailSchema, fixtures.packet],
  ['wiresharkFilter', S.wiresharkFilterSchema, fixtures.wiresharkFilter],
  ['liveStatus', S.liveStatusSchema, fixtures.liveStatus],
  ['interfaces', S.interfacesSchema, fixtures.interfaces],
  ['rules', S.rulesSchema, fixtures.rules],
  ['rulePreview', S.rulePreviewSchema, fixtures.rulePreview],
  ['iocs', S.iocStatusSchema, fixtures.iocs],
  ['note', S.noteSchema, fixtures.note],
  ['health', S.healthSchema, fixtures.health],
  ['systemOverview', S.systemOverviewSchema, fixtures.systemOverview],
  ['processes', S.processesSchema, fixtures.processes],
  ['process', S.processDetailSchema, fixtures.process],
  ['ports', S.portsSchema, fixtures.ports],
  ['connections', S.connectionsSchema, fixtures.connections],
  ['services', S.servicesSchema, fixtures.services],
  ['startup', S.startupSchema, fixtures.startup],
  ['netConfig', S.netConfigSchema, fixtures.netConfig],
  ['netConfigRaw', S.netConfigRawSchema, fixtures.netConfigRaw],
  ['wifi', S.wifiSchema, fixtures.wifi],
  ['wifiHistory', S.wifiHistorySchema, fixtures.wifiHistory],
  ['monitor', S.monitorSchema, fixtures.monitor],
  ['internet', S.internetCheckSchema, fixtures.internet],
  ['latency', S.latencySchema, fixtures.latency],
  ['ping', S.pingSchema, fixtures.ping],
  ['portScan', S.portScanSchema, fixtures.portScan],
  ['duplicateIp', S.duplicateIpSchema, fixtures.duplicateIp],
]

describe('esquemas de la API', () => {
  it.each(cases)('%s: la respuesta de ejemplo calza', (_name, schema, data) => {
    const result = schema.safeParse(data)
    expect(result.success, JSON.stringify(result.error?.issues)).toBe(true)
  })

  it('la alerta de demo trae la técnica y la táctica MITRE', () => {
    const [first] = S.alertsSchema.parse(fixtures.alerts)
    expect(first.mitre_technique).toBe('T1040')
    expect(first.mitre_tactic).toBe('Credential Access')
  })

  it('rechaza lo que no calza', () => {
    expect(
      S.sessionsPageSchema.safeParse({ total: '1', items: [] }).success
    ).toBe(false)
    expect(S.severitySchema.safeParse('urgente').success).toBe(false)
    expect(S.captureSchema.safeParse({ source: 'x' }).success).toBe(false)
  })
})
