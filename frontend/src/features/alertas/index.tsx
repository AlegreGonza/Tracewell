import { useMemo } from 'react'
import { getRouteApi } from '@tanstack/react-router'
import { useAlerts } from '@/lib/api/queries'
import { RequireCapture } from '@/components/empty-capture'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Button } from '@/components/ui/button'
import { alertKeys } from './attack'
import { AlertDetail } from './components/alert-detail'
import { AlertsTable } from './components/alerts-table'
import { AttackMap } from './components/attack-map'

const route = getRouteApi('/_app/capturas/alertas/')

function AlertasContent() {
  const { severity, tactic, technique, alerta } = route.useSearch()
  const navigate = route.useNavigate()
  const query = useAlerts(severity)

  const rows = useMemo(() => {
    const all = query.data ?? []
    const keys = alertKeys(all)
    return all
      .map((alert, i) => ({ key: keys[i], alert }))
      .filter(
        ({ alert }) =>
          (tactic === undefined || (alert.mitre_tactic ?? '') === tactic) &&
          (technique === undefined ||
            (alert.mitre_technique ?? '') === technique)
      )
  }, [query.data, tactic, technique])

  const set = (
    patch: Partial<{ tactic: string; technique: string; alerta: string }>
  ) =>
    void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true })
  const filtered = tactic !== undefined || technique !== undefined

  return (
    <QueryBoundary
      query={query}
      isEmpty={(d) => d.length === 0}
      empty={
        <p className='text-sm text-muted-foreground'>
          Ninguna regla se disparó con esta captura.
        </p>
      }
    >
      {(all) => (
        <div className='space-y-4'>
          <AttackMap
            alerts={all}
            tactic={tactic}
            technique={technique}
            onSelect={(f) =>
              set({ tactic: f?.tactic, technique: f?.technique })
            }
          />
          <div className='flex items-center justify-between text-sm text-muted-foreground'>
            <span>
              {rows.length} de {all.length} alertas
            </span>
            {filtered && (
              <Button
                variant='ghost'
                size='sm'
                onClick={() => set({ tactic: undefined, technique: undefined })}
              >
                Quitar filtro
              </Button>
            )}
          </div>
          <AlertsTable
            rows={rows}
            selectedKey={alerta}
            onOpen={(key) => set({ alerta: key })}
          />
          <AlertDetail
            alert={rows.find((r) => r.key === alerta)?.alert ?? null}
            onClose={() => set({ alerta: undefined })}
          />
        </div>
      )}
    </QueryBoundary>
  )
}

export function Alertas() {
  return (
    <Page
      title='Alertas y ATT&CK'
      description='Alertas detectadas por las reglas, con su técnica MITRE ATT&CK.'
    >
      <RequireCapture>
        <AlertasContent />
      </RequireCapture>
    </Page>
  )
}
