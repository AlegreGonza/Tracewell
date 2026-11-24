import { useState } from 'react'
import { Check, Minus, X } from 'lucide-react'
import { useInternetCheck, useLatencyTest } from '@/lib/api/mutations'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Box,
  Fact,
  Facts,
  RunButton,
  SuggestedCommand,
  Verdict,
} from './components/parts'
import { latencyVerdict, ms } from './views'

function StepMark({ ok }: { ok: boolean | null | undefined }) {
  if (ok === true) return <Check className='size-4' aria-label='bien' />
  if (ok === false) return <X className='size-4' aria-label='falla' />
  return <Minus className='size-4' aria-label='omitido' />
}

/** «¿Hay Internet?»: revisa capa por capa y dice dónde se corta. */
export function Internet() {
  const check = useInternetCheck()
  const r = check.data
  return (
    <Box title='¿Hay Internet?' topic='soporte_internet'>
      <div className='space-y-2'>
        <RunButton
          onClick={() => check.mutate()}
          busy={check.isPending}
          idle='Comprobar ahora'
          working='Comprobando…'
        />
        <p className='text-sm text-muted-foreground'>
          Abre una conexión corta a 1.1.1.1 y 8.8.8.8 y le pide a tu DNS la
          dirección de unos sitios conocidos. No cambia nada.
        </p>
      </div>
      {r && (
        <>
          <Verdict ok={r.ok}>
            <p className='font-semibold'>{r.summary}</p>
            {r.advice && <p>{r.advice}</p>}
            <SuggestedCommand command={r.command} />
          </Verdict>
          <ol className='space-y-2'>
            {r.steps.map((s) => (
              <li key={s.code} className='flex items-start gap-2 text-sm'>
                <StepMark ok={s.ok} />
                <div>
                  <strong>{s.title}</strong>
                  <div className='text-muted-foreground'>{s.detail}</div>
                </div>
              </li>
            ))}
          </ol>
        </>
      )}
    </Box>
  )
}

function Bars({ times }: { times: number[] }) {
  const max = Math.max(...times, 1)
  return (
    <div
      role='img'
      aria-label={`${times.length} mediciones, entre ${Math.min(...times)} y ${Math.max(...times)} ms`}
      className='flex h-16 items-end gap-1'
    >
      {times.map((t, i) => (
        <i
          key={i}
          title={`${t} ms`}
          className='w-3 rounded-sm bg-chart-2'
          style={{ height: `${Math.max(6, (t / max) * 100)}%` }}
        />
      ))}
    </div>
  )
}

/** «Latencia»: cuánto tarda en ir y volver un mensaje, a Internet y al router. */
export function Latencia() {
  const [host, setHost] = useState('1.1.1.1')
  const test = useLatencyTest()
  const r = test.data
  const routerFast = r?.router?.avg != null && r.router.avg < 10
  return (
    <Box title='Latencia' topic='soporte_latencia'>
      <form
        className='flex flex-wrap items-end gap-3'
        onSubmit={(e) => {
          e.preventDefault()
          test.mutate({ host: host.trim() || undefined, port: 443, samples: 8 })
        }}
      >
        <div className='space-y-1.5'>
          <Label htmlFor='lat-host'>Servidor a medir (puerto 443)</Label>
          <Input
            id='lat-host'
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder='1.1.1.1'
          />
        </div>
        <RunButton
          type='submit'
          busy={test.isPending}
          idle='Medir'
          working='Midiendo…'
        />
      </form>
      <p className='text-sm text-muted-foreground'>
        Abre 8 conexiones cortas a ese servidor y hace un ping a tu router.
        Tarda unos segundos.
      </p>
      {r && (
        <div className='space-y-3'>
          <p className='font-semibold'>{latencyVerdict(r.avg)}</p>
          <Facts>
            <Fact label='Promedio'>{ms(r.avg)}</Fact>
            <Fact label='Mejor / peor'>
              {ms(r.min)} / {ms(r.max)}
            </Fact>
            <Fact label='Variación (jitter)'>{ms(r.jitter)}</Fact>
            <Fact label='Fallidas'>
              {r.failed} de {r.samples}
            </Fact>
            <Fact label={`Tu router (${r.router?.host ?? '?'})`}>
              {r.router
                ? `${ms(r.router.avg)} · ${r.router.loss_pct ?? 0} % perdido`
                : 'no se encontró'}
            </Fact>
          </Facts>
          {r.times.length > 0 && <Bars times={r.times} />}
          {r.avg != null && r.avg > 80 && routerFast && (
            <p className='text-sm text-muted-foreground'>
              Tu router responde rápido e Internet lento: el cuello de botella
              está fuera de tu red local (proveedor o servidor lejano).
            </p>
          )}
        </div>
      )}
    </Box>
  )
}
