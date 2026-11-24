import { type ReactNode } from 'react'
import { AlertTriangle, Info } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { HelpTip } from '@/components/help-tip'

/** Tarjeta de una sección: título, ayuda «?», acciones y contenido. */
export function Box({
  title,
  topic,
  actions,
  children,
}: {
  title: string
  topic?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1.5'>
          <h2 className='text-base font-semibold'>{title}</h2>
          {topic && <HelpTip topic={topic} />}
        </CardTitle>
        {actions && <CardAction>{actions}</CardAction>}
      </CardHeader>
      <CardContent className='space-y-4'>{children}</CardContent>
    </Card>
  )
}

export function Notice({
  children,
  warn = false,
}: {
  children: ReactNode
  warn?: boolean
}) {
  const Icon = warn ? AlertTriangle : Info
  return (
    <Alert role='note'>
      <Icon aria-hidden='true' />
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

export const Dash = () => <span className='text-muted-foreground'>—</span>

export function Facts({ children }: { children: ReactNode }) {
  return (
    <dl className='grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3'>
      {children}
    </dl>
  )
}

export function Fact({
  label,
  mono,
  children,
}: {
  label: string
  mono?: boolean
  children: ReactNode
}) {
  return (
    <div className='min-w-0'>
      <dt className='text-xs text-muted-foreground'>{label}</dt>
      <dd
        className={mono ? 'font-mono text-sm break-all' : 'text-sm break-words'}
      >
        {children}
      </dd>
    </div>
  )
}

/** Botón que dispara una prueba: dice «ocupado» mientras corre. */
export function RunButton({
  onClick,
  busy,
  idle,
  working,
  disabled,
  type = 'button',
}: {
  onClick?: () => void
  busy: boolean
  idle: string
  working: string
  disabled?: boolean
  type?: 'button' | 'submit'
}) {
  return (
    <Button type={type} onClick={onClick} disabled={busy || disabled}>
      {busy ? working : idle}
    </Button>
  )
}

/** Veredicto de una prueba (role=status): verde si salió bien, rojo si no. */
export function Verdict({
  ok,
  children,
}: {
  ok: boolean
  children: ReactNode
}) {
  const tone = ok
    ? 'border-chart-2/50 bg-chart-2/10'
    : 'border-destructive/50 bg-destructive/10'
  return (
    <div
      role='status'
      className={`space-y-1 rounded-md border p-3 text-sm ${tone}`}
    >
      {children}
    </div>
  )
}

/** Comando sugerido: solo se muestra, Tracewell no lo ejecuta. */
export function SuggestedCommand({ command }: { command?: string | null }) {
  if (!command) return null
  return (
    <p className='text-sm'>
      Si querés, podés ejecutarlo vos: <code>{command}</code>{' '}
      <span className='text-muted-foreground'>(Tracewell no lo ejecuta)</span>
    </p>
  )
}
