import { type ReactNode } from 'react'
import { HelpTip } from '@/components/help-tip'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

type Props = {
  title: string
  /** Tema de lib/help para el botón «?». */
  topic?: string
  summary?: ReactNode
  actions?: ReactNode
  children: ReactNode
}

/** Tarjeta de una sección de soporte: título, ayuda, resumen y acciones. */
export function SectionCard({ title, topic, summary, actions, children }: Props) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1.5'>
          <h2 className='text-base font-semibold'>{title}</h2>
          {topic && <HelpTip topic={topic} />}
        </CardTitle>
        {summary && <CardDescription>{summary}</CardDescription>}
        {actions && <CardAction>{actions}</CardAction>}
      </CardHeader>
      <CardContent className='space-y-4'>{children}</CardContent>
    </Card>
  )
}

/** Lista de pares «dato: valor» (dl) con rejilla responsive. */
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
      <dd className={mono ? 'font-mono text-sm break-all' : 'text-sm break-words'}>
        {children}
      </dd>
    </div>
  )
}

export const Dash = () => <span className='text-muted-foreground'>—</span>
