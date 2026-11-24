import { type ReactNode } from 'react'
import { AlertTriangle, Info } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'

/** Aviso informativo o de advertencia (role=note); los errores usan QueryBoundary / toast. */
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
