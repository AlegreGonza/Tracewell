import { cva } from 'class-variance-authority'
import { type Severity } from '@/lib/api/schemas'
import { SEVERITY_LABEL } from '@/lib/severity'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'

// Colores de theme.css (--sev-*): texto sobre fondo tintado al 10%, contraste AA en ambos modos.
const severityStyle = cva('', {
  variants: {
    severity: {
      low: 'border-sev-low/40 bg-sev-low/10 text-sev-low',
      medium: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium',
      high: 'border-sev-high/40 bg-sev-high/10 text-sev-high',
      critical: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
    },
  },
})

type SeverityBadgeProps = Omit<
  React.ComponentProps<typeof Badge>,
  'variant'
> & {
  severity: Severity
}

/** Etiqueta de severidad reutilizable: severity="high" muestra "Alta". */
export function SeverityBadge({
  severity,
  className,
  children,
  ...props
}: SeverityBadgeProps) {
  return (
    <Badge
      variant='outline'
      data-severity={severity}
      className={cn(severityStyle({ severity }), className)}
      {...props}
    >
      {children ?? SEVERITY_LABEL[severity]}
    </Badge>
  )
}
