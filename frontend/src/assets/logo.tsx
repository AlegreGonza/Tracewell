import { type SVGProps } from 'react'

// Isotipo de Tracewell: la onda del tráfico (mismo trazo que la interfaz anterior).
export function Logo({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox='0 0 20 14'
      aria-hidden='true'
      focusable='false'
      className={className}
      {...props}
    >
      <path
        d='M0 7h5l2.5-6 4 12L14 7h6'
        fill='none'
        stroke='currentColor'
        strokeWidth='1.8'
        strokeLinejoin='miter'
      />
    </svg>
  )
}
