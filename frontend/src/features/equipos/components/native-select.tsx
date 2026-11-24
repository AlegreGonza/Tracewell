import { cn } from '@/lib/utils'

type NativeSelectProps = React.ComponentProps<'select'> & { label: string }

/** Selector nativo (accesible por teclado y lector de pantalla) con el estilo de los campos. */
export function NativeSelect({ label, className, children, ...props }: NativeSelectProps) {
  return (
    <label className='flex items-center gap-2 text-sm'>
      <span className='text-muted-foreground'>{label}</span>
      <select
        className={cn(
          'h-8 rounded-md border border-input bg-background px-2 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50',
          className
        )}
        {...props}
      >
        {children}
      </select>
    </label>
  )
}
