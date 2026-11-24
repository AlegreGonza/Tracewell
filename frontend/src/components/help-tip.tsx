import { CircleHelp } from 'lucide-react'
import { HELP } from '@/lib/help'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'

/** Botón «?» que despliega una explicación en lenguaje simple (tema de lib/help). */
export function HelpTip({ topic }: { topic: string }) {
  // hasOwn: un tema como "constructor" no existe
  const help = Object.hasOwn(HELP, topic) ? HELP[topic] : null
  if (!help) return null
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type='button'
          aria-label={`Ayuda: ${help.title}`}
          title='¿Qué estoy viendo?'
          className='inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
        >
          <CircleHelp className='size-4' aria-hidden='true' />
        </button>
      </PopoverTrigger>
      <PopoverContent
        role='note'
        className='w-80 text-sm'
        aria-label={help.title}
      >
        <p className='mb-1 font-medium'>{help.title}</p>
        <p className='text-muted-foreground'>{help.text}</p>
      </PopoverContent>
    </Popover>
  )
}
