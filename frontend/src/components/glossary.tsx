import { useState } from 'react'
import { GLOSSARY } from '@/lib/help'
import { Input } from '@/components/ui/input'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'

type GlossaryProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Glosario con buscador en un panel lateral: las palabras que asustan, explicadas sin vueltas.
 * Para abrirlo desde Ctrl+K: guardá `open` en un estado y montá <Glossary open onOpenChange />.
 */
export function Glossary({ open, onOpenChange }: GlossaryProps) {
  const [query, setQuery] = useState('')
  const q = query.trim().toLowerCase()
  const items = GLOSSARY.filter(
    ([term, text]) =>
      !q || term.toLowerCase().includes(q) || text.toLowerCase().includes(q)
  )
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className='overflow-y-auto sm:max-w-md'>
        <SheetHeader>
          <SheetTitle>Glosario</SheetTitle>
          <SheetDescription>
            Los términos técnicos, explicados sin vueltas.
          </SheetDescription>
        </SheetHeader>
        <div className='flex flex-col gap-3 px-4 pb-4'>
          <Input
            type='search'
            aria-label='Buscar en el glosario'
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='Buscar un término (por ejemplo: SYN, TTL, DNS)'
            autoComplete='off'
          />
          {items.length === 0 ? (
            <p className='text-sm text-muted-foreground'>
              Ningún término coincide.
            </p>
          ) : (
            <dl className='space-y-3'>
              {items.map(([term, text]) => (
                <div key={term}>
                  <dt className='text-sm font-medium'>{term}</dt>
                  <dd className='text-sm text-muted-foreground'>{text}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
