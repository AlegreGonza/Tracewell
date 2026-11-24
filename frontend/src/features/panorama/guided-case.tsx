import { useState } from 'react'
import { Link, type LinkProps } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'

type Step = {
  title: string
  text: string
  link?: { label: string; props: Pick<LinkProps, 'to' | 'search'> }
}

const sesionesDe = (ip: string): LinkProps['search'] => ({ ip, page: 1, size: 50 })

// Los pasos del caso de la demo (samples/demo.pcap).
const STEPS: Step[] = [
  {
    title: 'Mirá el panorama',
    text: 'Arriba tenés el resumen: 32 sesiones y 45 paquetes. El gráfico muestra cuándo hubo tráfico y «Quién más habla», quién generó más. Tocá los «?» de cada sección para que te explique qué estás viendo.',
  },
  {
    title: 'Alertas: ¿qué encontró Tracewell?',
    text: 'Hay 3 alertas. Abrí «Escaneo de puertos»: la IP 192.168.1.66 mandó un SYN a 25 puertos de 192.168.1.5 en una fracción de segundo. Es alguien «tocando todas las puertas» para ver cuáles están abiertas. En el mapa ATT&CK se ilumina la táctica Discovery.',
    link: { label: 'Ir a las alertas', props: { to: '/capturas/alertas', search: {} } },
  },
  {
    title: 'Mirá un escaneo en la tabla de sesiones',
    text: 'Filtrá por 192.168.1.66: son decenas de sesiones de 1 solo paquete de 54 bytes. Abrí una y leé «En palabras simples»: «Intentó conectarse y nadie respondió». Un paquete, sin saludo, sin respuesta: esa es la cara de un escaneo.',
    link: {
      label: 'Filtrar por 192.168.1.66',
      props: { to: '/capturas/sesiones', search: sesionesDe('192.168.1.66') },
    },
  },
  {
    title: 'Encontrá una contraseña en claro',
    text: 'Filtrá por 192.168.1.20, abrí la sesión al puerto 21 (FTP) y mirá el resumen y la explicación. FTP no cifra nada: cualquiera en la red puede ver esa contraseña.',
    link: {
      label: 'Filtrar por 192.168.1.20',
      props: { to: '/capturas/sesiones', search: sesionesDe('192.168.1.20') },
    },
  },
  {
    title: 'Leé una petición HTTP',
    text: 'En la pestaña HTTP vas a ver un GET a www.example.com con su respuesta 200. Si la respuesta trae un archivo, Tracewell calcula su huella SHA-256 y reconoce qué es por sus primeros bytes.',
    link: { label: 'Ir a DNS y HTTP', props: { to: '/capturas/trafico' } },
  },
  {
    title: 'Un nombre DNS que no cierra',
    text: 'En la tabla de DNS aparece un nombre larguísimo y aleatorio terminado en evil-c2.example, sin respuesta. Es lo que haría un malware que busca su servidor de control. Tracewell lo marca con una pista.',
    link: { label: 'Ir a DNS y HTTP', props: { to: '/capturas/trafico' } },
  },
  {
    title: 'Decidí como un analista',
    text: 'Escaneo desde 192.168.1.66: investigar ese equipo y bloquearlo. Contraseña FTP en claro: cambiarla y migrar a un servicio cifrado. Nombre DNS sospechoso: bloquear el dominio y buscar qué programa lo pidió. Anotalo en la nota de cada sesión y generá el informe HTML.',
  },
]

/** Recorrido guiado de la demo: siete pasos para aprender a investigar. */
export function GuidedCase() {
  const [open, setOpen] = useState(true)
  const [done, setDone] = useState<ReadonlySet<number>>(new Set())
  const toggle = (i: number) =>
    setDone((prev) => {
      const next = new Set(prev)
      if (!next.delete(i)) next.add(i)
      return next
    })

  return (
    <Card>
      <CardHeader className='flex-row items-center justify-between gap-2'>
        <CardTitle>Caso guiado: investigá esta demo</CardTitle>
        <div className='flex items-center gap-3 text-sm text-muted-foreground'>
          {done.size} de {STEPS.length} pasos
          <Button
            variant='ghost'
            size='sm'
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? 'Ocultar' : 'Mostrar'}
          </Button>
        </div>
      </CardHeader>
      {open && (
        <CardContent>
          <ol className='space-y-4'>
            {STEPS.map((s, i) => (
              <li key={s.title} className='space-y-1'>
                <label className='flex items-center gap-2 font-medium'>
                  <Checkbox
                    checked={done.has(i)}
                    onCheckedChange={() => toggle(i)}
                  />
                  {s.title}
                </label>
                <p className='text-sm text-muted-foreground'>{s.text}</p>
                {s.link && (
                  <Button asChild variant='outline' size='sm'>
                    <Link {...s.link.props}>{s.link.label}</Link>
                  </Button>
                )}
              </li>
            ))}
          </ol>
        </CardContent>
      )}
    </Card>
  )
}
