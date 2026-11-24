import { useEffect, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { FolderOpen, Play, Radio, Square } from 'lucide-react'
import { toast } from 'sonner'
import { errorMessage } from '@/lib/api/errors'
import {
  useAnalyze,
  useDemo,
  useLiveStart,
  useLiveStop,
} from '@/lib/api/mutations'
import { useInterfaces, useLiveStatus } from '@/lib/api/queries'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Page } from '@/components/page'
import { useNativePicker } from '@/hooks/use-native-picker'

const STOP_REASON: Record<string, string> = {
  duration: 'se alcanzó el tiempo máximo',
  packets: 'se alcanzó el máximo de paquetes',
  user: 'la detuviste vos',
  error: 'hubo un error',
}

/** Pantalla de inicio: abrir un archivo, la captura de demostración o capturar en vivo. */
export function Inicio() {
  return (
    <Page
      title='Abrir captura'
      description='Elegí qué analizar: un archivo, la demo o tu propia red en vivo.'
    >
      <div className='grid gap-4 lg:grid-cols-2'>
        <FileCard />
        <LiveCard />
      </div>
    </Page>
  )
}

function FileCard() {
  const [path, setPath] = useState('')
  const navigate = useNavigate()
  const analyze = useAnalyze()
  const demo = useDemo()
  const pickFile = useNativePicker()
  const busy = analyze.isPending || demo.isPending

  const goToOverview = () => void navigate({ to: '/capturas/alertas' })
  const run = (p: string) => analyze.mutate(p, { onSuccess: goToOverview })

  async function browse() {
    if (!pickFile) return
    try {
      const picked = await pickFile()
      if (typeof picked === 'string' && picked) {
        setPath(picked)
        run(picked)
      }
    } catch (e) {
      toast.error(
        errorMessage(e) || 'No se pudo abrir el selector de archivos.'
      )
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Archivo de captura</CardTitle>
        <CardDescription>
          Un .pcap o .pcapng. Con «Examinar…» se autoriza solo el archivo que
          elijas; si escribís la ruta, tiene que estar en Descargas.
        </CardDescription>
      </CardHeader>
      <CardContent className='space-y-3'>
        <form
          className='space-y-2'
          onSubmit={(e) => {
            e.preventDefault()
            if (path.trim()) run(path.trim())
          }}
        >
          <Label htmlFor='path'>Ruta del archivo .pcap o .pcapng</Label>
          <div className='flex gap-2'>
            <Input
              id='path'
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder='Ruta de un archivo .pcap / .pcapng'
              disabled={busy}
              autoComplete='off'
              spellCheck={false}
            />
            {pickFile && (
              <Button
                type='button'
                variant='outline'
                onClick={() => void browse()}
                disabled={busy}
              >
                <FolderOpen /> Examinar…
              </Button>
            )}
          </div>
          <Button type='submit' disabled={busy || !path.trim()}>
            Analizar
          </Button>
        </form>
        <div className='border-t pt-3'>
          <Button
            variant='secondary'
            disabled={busy}
            onClick={() => demo.mutate(undefined, { onSuccess: goToOverview })}
          >
            <Play /> Modo demo
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function LiveCard() {
  const navigate = useNavigate()
  const interfaces = useInterfaces({ staleTime: 0 })
  const [iface, setIface] = useState('')
  const start = useLiveStart()
  const stop = useLiveStop()
  const status = useLiveStatus({
    refetchInterval: (q) => (q.state.data?.state === 'running' ? 1000 : false),
  })
  const running = status.data?.state === 'running'

  // Si el backend dice que terminó (límite de tiempo o de paquetes), se cierra solo.
  useEffect(() => {
    if (
      status.data?.state === 'finished' &&
      !stop.isPending &&
      !stop.isSuccess
    ) {
      stop.mutate(undefined, {
        onSuccess: () => void navigate({ to: '/capturas/alertas' }),
      })
    }
  }, [status.data?.state, stop, navigate])

  return (
    <Card>
      <CardHeader>
        <CardTitle>Captura en vivo</CardTitle>
        <CardDescription>
          Captura el tráfico de una interfaz de red de este equipo (puede
          requerir permisos de administrador).
        </CardDescription>
      </CardHeader>
      <CardContent className='space-y-3'>
        <Label htmlFor='iface'>Interfaz de red</Label>
        <Select value={iface} onValueChange={setIface} disabled={running}>
          <SelectTrigger id='iface' className='w-full'>
            <SelectValue placeholder='Elegí una interfaz' />
          </SelectTrigger>
          <SelectContent>
            {interfaces.data?.map((i) => (
              <SelectItem key={i.name} value={i.name}>
                {i.name}
                {i.description ? ` — ${i.description}` : ''}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {running ? (
          <Button
            variant='destructive'
            disabled={stop.isPending}
            onClick={() =>
              stop.mutate(undefined, {
                onSuccess: () => void navigate({ to: '/capturas/alertas' }),
              })
            }
          >
            <Square /> Detener y analizar
          </Button>
        ) : (
          <Button
            disabled={!iface || start.isPending}
            onClick={() => start.mutate({ interface: iface })}
          >
            <Radio /> Empezar a capturar
          </Button>
        )}
        {status.data && status.data.state !== 'idle' && (
          <p className='text-sm text-muted-foreground' role='status'>
            {running ? 'Capturando… ' : 'Captura terminada. '}
            {status.data.packets} paquetes · {status.data.seconds.toFixed(0)} s
            {!running && status.data.reason
              ? ` (${STOP_REASON[status.data.reason] ?? status.data.reason})`
              : ''}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
