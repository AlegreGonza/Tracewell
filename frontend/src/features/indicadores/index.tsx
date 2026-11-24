import { useState } from 'react'
import { FolderOpen, Loader2, Trash2, Upload } from 'lucide-react'
import { toast } from 'sonner'
import { errorMessage } from '@/lib/api/errors'
import { useClearIocs, useLoadIocs } from '@/lib/api/mutations'
import { useIocs } from '@/lib/api/queries'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Page } from '@/components/page'
import { useNativePicker } from '@/hooks/use-native-picker'
import { QueryBoundary } from '@/components/query-boundary'
import { CardSkeleton } from '@/components/skeletons'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import { IocStatus } from './components/ioc-status'

const FORMATS = [
  ['Texto', 'Un indicador por línea (IP, red CIDR o dominio).'],
  ['CSV', 'Con una columna llamada value.'],
  ['STIX 2.1', 'Un archivo .json con indicadores de tipo STIX.'],
] as const

/** Indicadores de compromiso (IOC): cargar una lista, ver coincidencias y descartarla. */
export function Indicadores() {
  const iocs = useIocs()
  const load = useLoadIocs()
  const clear = useClearIocs()
  const [path, setPath] = useState('')
  const [confirming, setConfirming] = useState(false)
  const pickFile = useNativePicker()

  async function browse() {
    if (!pickFile) return
    try {
      const picked = await pickFile()
      if (typeof picked === 'string' && picked) {
        setPath(picked)
        load.mutate(picked, { onSuccess: () => setPath('') })
      }
    } catch (e) {
      toast.error(errorMessage(e) || 'No se pudo abrir el selector de archivos.')
    }
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const value = path.trim()
    if (!value) return
    load.mutate(value, { onSuccess: () => setPath('') })
  }

  return (
    <Page
      title='Indicadores (IOC)'
      description='Lista de indicadores de compromiso contra la captura.'
    >
      <div className='space-y-6'>
        <Card>
          <CardHeader>
            <CardTitle>Cargar una lista</CardTitle>
            <CardDescription>
              Elegí el archivo con «Examinar…» (se autoriza solo ese archivo) o
              escribí su ruta si está en Descargas. Extensiones: .txt, .csv,
              .json, .stix o .ioc. Formatos aceptados:
            </CardDescription>
          </CardHeader>
          <CardContent className='space-y-4'>
            <ul className='grid gap-2 text-sm sm:grid-cols-3'>
              {FORMATS.map(([name, hint]) => (
                <li key={name} className='rounded-md border p-2'>
                  <span className='font-medium'>{name}</span>
                  <span className='block text-muted-foreground'>{hint}</span>
                </li>
              ))}
            </ul>
            <form onSubmit={submit} className='flex flex-wrap items-end gap-2'>
              <div className='min-w-64 flex-1 space-y-1.5'>
                <Label htmlFor='ioc-path'>Ruta del archivo de indicadores</Label>
                <Input
                  id='ioc-path'
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder='C:\Users\usuario\Descargas\indicadores.txt'
                  disabled={load.isPending}
                  autoComplete='off'
                  spellCheck={false}
                />
              </div>
              <Button type='submit' disabled={load.isPending || !path.trim()}>
                {load.isPending ? (
                  <Loader2 className='animate-spin' aria-hidden />
                ) : (
                  <Upload aria-hidden />
                )}
                Cargar lista
              </Button>
              {pickFile && (
                <Button
                  type='button'
                  variant='outline'
                  onClick={() => void browse()}
                  disabled={load.isPending}
                >
                  <FolderOpen aria-hidden /> Examinar…
                </Button>
              )}
            </form>
            {load.isError && (
              <Alert variant='destructive' role='alert'>
                <AlertTitle>No se pudo cargar la lista</AlertTitle>
                <AlertDescription>{errorMessage(load.error)}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className='flex-row items-start justify-between gap-2'>
            <div className='space-y-1'>
              <CardTitle>Coincidencias</CardTitle>
              <CardDescription>
                Qué tanto de la captura coincide con la lista cargada.
              </CardDescription>
            </div>
            {iocs.data?.loaded && (
              <Button
                variant='outline'
                size='sm'
                onClick={() => setConfirming(true)}
              >
                <Trash2 aria-hidden /> Limpiar lista
              </Button>
            )}
          </CardHeader>
          <CardContent>
            <QueryBoundary query={iocs} skeleton={<CardSkeleton />}>
              {(status) => <IocStatus status={status} />}
            </QueryBoundary>
          </CardContent>
        </Card>
      </div>

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title='¿Limpiar la lista de indicadores?'
        desc='Se descarta la lista cargada y las marcas de coincidencia desaparecen de la captura. El archivo original no se toca.'
        confirmText='Limpiar lista'
        cancelBtnText='Cancelar'
        destructive
        isLoading={clear.isPending}
        handleConfirm={() =>
          clear.mutate(undefined, { onSettled: () => setConfirming(false) })
        }
      />
    </Page>
  )
}
