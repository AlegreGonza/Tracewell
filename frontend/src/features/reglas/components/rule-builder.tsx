import { useEffect, useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { CheckCircle2, FlaskConical, Loader2, Save } from 'lucide-react'
import { useForm, useWatch } from 'react-hook-form'
import { useSaveRule } from '@/lib/api/mutations'
import { errorMessage } from '@/lib/api/errors'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { ruleErrorMessage, useRulePreview } from '../api'
import {
  bodyIfValid,
  EMPTY_FORM,
  exampleToForm,
  PROTOCOL_OPTIONS,
  ruleFormSchema,
  SEVERITY_OPTIONS,
  TACTICS,
  toBody,
  type RuleFormValues,
} from '../schema'
import { RulePreview } from './rule-preview'

const DEBOUNCE_MS = 350

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return debounced
}

const selectClass =
  'h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm shadow-xs focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 outline-none'

type Props = { example: Record<string, unknown> | null }

/** Formulario de reglas nuevas (react-hook-form + zod) con vista previa y YAML en vivo. */
export function RuleBuilder({ example }: Props) {
  const form = useForm<RuleFormValues>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: EMPTY_FORM,
    mode: 'onChange',
  })
  const values = useWatch({ control: form.control }) as RuleFormValues
  const key = JSON.stringify(values)
  const stable = useMemo(() => JSON.parse(key) as RuleFormValues, [key])
  const debounced = useDebounced(stable, DEBOUNCE_MS)
  const body = useMemo(() => bodyIfValid(debounced), [debounced])
  const preview = useRulePreview(body)
  const save = useSaveRule()
  const [savedFile, setSavedFile] = useState<string | null>(null)

  const exists = preview.data?.exists === true
  const canSave =
    form.formState.isValid && !exists && !save.isPending && body !== null

  function onSubmit(v: RuleFormValues) {
    setSavedFile(null)
    save.mutate(toBody(v), {
      onSuccess: (r) => {
        setSavedFile(String(r.file ?? `${r.id ?? 'regla'}.yaml`))
        form.reset(EMPTY_FORM)
      },
    })
  }

  function loadExample() {
    if (!example) return
    setSavedFile(null)
    save.reset()
    form.reset(exampleToForm(example))
    void form.trigger()
  }

  const field = (
    name: keyof RuleFormValues,
    label: string,
    props: React.ComponentProps<typeof Input> = {},
    description?: string
  ) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field: f }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <FormControl>
            <Input {...props} {...f} />
          </FormControl>
          {description && <FormDescription>{description}</FormDescription>}
          <FormMessage />
        </FormItem>
      )}
    />
  )

  const select = (
    name: keyof RuleFormValues,
    label: string,
    options: readonly { value: string; label: string }[],
    description?: string
  ) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field: f }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <FormControl>
            <select className={selectClass} {...f}>
              {options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </FormControl>
          {description && <FormDescription>{description}</FormDescription>}
          <FormMessage />
        </FormItem>
      )}
    />
  )

  return (
    <Card>
      <CardHeader className='flex-row items-start justify-between gap-2'>
        <div className='space-y-1'>
          <CardTitle className='flex items-center gap-2'>
            <FlaskConical className='size-5' aria-hidden /> Crear una alerta
            nueva
          </CardTitle>
          <CardDescription>
            Elegí qué tráfico mirar y cuántas veces tiene que repetirse en un
            rato. Las reglas propias se guardan en tu carpeta de reglas (
            <code>%APPDATA%\Tracewell\rules</code> en Windows,{' '}
            <code>~/.config/tracewell/rules</code> en Linux y macOS); las
            incluidas no se tocan y la regla nueva vale desde la próxima captura
            que abras.
          </CardDescription>
        </div>
        <Button
          type='button'
          variant='outline'
          size='sm'
          onClick={loadExample}
          disabled={!example}
        >
          Cargar ejemplo
        </Button>
      </CardHeader>
      <CardContent className='grid gap-6 lg:grid-cols-2'>
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit)}
            aria-label='Datos de la regla'
            className='space-y-4'
            noValidate
          >
            <div className='grid gap-4 sm:grid-cols-2'>
              {field('name', 'Nombre', {
                maxLength: 80,
                placeholder: 'Ej.: Muchas conexiones al SSH',
                autoComplete: 'off',
              })}
              {select('severity', 'Severidad', SEVERITY_OPTIONS)}
            </div>
            <FormField
              control={form.control}
              name='description'
              render={({ field: f }) => (
                <FormItem>
                  <FormLabel>Descripción</FormLabel>
                  <FormControl>
                    <Textarea
                      rows={2}
                      placeholder='Qué significa que salte esta alerta'
                      {...f}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <fieldset className='space-y-3 rounded-md border p-3'>
              <legend className='px-1 text-sm font-medium'>
                Qué tráfico mirar (todo es opcional)
              </legend>
              <div className='grid gap-4 sm:grid-cols-2'>
                {select('protocol', 'Protocolo', PROTOCOL_OPTIONS)}
                {field(
                  'port',
                  'Puerto de destino',
                  { inputMode: 'numeric' },
                  '0 = cualquiera'
                )}
                {field('src_ip', 'IP o red de origen', {
                  placeholder: 'Ej.: 192.168.1.0/24',
                  autoComplete: 'off',
                })}
                {field('dst_ip', 'IP o red de destino', {
                  placeholder: 'Ej.: 10.0.0.5',
                  autoComplete: 'off',
                })}
              </div>
            </fieldset>
            <fieldset className='space-y-3 rounded-md border p-3'>
              <legend className='px-1 text-sm font-medium'>Umbral</legend>
              <div className='grid gap-4 sm:grid-cols-2'>
                {field('min_events', 'Cantidad de eventos', {
                  inputMode: 'numeric',
                })}
                {field('window_seconds', 'En una ventana de (segundos)', {
                  inputMode: 'decimal',
                })}
              </div>
            </fieldset>
            <fieldset className='space-y-3 rounded-md border p-3'>
              <legend className='px-1 text-sm font-medium'>
                MITRE ATT&amp;CK (opcional)
              </legend>
              <div className='grid gap-4 sm:grid-cols-2'>
                {select(
                  'mitre_tactic',
                  'Táctica',
                  [
                    { value: '', label: 'Por defecto (Reconnaissance)' },
                    ...TACTICS.map((t) => ({ value: t, label: t })),
                  ]
                )}
                {field('mitre_technique', 'ID de la técnica', {
                  placeholder: 'T1046',
                  autoComplete: 'off',
                })}
              </div>
              {field('mitre_name', 'Nombre de la técnica', {
                placeholder: 'Network Service Discovery',
                autoComplete: 'off',
              })}
              {field(
                'id',
                'Id de la regla',
                { placeholder: 'se genera a partir del nombre' },
                'Opcional. Minúsculas, números y _ (3 a 40).'
              )}
            </fieldset>

            {save.isError && (
              <Alert variant='destructive' role='alert'>
                <AlertTitle>No se pudo guardar la regla</AlertTitle>
                <AlertDescription>
                  {ruleErrorMessage(save.error)}
                </AlertDescription>
              </Alert>
            )}
            {savedFile && (
              <Alert role='status'>
                <CheckCircle2 />
                <AlertTitle>Regla guardada</AlertTitle>
                <AlertDescription>
                  Se guardó en <code>{savedFile}</code> dentro de tu carpeta de
                  reglas. Se aplicará a la próxima captura que abras.
                </AlertDescription>
              </Alert>
            )}
            <Button type='submit' disabled={!canSave}>
              {save.isPending ? (
                <Loader2 className='animate-spin' aria-hidden />
              ) : (
                <Save aria-hidden />
              )}
              {save.isPending ? 'Guardando…' : 'Guardar regla'}
            </Button>
          </form>
        </Form>

        <RulePreview
          preview={preview.data}
          loading={preview.isFetching}
          incomplete={body === null}
          error={preview.isError ? errorMessage(preview.error) : null}
        />
      </CardContent>
    </Card>
  )
}
