import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { useRuleList } from './api'
import { RuleBuilder } from './components/rule-builder'
import { RulesList } from './components/rules-list'

/** Reglas de detección: las activas (con MITRE) y un formulario para crear reglas propias. */
export function Reglas() {
  const rules = useRuleList()
  return (
    <Page
      title='Reglas'
      description='Reglas de detección incluidas y reglas propias.'
    >
      <div className='space-y-6'>
        <QueryBoundary query={rules}>
          {(data) => (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>Reglas activas ({data.items.length})</CardTitle>
                  <CardDescription>
                    Cada alerta de la captura sale de una de estas reglas.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <RulesList rules={data.items} />
                </CardContent>
              </Card>
              <RuleBuilder example={data.example} />
            </>
          )}
        </QueryBoundary>
      </div>
    </Page>
  )
}
