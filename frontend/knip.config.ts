import type { KnipConfig } from 'knip'

// Los componentes `ui/` son de la plantilla shadcn-admin: se usan a demanda.
const config: KnipConfig = {
  ignore: ['src/components/ui/**'],
  ignoreIssues: {
    'src/lib/api/**': ['exports', 'types'],
    'src/lib/utils.ts': ['exports'],
    'src/context/**': ['exports'],
    'src/test/**': ['exports', 'types'],
  },
}

export default config
