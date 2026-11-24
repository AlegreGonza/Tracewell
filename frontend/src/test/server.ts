import { setupServer } from 'msw/node'
import { handlers } from './handlers'

/** Servidor MSW compartido (lo arranca y limpia src/test/setup.ts). */
export const server = setupServer(...handlers)
