import { captureFixtures } from './fixtures-capture'
import { supportFixtures } from './fixtures-support'

/** Todas las respuestas de ejemplo (una por endpoint), usadas por los handlers de MSW. */
export const fixtures = { ...captureFixtures, ...supportFixtures }
