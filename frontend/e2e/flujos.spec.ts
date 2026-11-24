import { expect, test, type Page } from '@playwright/test'

// El token viaja en el hash, como lo hace la ventana de escritorio al abrir la URL.
const abrir = (page: Page, ruta = '/') =>
  page.goto(`${ruta}#token=${process.env.E2E_TOKEN}`)

async function cargarDemo(page: Page) {
  await abrir(page)
  await page.getByRole('button', { name: 'Modo demo' }).click()
  await expect(page).toHaveURL(/\/capturas\/alertas/)
}

test('demo → alerta → sesión', async ({ page }) => {
  await cargarDemo(page)
  await page.locator('tbody tr').first().getByRole('button').click()
  const detalle = page.getByRole('dialog')
  await expect(detalle.getByText('MITRE ATT&CK:')).toBeVisible()
  await detalle.getByRole('link', { name: /^#\d+/ }).first().click()
  await expect(page).toHaveURL(/\/capturas\/sesiones\?.*sesion=\d+/)
  await expect(page.getByRole('dialog').getByText(/^Sesión #\d+/)).toBeVisible()
})

test('crear una regla propia', async ({ page }) => {
  await abrir(page, '/capturas/reglas')
  await page.getByRole('button', { name: 'Cargar ejemplo' }).click()
  await page.getByRole('button', { name: 'Guardar regla' }).click()
  await expect(page.getByText('Regla guardada')).toBeVisible()
})

test('filtrar sesiones por IP', async ({ page }) => {
  await cargarDemo(page)
  await page.getByRole('link', { name: 'Sesiones' }).first().click()
  const filas = page.locator('tbody tr')
  const ip = (await filas.first().locator('td').nth(2).innerText()).split(/[:\s]/)[0]
  await page.getByLabel('Filtrar por IP').fill(ip)
  await page.getByLabel('Filtrar por IP').press('Enter')
  await expect(page).toHaveURL(new RegExp(`ip=${ip.replaceAll('.', '[.]')}`))
  for (const fila of await filas.all()) await expect(fila).toContainText(ip)
})
