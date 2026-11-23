import { test, expect } from '@playwright/test'

const { DEMO_URL, HUB_ADDR, HUB_ID, PEER_ID } = process.env
const open = (page, impl) => page.goto(`${DEMO_URL}?impl=${impl}&issuer=${encodeURIComponent(HUB_ADDR)}`)
const item = (page, list, peer) => page.locator(`#${list} li[data-key="${peer}"]`)

for (const impl of ['js', 'wasm']) {
  test(`${impl}: dials the issuer, discovers a peer and dials it over WSS`, async ({ page }) => {
    await open(page, impl)
    await page.getByRole('button', { name: 'Start' }).click()
    await expect(page.getByRole('status')).toContainText(`running (${impl})`)
    await expect(item(page, 'conns', HUB_ID)).toBeVisible()
    await expect(item(page, 'peers', PEER_ID)).toContainText('/tls/ws')
    await expect(item(page, 'conns', PEER_ID)).toContainText('/tls/ws')
  })
}

test('switching implementation restarts the node, stop stops it', async ({ page }) => {
  await open(page, 'js')
  await page.getByRole('button', { name: 'Start' }).click()
  const status = page.getByRole('status')
  await expect(status).toContainText('running (js)')
  const jsState = await status.textContent()

  await page.getByLabel('Rust (wasm)').check()
  await expect(status).toContainText('running (wasm)')
  expect(await status.textContent()).not.toBe(jsState) // new peer id
  await expect(item(page, 'conns', HUB_ID)).toBeVisible()

  await page.getByRole('button', { name: 'Stop' }).click()
  await expect(status).toHaveText('stopped')
})
