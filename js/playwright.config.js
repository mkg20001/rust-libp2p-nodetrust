// Browser tests for the demo page: `DEMO_DIR=$(nix build --print-out-paths ..#demo) npm run test:demo`
import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'test-demo',
  globalSetup: './test-demo/setup.js',
  timeout: 60_000,
  workers: 1,
  reporter: 'list',
  use: {
    browserName: 'chromium',
    // the fixture peer's WSS listener uses a self-signed certificate
    ignoreHTTPSErrors: true,
    launchOptions: { args: ['--ignore-certificate-errors'] }
  }
})
