import { defineConfig } from 'vitest/config';
import browserConfig from './vitest.config.ts';

export default defineConfig({
  ...browserConfig,
  test: {
    ...browserConfig.test,
    name: 'browser-chutney',
    browser: {
      ...browserConfig.test?.browser,
      enabled: true,
      provider: 'playwright',
      instances: [
        {
          browser: 'chromium',
          ...(process.env.TOR_TS_CHROMIUM_EXECUTABLE
            ? {
                launch: { executablePath: process.env.TOR_TS_CHROMIUM_EXECUTABLE },
              }
            : {}),
        },
      ],
    },
    include: ['src/**/*.chutney.test.ts'],
    exclude: [],
    globalSetup: ['./scripts/chutney-setup.ts'],
    hookTimeout: 120_000,
    testTimeout: 300_000,
  },
});
