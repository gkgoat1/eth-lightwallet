import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Phase 1 runs the ported suites against `legacy/` to prove the port is
    // faithful. Phase 2 flips `LWT_TARGET` to `src`.
    env: {
      LWT_TARGET: process.env.LWT_TARGET ?? 'legacy',
    },
    projects: [
      {
        test: {
          name: 'unit',
          include: ['test/unit/**/*.test.ts'],
          testTimeout: 20000,
          hookTimeout: 60000,
        },
      },
      {
        test: {
          name: 'e2e',
          include: ['test/e2e/**/*.test.ts'],
          testTimeout: 60000,
          hookTimeout: 120000,
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'lcov'],
    },
  },
});
