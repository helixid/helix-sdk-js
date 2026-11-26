import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Sample servers are their own workspace packages with their own test runs.
    exclude: [...configDefaults.exclude, 'examples/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/**/index.ts', 'src/types.ts'],
    },
  },
});
