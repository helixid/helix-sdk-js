import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Sample servers are their own workspace packages with their own test runs.
    exclude: [...configDefaults.exclude, 'examples/**'],
  },
});
