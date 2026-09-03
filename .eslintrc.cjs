module.exports = {
  root: true,
  env: {
    node: true,
    es2022: true,
  },
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended'
  ],
  parserOptions: {
    tsconfigRootDir: __dirname,
  },
  rules: {
    'no-console': 'warn',
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/explicit-function-return-type': 'error',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
  },
  overrides: [
    {
      files: ['helix-sdk-js/**/*.ts'],
      parserOptions: { project: ['./helix-sdk-js/tsconfig.eslint.json'] },
    },
    {
      files: ['cli/**/*.ts'],
      parserOptions: { project: ['./cli/tsconfig.eslint.json'] },
    },
    {
      files: ['did-hedera/**/*.ts'],
      parserOptions: { project: ['./did-hedera/tsconfig.eslint.json'] },
    },
    {
      files: ['langchain/**/*.ts'],
      parserOptions: { project: ['./langchain/tsconfig.eslint.json'] },
    },
    {
      files: ['mcp-middleware/**/*.ts'],
      parserOptions: { project: ['./mcp-middleware/tsconfig.eslint.json'] },
    },
    {
      files: ['mcp-server/**/*.ts'],
      parserOptions: { project: ['./mcp-server/tsconfig.eslint.json'] },
    },
    {
      files: ['widget/**/*.ts'],
      parserOptions: { project: ['./widget/tsconfig.eslint.json'] },
    },
    {
      files: ['**/tests/**/*.ts', '**/*.test.ts', 'vitest.config.ts'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/explicit-function-return-type': 'off',
      },
    },
  ],
};
