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
    '@typescript-eslint/no-unused-vars': 'error',
  },
  overrides: [
    {
      files: ['helix-sdk-js/**/*.ts'],
      parserOptions: { project: ['./helix-sdk-js/tsconfig.json'] },
    },
    {
      files: ['cli/**/*.ts'],
      parserOptions: { project: ['./cli/tsconfig.json'] },
    },
    {
      files: ['did-hedera/**/*.ts'],
      parserOptions: { project: ['./did-hedera/tsconfig.json'] },
    },
    {
      files: ['langchain/**/*.ts'],
      parserOptions: { project: ['./langchain/tsconfig.json'] },
    },
    {
      files: ['mcp/**/*.ts'],
      parserOptions: { project: ['./mcp/tsconfig.json'] },
    },
    {
      files: ['widget/**/*.ts'],
      parserOptions: { project: ['./widget/tsconfig.json'] },
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
