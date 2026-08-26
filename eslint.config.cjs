const js = require('@eslint/js');
const tsParser = require('@typescript-eslint/parser');
const tsPlugin = require('@typescript-eslint/eslint-plugin');
const importPlugin = require('eslint-plugin-import');
const prettier = require('eslint-config-prettier');
const globals = require('globals');

/** @type {import('eslint').Linter.FlatConfig[]} */
module.exports = [
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      'consensus/**',
      'eslint.config.cjs',
      // Build artifacts of `packages/core/scripts/verify.sh`: the cloned
      // Thales checkout and Lake's dependency tree. Both are gitignored,
      // but they appear locally after a verify run and carry hundreds of
      // TypeScript fixtures that are deliberately malformed.
      '**/.thales/**',
      '**/.lake/**',
    ],
  },
  {
    files: ['**/*.cjs'],
    languageOptions: {
      globals: {
        ...globals.es2022,
        ...globals.node,
      },
      sourceType: 'script',
    },
  },
  js.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        ...globals.es2022,
        ...globals.node,
        // Node's WebCrypto and fetch are available in modern Node, but not always in eslint globals.
        crypto: 'readonly',
        fetch: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      import: importPlugin,
    },
    settings: {
      'import/resolver': {
        typescript: {
          project: './packages/tor/tsconfig.json',
        },
      },
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      ...importPlugin.configs.recommended.rules,
      ...importPlugin.configs.typescript.rules,
      ...prettier.rules,

      // TypeScript handles undefined identifiers.
      'no-undef': 'off',

      // This repo intentionally uses explicit `.ts` extensions under Node's TS loader.
      'import/extensions': [
        'error',
        'ignorePackages',
        {
          ts: 'always',
          js: 'always',
        },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
      // Keep iterating on typing quality without blocking lint on legacy `any` usage.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    files: ['**/*.spec.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    // Thales 0.5's parser rejects `export` declarations
    // (https://github.com/jessealama/thales filed as Issue 5 in
    // packages/core/docs/thales-issues.md), so every top-level
    // function and `const` in `packages/core/src/` is module-local
    // and appears "unused" to ESLint. The Lean side IS using these
    // — they're consumed by the emitted Generated/*.lean and
    // referenced in Spec/*.lean — so disable the rule for this
    // tree until Thales gains export support and the seam can
    // re-`export` properly.
    files: ['packages/core/src/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
  {
    files: ['**/*.cjs'],
    languageOptions: {
      sourceType: 'script',
    },
  },
];
