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
      'packages/tor/src/directory-authorities.json',
      'eslint.config.cjs',
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
    files: ['**/*.cjs'],
    languageOptions: {
      sourceType: 'script',
    },
  },
];
