// ESLint "flat config": an array of config objects, applied in order.
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,               // core JavaScript mistakes
      tseslint.configs.recommended,         // TypeScript-aware rules
      reactHooks.configs.flat.recommended,  // rules-of-hooks + exhaustive-deps
      reactRefresh.configs.vite,            // keeps hot reload working (components-only exports)
    ],
    languageOptions: {
      globals: globals.browser,
    },
  },
  {
    // shadcn-generated components (kept identical to upstream so the CLI can update them)
    // export style helpers like `buttonVariants` next to the component. That only costs a
    // full page reload instead of hot reload in dev; our own code keeps the rule.
    files: ['src/components/ui/**/*.{ts,tsx}'],
    rules: { 'react-refresh/only-export-components': 'off' },
  },
])
