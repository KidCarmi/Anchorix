// Anchorix ESLint flat config (ESLint v9+).
//
// Replaces .eslintrc.cjs. Lint intent kept as close to the old config
// as possible:
//
//   eslint:recommended                    -> @eslint/js  recommended
//   plugin:@typescript-eslint/recommended -> typescript-eslint recommended
//   plugin:react/recommended              -> eslint-plugin-react flat/recommended
//   plugin:react-hooks/recommended        -> eslint-plugin-react-hooks recommended
//
// Project-specific overrides preserved:
//   - react/react-in-jsx-scope: off (we use the new JSX transform)
//   - @typescript-eslint/no-unused-vars: error with `_` prefix exception
//
// Ignore patterns (`dist`, `node_modules`) are now under the flat-config
// `ignores` key.

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactPlugin from "eslint-plugin-react";
import reactHooksPlugin from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  // Global ignores. Flat config replaces .eslintrc.cjs `ignorePatterns`.
  { ignores: ["dist/**", "node_modules/**", "*.tsbuildinfo"] },

  // Base JS recommended rules — applies to .js / .mjs / .cjs as well as
  // TS files (typescript-eslint inherits and overrides where needed).
  js.configs.recommended,

  // TypeScript-recommended rules from typescript-eslint v8.
  ...tseslint.configs.recommended,

  // React + react-hooks rules. Limited to TS/TSX source files plus the
  // root config files Vite/Vitest read.
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
    },
    plugins: {
      react: reactPlugin,
      "react-hooks": reactHooksPlugin,
    },
    settings: { react: { version: "detect" } },
    rules: {
      ...reactPlugin.configs.flat.recommended.rules,
      ...reactHooksPlugin.configs.recommended.rules,
      "react/react-in-jsx-scope": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_" },
      ],
    },
  },
);
