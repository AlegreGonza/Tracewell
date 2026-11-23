import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import { defineConfig, globalIgnores } from "eslint/config";

// Configuración mínima: reglas recomendadas, variables sin uso y reglas de hooks.
export default defineConfig([
  globalIgnores(["dist"]),
  js.configs.recommended,
  {
    files: ["**/*.{js,jsx}"],
    plugins: { "react-hooks": reactHooks },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      "no-unused-vars": ["error", { varsIgnorePattern: "^_", argsIgnorePattern: "^_", caughtErrors: "none", ignoreRestSiblings: true }],
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
  {
    // Los tests corren en vitest con globals: true
    files: ["**/*.test.{js,jsx}", "src/test/**"],
    languageOptions: { globals: { ...globals.vitest, ...globals.node } },
    // Los mocks de componentes usan hooks dentro de funciones auxiliares
    rules: { "react-hooks/rules-of-hooks": "off", "react-hooks/exhaustive-deps": "off" },
  },
]);
