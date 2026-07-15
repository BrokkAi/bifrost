// @ts-check

import eslint from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

const tsFiles = ["src/**/*.ts", "test/**/*.ts"];

export default tseslint.config(
  {
    ignores: ["node_modules/**", "out/**", "out-test/**"]
  },
  {
    ...eslint.configs.recommended,
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      globals: globals.node,
      sourceType: "module"
    }
  },
  {
    ...eslint.configs.recommended,
    files: tsFiles,
    rules: {
      ...eslint.configs.recommended.rules,
      "no-undef": "off"
    }
  },
  ...tseslint.configs.recommendedTypeChecked.map((config) => ({
    ...config,
    files: tsFiles
  })),
  {
    files: tsFiles,
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.test.json",
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        {
          prefer: "type-imports"
        }
      ]
    }
  }
);
