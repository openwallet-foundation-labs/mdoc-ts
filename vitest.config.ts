import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    watch: false,
    include: ['**/*.{test,tests}.ts'],
    setupFiles: ['./tests/setup.ts'],
  },
})