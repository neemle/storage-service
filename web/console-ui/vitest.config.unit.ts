import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['test/unit/**/*.spec.ts'],
    reporters: ['default', 'junit'],
    outputFile: {
      junit: 'test-results/ui-unit-junit.xml'
    }
  }
});
