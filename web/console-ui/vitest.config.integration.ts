import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['test/integration/**/*.spec.ts'],
    reporters: ['default', 'junit'],
    outputFile: {
      junit: 'test-results/ui-integration-junit.xml'
    }
  }
});
