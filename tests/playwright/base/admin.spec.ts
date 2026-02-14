import { expect, test } from '../fixtures';
import { loginAdmin } from '../helpers';

test('[UC-001][UC-004] admin login shows cluster nodes', async ({ page }) => {
  await loginAdmin(page);
  const clusterCard = page.locator('mat-card', { hasText: 'Cluster' });
  const nodeCount = await clusterCard.locator('mat-list-item').count();
  expect(nodeCount).toBeGreaterThan(0);
});
