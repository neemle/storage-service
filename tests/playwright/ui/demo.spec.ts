import { expect, test } from '../fixtures';
import { humanClick, loginAdmin, waitForHuman } from '../helpers';

const DEMO_TITLE =
  '[DEMO][UC-001][UC-002][UC-003][UC-004][UC-005][UC-006][UC-007][UC-008]' +
  '[UC-009][UC-010][UC-011][UC-012][UC-013][UC-014][UC-015] customer demo flow';

test(DEMO_TITLE, async ({ page }) => {
    await loginAdmin(page);
    await expect(page.getByRole('heading', { name: 'Cluster' })).toBeVisible();

    await expect(page.getByRole('button', { name: 'Create user' })).toBeVisible();

    const storageCard = page.getByTestId('storage-protection-card');
    await humanClick(storageCard.getByRole('tab', { name: 'Buckets', exact: true }));
    await expect(storageCard.getByRole('combobox', { name: 'WORM bucket', exact: true })).toBeVisible();

    await waitForHuman(page, 1200);
  });
