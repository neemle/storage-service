import { beforeEach, describe, expect, test, vi } from 'vitest';

interface FetchCall {
  init: RequestInit | undefined;
  url: string;
}

interface MockResponse {
  body: string | Uint8Array | null;
  headers?: Record<string, string>;
  status: number;
}

function responseFromMock(reply: MockResponse): Response {
  const headers = reply.headers ?? {
    'Content-Type': 'application/json'
  };
  return new Response(reply.status === 204 ? null : reply.body, {
    status: reply.status,
    headers
  });
}

function createFetchStub(calls: FetchCall[], queue: MockResponse[]) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const rawUrl =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

    calls.push({ url: rawUrl, init });
    const next = queue.shift();
    if (!next) {
      throw new Error('No mock response queued');
    }
    return responseFromMock(next);
  };
}

function headerValue(headers: HeadersInit | undefined, key: string): string | undefined {
  if (!headers) {
    return undefined;
  }

  const normalizedKey = key.toLowerCase();
  if (headers instanceof Headers) {
    return headers.get(key) ?? undefined;
  }

  if (Array.isArray(headers)) {
    const found = headers.find(([name]) => name.toLowerCase() === normalizedKey);
    return found ? found[1] : undefined;
  }

  const found = Object.entries(headers).find(([name]) => name.toLowerCase() === normalizedKey);
  return found && typeof found[1] === 'string' ? found[1] : undefined;
}

function resetRuntimeConfig(apiBase: string): void {
  window.__API_BASE__ = apiBase;
  window.__CONSOLE_API_BASE__ = undefined;
  window.__ADMIN_API_BASE__ = undefined;
}

function userPayload() {
  return {
    id: 'u1',
    username: 'admin',
    status: 'active',
    displayName: 'Admin',
    isAdmin: true
  };
}

function loginReply(token: string): MockResponse {
  return {
    status: 200,
    body: JSON.stringify({
      token,
      user: userPayload()
    })
  };
}

function meReply(): MockResponse {
  return {
    status: 200,
    body: JSON.stringify(userPayload())
  };
}

function listObjectsReply(): MockResponse {
  return {
    status: 200,
    body: JSON.stringify([
      {
        key: 'folder/file.txt',
        sizeBytes: 12,
        lastModified: '2026-02-10T00:00:00Z',
        etag: 'etag',
        contentType: 'text/plain'
      }
    ])
  };
}

function snapshotPoliciesReply(): MockResponse {
  return {
    status: 200,
    body: JSON.stringify([
      {
        id: 'sp-1',
        bucket_id: 'bucket-1',
        trigger_kind: 'daily',
        retention_count: 7,
        enabled: true,
        last_snapshot_at: null,
        created_by_user_id: 'u1',
        created_at: '2026-02-12T00:00:00Z',
        updated_at: '2026-02-12T00:00:00Z'
      }
    ])
  };
}

describe('api integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
    resetRuntimeConfig('http://ui-api.local');
  });

  registerLoginGetMeTest();
  registerAuthConfigTest();
  registerLogoutTest();
  registerListObjectsTest();
  registerStorageAdminApiTests();
  registerBucketVolumeBindingApiTests();
  registerListBucketsApiTests();
  registerBucketUpdateTests();
  registerReplicaModeApiTests();
  registerReplicaModeAliasApiTest();
  registerBackupTargetConnectionTest();
  registerBackupTargetS3CredentialTest();
  registerExportBackupRunTest();
  registerInvalidJsonTest();
});

function registerLoginGetMeTest(): void {
  test('login then getMe sends bearer token', async () => {
    const calls: FetchCall[] = [];
    globalThis.fetch = createFetchStub(calls, [loginReply('token-1'), meReply()]);

    const api = await import('../../src/api');
    const loginResult = await api.login('admin', 'secret');
    const me = await api.getMe();

    expect(loginResult.token).toBe('token-1');
    expect(me.username).toBe('admin');
    expect(calls[0].url).toBe('http://ui-api.local/console/v1/login');
    expect(calls[1].url).toBe('http://ui-api.local/console/v1/me');
    expect(headerValue(calls[0].init?.headers, 'authorization')).toBeUndefined();
    expect(headerValue(calls[1].init?.headers, 'authorization')).toBe('Bearer token-1');
  });
}

function registerAuthConfigTest(): void {
  test('getAuthConfig reads auth mode payload', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      {
        status: 200,
        body: JSON.stringify({
          mode: 'oidc',
          externalAuthEnabled: true,
          externalAuthType: 'oidc',
          externalLoginPath: '/console/v1/oidc/start',
          oidcEnabled: true,
          oidcLoginPath: '/console/v1/oidc/start'
        })
      }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const config = await api.getAuthConfig();
    expect(config.mode).toBe('oidc');
    expect(config.externalAuthEnabled).toBe(true);
    expect(config.externalAuthType).toBe('oidc');
    expect(config.oidcEnabled).toBe(true);
    expect(calls[0].url).toBe('http://ui-api.local/console/v1/auth/config');
  });
}

function registerLogoutTest(): void {
  test('logout clears token for subsequent requests', async () => {
    const calls: FetchCall[] = [];
    const queue = [loginReply('token-2'), { status: 204, body: '' }, meReply()];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    await api.login('admin', 'secret');
    await api.logout();
    await api.getMe();

    expect(headerValue(calls[2].init?.headers, 'authorization')).toBeUndefined();
  });
}

function registerListObjectsTest(): void {
  test('listObjects preserves prefix query values', async () => {
    const calls: FetchCall[] = [];
    globalThis.fetch = createFetchStub(calls, [listObjectsReply()]);

    const api = await import('../../src/api');
    const result = await api.listObjects('my-bucket', 'folder with spaces/');

    expect(result).toHaveLength(1);
    const requestUrl = new URL(calls[0].url);
    expect(requestUrl.pathname).toBe('/console/v1/buckets/my-bucket/objects');
    expect(requestUrl.searchParams.get('prefix')).toBe('folder with spaces/');
  });
}

function registerInvalidJsonTest(): void {
  test('invalid JSON responses are rejected', async () => {
    const calls: FetchCall[] = [];
    globalThis.fetch = createFetchStub(calls, [{ status: 200, body: 'not-json' }]);

    const api = await import('../../src/api');
    await expect(api.getMe()).rejects.toThrow('Invalid JSON response');
    expect(calls[0].url).toBe('http://ui-api.local/console/v1/me');
  });
}

function registerStorageAdminApiTests(): void {
  test('storage admin endpoints use expected request shapes', async () => {
    const calls = prepareStorageAdminFetch();
    const result = await executeStorageAdminScenario(calls);
    assertStorageAdminScenario(calls, result);
  });
}

function registerBucketVolumeBindingApiTests(): void {
  test('updateBucketVolumes sends selected node ids', async () => {
    const calls: FetchCall[] = [];
    globalThis.fetch = createFetchStub(calls, [{ status: 204, body: null }]);

    const api = await import('../../src/api');
    await api.updateBucketVolumes('bucket-a', ['node-1', 'node-2']);

    expect(calls[0].url).toBe('http://ui-api.local/admin/v1/storage/buckets/bucket-a/volumes');
    expect(calls[0].init?.method).toBe('PATCH');
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ nodeIds: ['node-1', 'node-2'] });
  });
}

function registerListBucketsApiTests(): void {
  test('listBuckets validates max available and bound node fields', async () => {
    const calls: FetchCall[] = [];
    const bucket = {
      id: 'bucket-1',
      name: 'private-a',
      createdAt: '2026-02-12T00:00:00Z',
      versioningStatus: 'off',
      publicRead: false,
      isWorm: false,
      boundNodeIds: ['master-1', 'node-v1'],
      maxAvailableBytes: 4096
    };
    globalThis.fetch = createFetchStub(calls, [{ status: 200, body: JSON.stringify([bucket]) }]);

    const api = await import('../../src/api');
    const items = await api.listBuckets();

    expect(items).toHaveLength(1);
    expect(items[0].boundNodeIds).toEqual(['master-1', 'node-v1']);
    expect(items[0].maxAvailableBytes).toBe(4096);
    expect(calls[0].url).toBe('http://ui-api.local/console/v1/buckets');
  });
}

function registerBucketUpdateTests(): void {
  test('updateBucketVersioning sends camelCase payload', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [{ status: 204, body: null }];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    await api.updateBucketVersioning('bucket-v1', 'enabled');

    expect(calls[0].url).toBe('http://ui-api.local/console/v1/buckets/bucket-v1');
    expect(calls[0].init?.method).toBe('PATCH');
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ versioningStatus: 'enabled' });
  });
}

function backupPolicyReply(): MockResponse {
  return {
    status: 200,
    body: JSON.stringify({
      id: 'bp-1',
      name: 'policy',
      scope: 'master',
      node_id: null,
      source_bucket_id: 'source',
      backup_bucket_id: 'backup',
      backup_type: 'full',
      schedule_kind: 'daily',
      strategy: '3-2-1',
      retention_count: 4,
      enabled: true,
      external_targets_json: [],
      last_run_at: null,
      created_by_user_id: 'u1',
      created_at: '2026-02-12T00:00:00Z',
      updated_at: '2026-02-12T00:00:00Z'
    })
  };
}

function prepareStorageAdminFetch(): FetchCall[] {
  const calls: FetchCall[] = [];
  const queue: MockResponse[] = [
    { status: 204, body: null },
    snapshotPoliciesReply(),
    backupPolicyReply()
  ];
  globalThis.fetch = createFetchStub(calls, queue);
  return calls;
}

interface StorageAdminScenarioResult {
  backupName: string;
  policiesLength: number;
  wormBody: unknown;
}

async function executeStorageAdminScenario(calls: FetchCall[]): Promise<StorageAdminScenarioResult> {
  const api = await import('../../src/api');
  await api.updateBucketWorm('backup-bucket', true);
  const policies = await api.listSnapshotPolicies();
  const backup = await api.createBackupPolicy({
    name: 'policy',
    scope: 'master',
    sourceBucketName: 'source',
    backupBucketName: 'backup',
    backupType: 'full',
    scheduleKind: 'daily',
    strategy: '3-2-1',
    retentionCount: 4,
    enabled: true,
    externalTargets: []
  });
  const wormBody = JSON.parse((calls[0].init?.body ?? '').toString());
  return {
    backupName: backup.name,
    policiesLength: policies.length,
    wormBody
  };
}

function assertStorageAdminScenario(calls: FetchCall[], result: StorageAdminScenarioResult): void {
  expect(result.policiesLength).toBe(1);
  expect(result.backupName).toBe('policy');
  expect(calls[0].url).toBe('http://ui-api.local/admin/v1/storage/buckets/backup-bucket/worm');
  expect(calls[1].url).toBe('http://ui-api.local/admin/v1/storage/snapshot-policies');
  expect(calls[2].url).toBe('http://ui-api.local/admin/v1/storage/backup-policies');
  expect(result.wormBody).toEqual({ isWorm: true });
}

function registerReplicaModeApiTests(): void {
  test('updateReplicaMode accepts camelCase response payload', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      {
        status: 200,
        body: JSON.stringify({ nodeId: 'node-1', subMode: 'backup' })
      }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const result = await api.updateReplicaMode('node-1', 'backup');

    expect(result).toEqual({ nodeId: 'node-1', subMode: 'backup' });
    expect(calls[0].url).toBe('http://ui-api.local/admin/v1/cluster/nodes/node-1/mode');
  });

  test('updateReplicaMode normalizes legacy snake_case response payload', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      {
        status: 200,
        body: JSON.stringify({ node_id: 'node-2', sub_mode: 'volume' })
      }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const result = await api.updateReplicaMode('node-2', 'volume');

    expect(result).toEqual({ nodeId: 'node-2', subMode: 'volume' });
    expect(calls[0].url).toBe('http://ui-api.local/admin/v1/cluster/nodes/node-2/mode');
  });
}

function registerReplicaModeAliasApiTest(): void {
  test('updateReplicaMode accepts slave-* aliases in response payload', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      {
        status: 200,
        body: JSON.stringify({ nodeId: 'node-3', subMode: 'slave-backup' })
      }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const result = await api.updateReplicaMode('node-3', 'backup');

    expect(result).toEqual({ nodeId: 'node-3', subMode: 'backup' });
    expect(calls[0].url).toBe('http://ui-api.local/admin/v1/cluster/nodes/node-3/mode');
  });
}

function registerExportBackupRunTest(): void {
  test('exportBackupRun returns binary blob', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      {
        status: 200,
        body: new Uint8Array([1, 2, 3, 4]),
        headers: {
          'Content-Type': 'application/gzip'
        }
      }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const blob = await api.exportBackupRun('run-1', 'tar.gz');
    expect(blob).toBeInstanceOf(Blob);
    expect(blob.size).toBeGreaterThan(0);
    expect(calls[0].url).toContain('/admin/v1/storage/backups/runs/run-1/export?format=tar.gz');
  });
}

function registerBackupTargetConnectionTest(): void {
  test('testBackupTargetConnection posts target payload', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      { status: 200, body: JSON.stringify({ ok: true, message: 'reachable' }) }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const result = await api.testBackupTargetConnection({
      name: 'remote-1',
      kind: 's3',
      endpoint: 'https://backup.example.com/upload',
      method: 'PUT',
      enabled: true,
      timeoutSeconds: 10
    });

    expect(result.ok).toBe(true);
    expect(calls[0].url).toBe('http://ui-api.local/admin/v1/storage/backup-targets/test');
    const body = JSON.parse((calls[0].init?.body ?? '').toString());
    expect(body.target.name).toBe('remote-1');
    expect(body.target.kind).toBe('s3');
  });
}

function registerBackupTargetS3CredentialTest(): void {
  test('testBackupTargetConnection sends S3 credential fields', async () => {
    const calls: FetchCall[] = [];
    const queue: MockResponse[] = [
      { status: 200, body: JSON.stringify({ ok: true, message: 'reachable' }) }
    ];
    globalThis.fetch = createFetchStub(calls, queue);

    const api = await import('../../src/api');
    const result = await api.testBackupTargetConnection({
      name: 'offsite-s3',
      kind: 's3',
      endpoint: 'https://s3.amazonaws.com',
      enabled: true,
      timeoutSeconds: 30,
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY',
      region: 'us-east-1',
      bucketName: 'my-backup-bucket'
    });

    expect(result.ok).toBe(true);
    const body = JSON.parse((calls[0].init?.body ?? '').toString());
    expect(body.target.accessKeyId).toBe('AKIAIOSFODNN7EXAMPLE');
    expect(body.target.region).toBe('us-east-1');
    expect(body.target.bucketName).toBe('my-backup-bucket');
  });
}
