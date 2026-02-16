import { describe, expect, test } from 'vitest';
import {
  isAuthConfig,
  isAuditLogArray,
  isBackupTargetTestResponse,
  isBackupPolicyArray,
  isBackupRunArray,
  isBucket,
  isBucketSnapshotArray,
  isBucketSnapshotPolicyArray,
  isExternalBackupTargetArray,
  isObjectDetail,
  isPresignResponse,
  isReplicaModeResponse,
  isUser,
  isUserArray
} from '../../src/validators';

describe('validators unit', () => {
  registerUserTests();
  registerObjectDetailTests();
  registerPresignTests();
  registerArrayTests();
  registerAuthConfigTests();
  registerStorageValidatorTests();
  registerBucketValidatorTests();
  registerExternalTargetValidatorTests();
  registerReplicaModeValidatorTests();
});

function registerUserTests(): void {
  test('isUser accepts valid user object', () => {
    const value = buildUser(true);
    expect(isUser(value)).toBe(true);
  });

  test('isUser rejects invalid object', () => {
    const value = buildUser(false);
    expect(isUser(value)).toBe(false);
  });
}

function registerObjectDetailTests(): void {
  test('isObjectDetail validates metadata map values', () => {
    const valid = buildObjectDetail();
    const invalid = {
      ...valid,
      metadata: {
        owner: 'qa',
        retries: 2
      }
    };

    expect(isObjectDetail(valid)).toBe(true);
    expect(isObjectDetail(invalid)).toBe(false);
  });
}

function registerPresignTests(): void {
  test('isPresignResponse validates optional string headers', () => {
    const valid = {
      url: 'http://example.local/upload',
      headers: {
        'x-amz-date': '20260210T010203Z',
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD'
      }
    };
    const invalid = { url: 'http://example.local/upload', headers: { 'x-amz-date': 123 } };

    expect(isPresignResponse(valid)).toBe(true);
    expect(isPresignResponse(invalid)).toBe(false);
  });
}

function registerArrayTests(): void {
  test('array validators require every item to be valid', () => {
    const users = [buildUser(true), { ...buildUser(true), id: 'u2', username: 'bob', isAdmin: true }];
    const audit = [buildAudit('a1', { source: 'ui' })];
    const invalidAudit = [...audit, buildAudit('a2', 'not-an-object')];

    expect(isUserArray(users)).toBe(true);
    expect(isAuditLogArray(audit)).toBe(true);
    expect(isAuditLogArray(invalidAudit)).toBe(false);
  });
}

function buildAuthConfig(mode: 'internal' | 'oidc' | 'oauth2' | 'saml2'): Record<string, unknown> {
  if (mode === 'internal') {
    return {
      mode,
      externalAuthEnabled: false,
      externalAuthType: null,
      externalLoginPath: null,
      oidcEnabled: false,
      oidcLoginPath: null
    };
  }
  return {
    mode,
    externalAuthEnabled: true,
    externalAuthType: mode,
    externalLoginPath: '/console/v1/oidc/start',
    oidcEnabled: true,
    oidcLoginPath: '/console/v1/oidc/start'
  };
}

function registerAuthConfigTests(): void {
  test('isAuthConfig validates internal payload', () => {
    expect(isAuthConfig(buildAuthConfig('internal'))).toBe(true);
  });

  test('isAuthConfig validates external payloads', () => {
    expect(isAuthConfig(buildAuthConfig('oidc'))).toBe(true);
    expect(isAuthConfig(buildAuthConfig('oauth2'))).toBe(true);
    expect(isAuthConfig(buildAuthConfig('saml2'))).toBe(true);
  });

  test('isAuthConfig rejects invalid auth payload', () => {
    const invalid = {
      ...buildAuthConfig('oidc'),
      oidcEnabled: 'true'
    };
    expect(isAuthConfig(invalid)).toBe(false);
  });
}

function registerStorageValidatorTests(): void {
  test('storage validators accept valid snapshot and backup payloads', () => {
    const policies = [buildSnapshotPolicy()];
    const snapshots = [buildSnapshot()];
    const backupPolicies = [buildBackupPolicy()];
    const backupRuns = [buildBackupRun()];

    expect(isBucketSnapshotPolicyArray(policies)).toBe(true);
    expect(isBucketSnapshotArray(snapshots)).toBe(true);
    expect(isBackupPolicyArray(backupPolicies)).toBe(true);
    expect(isBackupRunArray(backupRuns)).toBe(true);
  });

  test('storage validators reject invalid payloads', () => {
    const invalidSnapshots = [{ ...buildSnapshot(), object_count: 'bad' }];
    const invalidRuns = [{ ...buildBackupRun(), archive_size_bytes: '12' }];

    expect(isBucketSnapshotArray(invalidSnapshots)).toBe(false);
    expect(isBackupRunArray(invalidRuns)).toBe(false);
  });
}

function registerBucketValidatorTests(): void {
  test('isBucket validates known versioning states', () => {
    const valid = {
      id: 'b1',
      name: 'bucket-1',
      createdAt: '2026-02-12T00:00:00Z',
      versioningStatus: 'enabled',
      publicRead: false,
      isWorm: false,
      boundNodeIds: ['node-1'],
      maxAvailableBytes: 1024
    };
    const invalid = { ...valid, versioningStatus: 'unknown' };
    expect(isBucket(valid)).toBe(true);
    expect(isBucket(invalid)).toBe(false);
  });
}

function registerExternalTargetValidatorTests(): void {
  test('external target validators accept valid payloads', () => {
    const targets = buildValidExternalTargets();
    const testReply = { ok: true, message: 'reachable' };
    expect(isExternalBackupTargetArray(targets)).toBe(true);
    expect(isBackupTargetTestResponse(testReply)).toBe(true);
  });

  test('external target validators reject invalid payloads', () => {
    const invalidTargets = buildInvalidExternalTargets();
    const invalidReply = { ok: 'true', message: 'reachable' };
    expect(isExternalBackupTargetArray(invalidTargets)).toBe(false);
    expect(isBackupTargetTestResponse(invalidReply)).toBe(false);
  });

  test('external target validators accept S3 kind-specific fields', () => {
    const targets = [buildS3ExternalTarget()];
    expect(isExternalBackupTargetArray(targets)).toBe(true);
  });

  test('external target validators accept glacier kind-specific fields', () => {
    const targets = [buildGlacierExternalTarget()];
    expect(isExternalBackupTargetArray(targets)).toBe(true);
  });

  test('external target validators accept sftp with credentials', () => {
    const targets = [buildSftpExternalTarget()];
    expect(isExternalBackupTargetArray(targets)).toBe(true);
  });

  test('external target validators reject non-string credential fields', () => {
    const targets = [{ ...buildS3ExternalTarget(), accessKeyId: 42 }];
    expect(isExternalBackupTargetArray(targets)).toBe(false);
  });
}

function registerReplicaModeValidatorTests(): void {
  test('isReplicaModeResponse accepts camelCase shape', () => {
    const valid = { nodeId: 'node-1', subMode: 'backup' };
    const invalid = { node_id: 'node-1', sub_mode: 'backup' };
    expect(isReplicaModeResponse(valid)).toBe(true);
    expect(isReplicaModeResponse(invalid)).toBe(false);
  });

  test('isReplicaModeResponse rejects unknown mode values', () => {
    const invalid = { nodeId: 'node-1', subMode: 'slave-backup' };
    expect(isReplicaModeResponse(invalid)).toBe(false);
  });
}

function buildValidExternalTargets(): Record<string, unknown>[] {
  return [
    {
      name: 'remote-1',
      kind: 's3',
      endpoint: 'https://backup.example.com/upload',
      enabled: true,
      method: 'PUT',
      headers: { Authorization: 'Bearer token' },
      timeoutSeconds: 10
    }
  ];
}

function buildInvalidExternalTargets(): Record<string, unknown>[] {
  return [
    {
      name: 'remote-1',
      kind: 's3',
      endpoint: 'https://backup.example.com/upload',
      headers: { Authorization: 42 }
    }
  ];
}

function buildUser(validAdmin: boolean): Record<string, unknown> {
  return {
    id: 'u1',
    username: 'alice',
    status: 'active',
    displayName: 'Alice',
    isAdmin: validAdmin ? true : 'yes'
  };
}

function buildObjectDetail(): Record<string, unknown> {
  return {
    key: 'bucket/file.txt',
    sizeBytes: 12,
    lastModified: '2026-02-10T00:00:00Z',
    etag: 'etag-1',
    contentType: 'text/plain',
    metadata: {
      owner: 'qa',
      scope: 'unit'
    }
  };
}

function buildAudit(id: string, details: unknown): Record<string, unknown> {
  return {
    id,
    ts: '2026-02-10T00:00:00Z',
    action: id === 'a1' ? 'login' : 'logout',
    outcome: 'success',
    actorUserId: id === 'a1' ? 'u1' : 'u2',
    actorIp: '127.0.0.1',
    targetType: 'user',
    targetId: id === 'a1' ? 'u1' : 'u2',
    details
  };
}

function buildSnapshotPolicy(): Record<string, unknown> {
  return {
    id: 'sp-1',
    bucket_id: 'bucket-1',
    trigger_kind: 'daily',
    retention_count: 7,
    enabled: true,
    last_snapshot_at: '2026-02-12T01:00:00Z',
    created_by_user_id: 'u1',
    created_at: '2026-02-12T00:00:00Z',
    updated_at: '2026-02-12T00:00:00Z'
  };
}

function buildSnapshot(): Record<string, unknown> {
  return {
    id: 'snap-1',
    bucket_id: 'bucket-1',
    trigger_kind: 'on_demand',
    created_by_user_id: 'u1',
    object_count: 2,
    total_size_bytes: 48,
    created_at: '2026-02-12T00:00:00Z'
  };
}

function buildBackupPolicy(): Record<string, unknown> {
  return {
    id: 'bp-1',
    name: 'daily policy',
    scope: 'master',
    node_id: null,
    source_bucket_id: 'bucket-source',
    backup_bucket_id: 'bucket-backup',
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
  };
}

function buildBackupRun(): Record<string, unknown> {
  return {
    id: 'br-1',
    policy_id: 'bp-1',
    snapshot_id: null,
    backup_type: 'full',
    changed_since: null,
    trigger_kind: 'on_demand',
    status: 'success',
    archive_format: 'tar.gz',
    archive_object_key: 'backups/br-1.tar.gz',
    archive_size_bytes: 128,
    error_text: null,
    started_at: '2026-02-12T00:00:00Z',
    completed_at: '2026-02-12T00:01:00Z'
  };
}

function buildS3ExternalTarget(): Record<string, unknown> {
  return {
    name: 'offsite-s3',
    kind: 's3',
    endpoint: 'https://s3.amazonaws.com',
    enabled: true,
    timeoutSeconds: 30,
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1',
    bucketName: 'my-backup-bucket'
  };
}

function buildGlacierExternalTarget(): Record<string, unknown> {
  return {
    name: 'archive-glacier',
    kind: 'glacier',
    endpoint: 'https://glacier.us-east-1.amazonaws.com',
    enabled: true,
    timeoutSeconds: 60,
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1',
    vaultName: 'my-archive-vault'
  };
}

function buildSftpExternalTarget(): Record<string, unknown> {
  return {
    name: 'sftp-target',
    kind: 'sftp',
    endpoint: 'sftp://backup.example.com:22/backups',
    enabled: true,
    timeoutSeconds: 15,
    username: 'backup-user',
    password: 's3cret'
  };
}
