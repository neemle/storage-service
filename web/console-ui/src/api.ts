import type {
  AccessKey,
  AuthConfig,
  AuditLog,
  BackupTargetTestResponse,
  BackupPolicy,
  BackupRun,
  Bucket,
  BucketSnapshot,
  BucketSnapshotPolicy,
  BackupSchedule,
  BackupScope,
  BackupStrategy,
  BackupType,
  ExternalBackupTarget,
  JoinToken,
  LoginResponse,
  NodeInfo,
  ObjectDetail,
  ObjectItem,
  ObjectUrlResponse,
  PresignResponse,
  ReplicaModeResponse,
  ReplicaSubMode,
  SecretKeyResponse,
  SnapshotTrigger,
  User
} from './types';
import {
  isAccessKeyArray,
  isAuthConfig,
  isAuditLogArray,
  isBackupPolicy,
  isBackupPolicyArray,
  isBackupRun,
  isBackupRunArray,
  isBackupTargetTestResponse,
  isBucketArray,
  isBucketSnapshot,
  isBucketSnapshotArray,
  isBucketSnapshotPolicy,
  isBucketSnapshotPolicyArray,
  isJoinToken,
  isLoginResponse,
  isNodeInfoArray,
  isObjectDetail,
  isObjectItemArray,
  isObjectUrlResponse,
  isPresignResponse,
  isReplicaModeResponse,
  isSecretKeyResponse,
  isUser,
  isUserArray
} from './validators';

declare global {
  interface Window {
    __API_BASE__?: string;
    __CONSOLE_API_BASE__?: string;
    __ADMIN_API_BASE__?: string;
  }
}

const baseUrl =
  typeof window === 'undefined'
    ? ''
    : window.__API_BASE__ ?? window.__CONSOLE_API_BASE__ ?? window.__ADMIN_API_BASE__ ?? '';
let authToken: string | null = null;

export interface CreateBackupPolicyPayload {
  name: string;
  scope: BackupScope;
  nodeId?: string;
  sourceBucketName: string;
  backupBucketName: string;
  backupType: BackupType;
  scheduleKind: BackupSchedule;
  strategy: BackupStrategy;
  retentionCount: number;
  enabled: boolean;
  externalTargets: ExternalBackupTarget[];
}

export interface UpdateBackupPolicyPayload {
  name?: string;
  backupType?: BackupType;
  scheduleKind?: BackupSchedule;
  strategy?: BackupStrategy;
  retentionCount?: number;
  enabled?: boolean;
  externalTargets?: ExternalBackupTarget[];
}

function toHeaderRecord(initHeaders?: HeadersInit): Record<string, string> {
  const result: Record<string, string> = {};
  if (!initHeaders) {
    return result;
  }
  if (initHeaders instanceof Headers) {
    initHeaders.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }
  if (Array.isArray(initHeaders)) {
    for (const entry of initHeaders) {
      if (entry.length === 2) {
        const [key, value] = entry;
        result[key] = value;
      }
    }
    return result;
  }
  for (const [key, value] of Object.entries(initHeaders)) {
    if (typeof value === 'string') {
      result[key] = value;
    }
  }
  return result;
}

function buildHeaders(initHeaders?: HeadersInit): Record<string, string> {
  const headers = toHeaderRecord(initHeaders);
  headers['Content-Type'] = 'application/json';
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  return headers;
}

async function apiFetch(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(`${baseUrl}${path}`, {
    credentials: 'include',
    ...init,
    headers: buildHeaders(init?.headers)
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  if (response.status === 204) {
    return null;
  }
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed;
  } catch {
    throw new Error('Invalid JSON response');
  }
}

async function apiFetchBlob(path: string, init?: RequestInit): Promise<Blob> {
  const response = await fetch(`${baseUrl}${path}`, {
    credentials: 'include',
    ...init,
    headers: buildHeaders(init?.headers)
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  return response.blob();
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const data = await apiFetch('/console/v1/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });
  if (!isLoginResponse(data)) {
    throw new Error('Invalid login response');
  }
  authToken = data.token;
  return data;
}

export async function getAuthConfig(): Promise<AuthConfig> {
  const data = await apiFetch('/console/v1/auth/config');
  if (!isAuthConfig(data)) {
    throw new Error('Invalid auth config response');
  }
  return data;
}

export async function logout(): Promise<void> {
  await apiFetch('/console/v1/logout', { method: 'POST' });
  authToken = null;
}

export async function getMe(): Promise<User> {
  const data = await apiFetch('/console/v1/me');
  if (!isUser(data)) {
    throw new Error('Invalid user response');
  }
  return data;
}

export async function listAccessKeys(): Promise<AccessKey[]> {
  const data = await apiFetch('/console/v1/access-keys');
  if (!isAccessKeyArray(data)) {
    throw new Error('Invalid access key response');
  }
  return data;
}

export async function createAccessKey(label: string): Promise<SecretKeyResponse> {
  const data = await apiFetch('/console/v1/access-keys', {
    method: 'POST',
    body: JSON.stringify({ label })
  });
  if (!isSecretKeyResponse(data)) {
    throw new Error('Invalid access key response');
  }
  return data;
}

export async function updateAccessKey(accessKeyId: string, status: string): Promise<void> {
  await apiFetch(`/console/v1/access-keys/${encodeURIComponent(accessKeyId)}`, {
    method: 'PATCH',
    body: JSON.stringify({ status })
  });
}

export async function deleteAccessKey(accessKeyId: string): Promise<void> {
  await apiFetch(`/console/v1/access-keys/${encodeURIComponent(accessKeyId)}`, {
    method: 'DELETE'
  });
}

export async function listBuckets(): Promise<Bucket[]> {
  const data = await apiFetch('/console/v1/buckets');
  if (!isBucketArray(data)) {
    throw new Error('Invalid bucket response');
  }
  return data;
}

export async function updateBucket(bucket: string, payload: { name?: string; publicRead?: boolean }): Promise<void> {
  await apiFetch(`/console/v1/buckets/${encodeURIComponent(bucket)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export async function renameBucket(bucket: string, name: string): Promise<void> {
  await updateBucket(bucket, { name });
}

export async function updateBucketPublic(bucket: string, publicRead: boolean): Promise<void> {
  await updateBucket(bucket, { publicRead });
}

export async function listObjects(bucket: string, prefix?: string): Promise<ObjectItem[]> {
  const params = new URLSearchParams();
  if (prefix) {
    params.set('prefix', prefix);
  }
  const query = params.toString();
  const path = query
    ? `/console/v1/buckets/${encodeURIComponent(bucket)}/objects?${query}`
    : `/console/v1/buckets/${encodeURIComponent(bucket)}/objects`;
  const data = await apiFetch(path);
  if (!isObjectItemArray(data)) {
    throw new Error('Invalid object list response');
  }
  return data;
}

export async function getObjectDetail(bucket: string, key: string): Promise<ObjectDetail> {
  const data = await apiFetch(`/console/v1/buckets/${encodeURIComponent(bucket)}/objects/${encodeURIComponent(key)}`);
  if (!isObjectDetail(data)) {
    throw new Error('Invalid object detail response');
  }
  return data;
}

export async function getObjectDownloadUrl(
  bucket: string,
  key: string,
  expiresSeconds?: number
): Promise<ObjectUrlResponse> {
  const params = new URLSearchParams();
  if (expiresSeconds) {
    params.set('expiresSeconds', expiresSeconds.toString());
  }
  const query = params.toString();
  const path = query
    ? `/console/v1/buckets/${encodeURIComponent(bucket)}/object-url/${encodeURIComponent(key)}?${query}`
    : `/console/v1/buckets/${encodeURIComponent(bucket)}/object-url/${encodeURIComponent(key)}`;
  const data = await apiFetch(path);
  if (!isObjectUrlResponse(data)) {
    throw new Error('Invalid object url response');
  }
  return data;
}

export async function updateObject(
  bucket: string,
  key: string,
  payload: { newKey?: string; metadata?: Record<string, string> }
): Promise<void> {
  await apiFetch(`/console/v1/buckets/${encodeURIComponent(bucket)}/objects/${encodeURIComponent(key)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export async function renameObject(bucket: string, key: string, newKey: string): Promise<void> {
  await updateObject(bucket, key, { newKey });
}

export async function updateObjectMetadata(
  bucket: string,
  key: string,
  metadata: Record<string, string>
): Promise<void> {
  await updateObject(bucket, key, { metadata });
}

export async function presignUrl(
  method: 'PUT' | 'GET' | 'DELETE',
  bucket: string,
  key?: string,
  expiresSeconds?: number,
  accessKeyId?: string
): Promise<PresignResponse> {
  const data = await apiFetch('/console/v1/presign', {
    method: 'POST',
    body: JSON.stringify({
      method,
      bucket,
      key: key ?? '',
      expiresSeconds,
      accessKeyId
    })
  });
  if (!isPresignResponse(data)) {
    throw new Error('Invalid presign response');
  }
  return data;
}

export async function listUsers(): Promise<User[]> {
  const data = await apiFetch('/admin/v1/users');
  if (!isUserArray(data)) {
    throw new Error('Invalid users response');
  }
  return data;
}

export async function createUser(
  username: string,
  password: string,
  displayName?: string,
  temporaryPassword?: boolean
): Promise<void> {
  await apiFetch('/admin/v1/users', {
    method: 'POST',
    body: JSON.stringify({ username, password, displayName, temporaryPassword })
  });
}

export async function updateUser(
  userId: string,
  payload: { status?: string; password?: string; temporaryPassword?: boolean }
): Promise<void> {
  await apiFetch(`/admin/v1/users/${encodeURIComponent(userId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await apiFetch('/console/v1/change-password', {
    method: 'POST',
    body: JSON.stringify({ currentPassword, newPassword })
  });
}

export async function listNodes(): Promise<NodeInfo[]> {
  const data = await apiFetch('/admin/v1/cluster/nodes');
  if (!isNodeInfoArray(data)) {
    throw new Error('Invalid node response');
  }
  return data;
}

export async function createJoinToken(): Promise<JoinToken> {
  const data = await apiFetch('/admin/v1/cluster/join-tokens', { method: 'POST' });
  if (!isJoinToken(data)) {
    throw new Error('Invalid join token response');
  }
  return data;
}

export async function listAuditLogs(offset?: number, limit?: number): Promise<AuditLog[]> {
  const params = new URLSearchParams();
  if (offset !== undefined) {
    params.set('offset', offset.toString());
  }
  if (limit !== undefined) {
    params.set('limit', limit.toString());
  }
  const query = params.toString();
  const path = query ? `/admin/v1/audit?${query}` : '/admin/v1/audit';
  const data = await apiFetch(path);
  if (!isAuditLogArray(data)) {
    throw new Error('Invalid audit response');
  }
  return data;
}

export async function updateBucketWorm(bucketName: string, isWorm: boolean): Promise<void> {
  await apiFetch(`/admin/v1/storage/buckets/${encodeURIComponent(bucketName)}/worm`, {
    method: 'PATCH',
    body: JSON.stringify({ isWorm })
  });
}

export async function upsertSnapshotPolicy(
  bucketName: string,
  triggerKind: SnapshotTrigger,
  retentionCount: number,
  enabled: boolean
): Promise<BucketSnapshotPolicy> {
  const data = await apiFetch('/admin/v1/storage/snapshot-policies', {
    method: 'POST',
    body: JSON.stringify({ bucketName, triggerKind, retentionCount, enabled })
  });
  if (!isBucketSnapshotPolicy(data)) {
    throw new Error('Invalid snapshot policy response');
  }
  return data;
}

export async function listSnapshotPolicies(): Promise<BucketSnapshotPolicy[]> {
  const data = await apiFetch('/admin/v1/storage/snapshot-policies');
  if (!isBucketSnapshotPolicyArray(data)) {
    throw new Error('Invalid snapshot policy list response');
  }
  return data;
}

export async function createSnapshot(
  bucketName: string,
  triggerKind?: SnapshotTrigger
): Promise<BucketSnapshot> {
  const data = await apiFetch('/admin/v1/storage/snapshots', {
    method: 'POST',
    body: JSON.stringify({ bucketName, triggerKind })
  });
  if (!isBucketSnapshot(data)) {
    throw new Error('Invalid snapshot response');
  }
  return data;
}

export async function listSnapshots(bucketName: string, offset?: number, limit?: number): Promise<BucketSnapshot[]> {
  const params = new URLSearchParams();
  if (offset !== undefined) {
    params.set('offset', offset.toString());
  }
  if (limit !== undefined) {
    params.set('limit', limit.toString());
  }
  const query = params.toString();
  const path = query
    ? `/admin/v1/storage/snapshots/${encodeURIComponent(bucketName)}?${query}`
    : `/admin/v1/storage/snapshots/${encodeURIComponent(bucketName)}`;
  const data = await apiFetch(path);
  if (!isBucketSnapshotArray(data)) {
    throw new Error('Invalid snapshot list response');
  }
  return data;
}

export async function restoreSnapshot(snapshotId: string, bucketName: string, ownerUserId?: string): Promise<void> {
  await apiFetch(`/admin/v1/storage/snapshots/${encodeURIComponent(snapshotId)}/restore`, {
    method: 'POST',
    body: JSON.stringify({ bucketName, ownerUserId })
  });
}

export async function createBackupPolicy(payload: CreateBackupPolicyPayload): Promise<BackupPolicy> {
  const data = await apiFetch('/admin/v1/storage/backup-policies', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  if (!isBackupPolicy(data)) {
    throw new Error('Invalid backup policy response');
  }
  return data;
}

export async function testBackupTargetConnection(
  target: ExternalBackupTarget
): Promise<BackupTargetTestResponse> {
  const data = await apiFetch('/admin/v1/storage/backup-targets/test', {
    method: 'POST',
    body: JSON.stringify({ target })
  });
  if (!isBackupTargetTestResponse(data)) {
    throw new Error('Invalid backup target test response');
  }
  return data;
}

export async function listBackupPolicies(): Promise<BackupPolicy[]> {
  const data = await apiFetch('/admin/v1/storage/backup-policies');
  if (!isBackupPolicyArray(data)) {
    throw new Error('Invalid backup policy list response');
  }
  return data;
}

export async function updateBackupPolicy(policyId: string, payload: UpdateBackupPolicyPayload): Promise<BackupPolicy> {
  const data = await apiFetch(`/admin/v1/storage/backup-policies/${encodeURIComponent(policyId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
  if (!isBackupPolicy(data)) {
    throw new Error('Invalid updated backup policy response');
  }
  return data;
}

export async function runBackupPolicy(policyId: string): Promise<BackupRun> {
  const data = await apiFetch(`/admin/v1/storage/backups/${encodeURIComponent(policyId)}/run`, {
    method: 'POST'
  });
  if (!isBackupRun(data)) {
    throw new Error('Invalid backup run response');
  }
  return data;
}

export async function listBackupRuns(offset?: number, limit?: number): Promise<BackupRun[]> {
  const params = new URLSearchParams();
  if (offset !== undefined) {
    params.set('offset', offset.toString());
  }
  if (limit !== undefined) {
    params.set('limit', limit.toString());
  }
  const query = params.toString();
  const path = query ? `/admin/v1/storage/backups/runs?${query}` : '/admin/v1/storage/backups/runs';
  const data = await apiFetch(path);
  if (!isBackupRunArray(data)) {
    throw new Error('Invalid backup run list response');
  }
  return data;
}

export async function exportBackupRun(runId: string, format: 'tar' | 'tar.gz'): Promise<Blob> {
  const base = `/admin/v1/storage/backups/runs/${encodeURIComponent(runId)}/export`;
  const path = `${base}?format=${encodeURIComponent(format)}`;
  return apiFetchBlob(path, { method: 'GET' });
}

export async function updateReplicaMode(nodeId: string, subMode: ReplicaSubMode): Promise<ReplicaModeResponse> {
  const data = await apiFetch(`/admin/v1/cluster/nodes/${encodeURIComponent(nodeId)}/mode`, {
    method: 'PATCH',
    body: JSON.stringify({ subMode })
  });
  if (!isReplicaModeResponse(data)) {
    throw new Error('Invalid replica mode response');
  }
  return data;
}
