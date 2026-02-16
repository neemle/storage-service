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
  ExternalBackupTarget,
  JoinToken,
  LoginResponse,
  NodeInfo,
  ObjectDetail,
  ObjectItem,
  ObjectUrlResponse,
  PresignResponse,
  ReplicaModeResponse,
  SecretKeyResponse,
  User
} from './types';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !Number.isNaN(value);
}

function isBucketVersioningStatus(value: unknown): value is 'off' | 'enabled' | 'suspended' {
  return value === 'off' || value === 'enabled' || value === 'suspended';
}

function isNullableString(value: unknown): value is string | null | undefined {
  return value === null || value === undefined || typeof value === 'string';
}

function isNullableNumber(value: unknown): value is number | null | undefined {
  return value === null || value === undefined || typeof value === 'number';
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (!isRecord(value)) {
    return false;
  }
  for (const entry of Object.values(value)) {
    if (typeof entry !== 'string') {
      return false;
    }
  }
  return true;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isString);
}

function isNullableReplicaSubMode(value: unknown): value is 'delivery' | 'backup' | 'volume' | null | undefined {
  return (
    value === undefined ||
    value === null ||
    value === 'delivery' ||
    value === 'backup' ||
    value === 'volume'
  );
}

export function isUser(value: unknown): value is User {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['id']) &&
    isString(value['username']) &&
    isString(value['status']) &&
    isNullableString(value['displayName']) &&
    isBoolean(value['isAdmin'])
  );
}

export function isAccessKey(value: unknown): value is AccessKey {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['accessKeyId']) &&
    isString(value['label']) &&
    isString(value['status']) &&
    isString(value['createdAt']) &&
    isNullableString(value['lastUsedAt'])
  );
}

export function isBucket(value: unknown): value is Bucket {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['id']) &&
    isString(value['name']) &&
    isString(value['createdAt']) &&
    isBucketVersioningStatus(value['versioningStatus']) &&
    isBoolean(value['publicRead']) &&
    isBoolean(value['isWorm']) &&
    isStringArray(value['boundNodeIds']) &&
    isNumber(value['maxAvailableBytes'])
  );
}

export function isBucketSnapshotPolicy(value: unknown): value is BucketSnapshotPolicy {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['id']) &&
    isString(value['bucket_id']) &&
    isString(value['trigger_kind']) &&
    isNumber(value['retention_count']) &&
    isBoolean(value['enabled']) &&
    isNullableString(value['last_snapshot_at']) &&
    isNullableString(value['created_by_user_id']) &&
    isString(value['created_at']) &&
    isString(value['updated_at'])
  );
}

export function isBucketSnapshot(value: unknown): value is BucketSnapshot {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['id']) &&
    isString(value['bucket_id']) &&
    isString(value['trigger_kind']) &&
    isNullableString(value['created_by_user_id']) &&
    isNumber(value['object_count']) &&
    isNumber(value['total_size_bytes']) &&
    isString(value['created_at'])
  );
}

export function isBackupPolicy(value: unknown): value is BackupPolicy {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['id']) &&
    isString(value['name']) &&
    isString(value['scope']) &&
    isNullableString(value['node_id']) &&
    isString(value['source_bucket_id']) &&
    isString(value['backup_bucket_id']) &&
    isString(value['backup_type']) &&
    isString(value['schedule_kind']) &&
    isString(value['strategy']) &&
    isNumber(value['retention_count']) &&
    isBoolean(value['enabled']) &&
    isString(value['created_at']) &&
    isString(value['updated_at']) &&
    isNullableString(value['last_run_at']) &&
    isNullableString(value['created_by_user_id'])
  );
}

export function isBackupRun(value: unknown): value is BackupRun {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['id']) &&
    isString(value['policy_id']) &&
    isNullableString(value['snapshot_id']) &&
    isString(value['backup_type']) &&
    isNullableString(value['changed_since']) &&
    isString(value['trigger_kind']) &&
    isString(value['status']) &&
    isString(value['archive_format']) &&
    isNullableString(value['archive_object_key']) &&
    isNullableNumber(value['archive_size_bytes']) &&
    isNullableString(value['error_text']) &&
    isString(value['started_at']) &&
    isNullableString(value['completed_at'])
  );
}

export function isExternalBackupTarget(value: unknown): value is ExternalBackupTarget {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['name']) &&
    isString(value['kind']) &&
    isString(value['endpoint']) &&
    (value['enabled'] === undefined || isBoolean(value['enabled'])) &&
    (value['method'] === undefined || isString(value['method'])) &&
    (value['headers'] === undefined || value['headers'] === null || isStringRecord(value['headers'])) &&
    (value['timeoutSeconds'] === undefined || isNumber(value['timeoutSeconds'])) &&
    (value['accessKeyId'] === undefined || isString(value['accessKeyId'])) &&
    (value['secretAccessKey'] === undefined || isString(value['secretAccessKey'])) &&
    (value['region'] === undefined || isString(value['region'])) &&
    (value['bucketName'] === undefined || isString(value['bucketName'])) &&
    (value['vaultName'] === undefined || isString(value['vaultName'])) &&
    (value['username'] === undefined || isString(value['username'])) &&
    (value['password'] === undefined || isString(value['password']))
  );
}

export function isExternalBackupTargetArray(value: unknown): value is ExternalBackupTarget[] {
  return Array.isArray(value) && value.every(isExternalBackupTarget);
}

export function isBackupTargetTestResponse(value: unknown): value is BackupTargetTestResponse {
  if (!isRecord(value)) {
    return false;
  }
  return isBoolean(value['ok']) && isString(value['message']);
}

export function isReplicaModeResponse(value: unknown): value is ReplicaModeResponse {
  if (!isRecord(value)) {
    return false;
  }
  return isString(value['nodeId']) && isReplicaSubMode(value['subMode']);
}

function isReplicaSubMode(value: unknown): value is 'delivery' | 'backup' | 'volume' {
  return value === 'delivery' || value === 'backup' || value === 'volume';
}

export function isObjectItem(value: unknown): value is ObjectItem {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['key']) &&
    isNumber(value['sizeBytes']) &&
    isString(value['lastModified']) &&
    isNullableString(value['etag']) &&
    isNullableString(value['contentType'])
  );
}

export function isObjectDetail(value: unknown): value is ObjectDetail {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['key']) &&
    isNumber(value['sizeBytes']) &&
    isString(value['lastModified']) &&
    isNullableString(value['etag']) &&
    isNullableString(value['contentType']) &&
    isStringRecord(value['metadata'])
  );
}

export function isObjectUrlResponse(value: unknown): value is ObjectUrlResponse {
  if (!isRecord(value)) {
    return false;
  }
  return isString(value['url']) && isBoolean(value['public']);
}

export function isNodeInfo(value: unknown): value is NodeInfo {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isString(value['nodeId']) &&
    isString(value['role']) &&
    isString(value['addressInternal']) &&
    isString(value['status']) &&
    isNullableString(value['lastHeartbeatAt']) &&
    isNullableNumber(value['capacityBytes']) &&
    isNullableNumber(value['freeBytes']) &&
    isNullableReplicaSubMode(value['subMode'])
  );
}

export function isJoinToken(value: unknown): value is JoinToken {
  if (!isRecord(value)) {
    return false;
  }
  return isString(value['token']) && isString(value['expiresAt']);
}

export function isAuditLog(value: unknown): value is AuditLog {
  if (!isRecord(value)) {
    return false;
  }
  const details = value['details'];
  return (
    isString(value['id']) &&
    isString(value['ts']) &&
    isString(value['action']) &&
    isString(value['outcome']) &&
    isNullableString(value['actorUserId']) &&
    isNullableString(value['actorIp']) &&
    isNullableString(value['targetType']) &&
    isNullableString(value['targetId']) &&
    (details === undefined || details === null || isRecord(details))
  );
}

export function isLoginResponse(value: unknown): value is LoginResponse {
  if (!isRecord(value)) {
    return false;
  }
  return isString(value['token']) && isUser(value['user']);
}

export function isAuthConfig(value: unknown): value is AuthConfig {
  if (!isRecord(value)) {
    return false;
  }
  const mode = value['mode'];
  const validMode =
    mode === 'internal' || mode === 'oidc' || mode === 'oauth2' || mode === 'saml2';
  const externalAuthType = value['externalAuthType'];
  const validExternalType =
    externalAuthType === undefined ||
    externalAuthType === null ||
    externalAuthType === 'oidc' ||
    externalAuthType === 'oauth2' ||
    externalAuthType === 'saml2';
  return (
    validMode &&
    isBoolean(value['externalAuthEnabled']) &&
    validExternalType &&
    isNullableString(value['externalLoginPath']) &&
    isBoolean(value['oidcEnabled']) &&
    isNullableString(value['oidcLoginPath'])
  );
}

export function isSecretKeyResponse(value: unknown): value is SecretKeyResponse {
  if (!isRecord(value)) {
    return false;
  }
  return isString(value['accessKeyId']) && isString(value['secretAccessKey']);
}

export function isPresignResponse(value: unknown): value is PresignResponse {
  if (!isRecord(value)) {
    return false;
  }
  const headers = value['headers'];
  return isString(value['url']) && (headers === undefined || headers === null || isStringRecord(headers));
}

export function isUserArray(value: unknown): value is User[] {
  return Array.isArray(value) && value.every(isUser);
}

export function isAccessKeyArray(value: unknown): value is AccessKey[] {
  return Array.isArray(value) && value.every(isAccessKey);
}

export function isBucketArray(value: unknown): value is Bucket[] {
  return Array.isArray(value) && value.every(isBucket);
}

export function isObjectItemArray(value: unknown): value is ObjectItem[] {
  return Array.isArray(value) && value.every(isObjectItem);
}

export function isNodeInfoArray(value: unknown): value is NodeInfo[] {
  return Array.isArray(value) && value.every(isNodeInfo);
}

export function isAuditLogArray(value: unknown): value is AuditLog[] {
  return Array.isArray(value) && value.every(isAuditLog);
}

export function isBucketSnapshotPolicyArray(value: unknown): value is BucketSnapshotPolicy[] {
  return Array.isArray(value) && value.every(isBucketSnapshotPolicy);
}

export function isBucketSnapshotArray(value: unknown): value is BucketSnapshot[] {
  return Array.isArray(value) && value.every(isBucketSnapshot);
}

export function isBackupPolicyArray(value: unknown): value is BackupPolicy[] {
  return Array.isArray(value) && value.every(isBackupPolicy);
}

export function isBackupRunArray(value: unknown): value is BackupRun[] {
  return Array.isArray(value) && value.every(isBackupRun);
}
