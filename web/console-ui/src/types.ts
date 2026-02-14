export interface User {
  id: string;
  username: string;
  displayName?: string | null;
  status: string;
  isAdmin: boolean;
  mustChangePassword?: boolean;
}

export interface AccessKey {
  accessKeyId: string;
  label: string;
  status: string;
  createdAt: string;
  lastUsedAt?: string | null;
}

export interface Bucket {
  id: string;
  name: string;
  createdAt: string;
  versioningStatus: string;
  publicRead: boolean;
  isWorm: boolean;
}

export type SnapshotTrigger =
  | 'hourly'
  | 'daily'
  | 'weekly'
  | 'monthly'
  | 'on_demand'
  | 'on_create_change';

export interface BucketSnapshotPolicy {
  id: string;
  bucket_id: string;
  trigger_kind: SnapshotTrigger;
  retention_count: number;
  enabled: boolean;
  last_snapshot_at?: string | null;
  created_by_user_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface BucketSnapshot {
  id: string;
  bucket_id: string;
  trigger_kind: SnapshotTrigger;
  created_by_user_id?: string | null;
  object_count: number;
  total_size_bytes: number;
  created_at: string;
}

export type BackupScope = 'master' | 'replica';
export type BackupType = 'full' | 'incremental' | 'differential';
export type BackupSchedule = 'hourly' | 'daily' | 'weekly' | 'monthly' | 'on_demand';
export type BackupStrategy = '3-2-1' | '3-2-1-1-0' | '4-3-2';
export type ExternalBackupTargetKind = 's3' | 'glacier' | 'sftp' | 'other';
export type ExternalBackupTargetMethod = 'PUT' | 'POST';

export interface ExternalBackupTarget {
  name: string;
  kind: ExternalBackupTargetKind;
  endpoint: string;
  enabled?: boolean;
  method?: ExternalBackupTargetMethod;
  headers?: Record<string, string> | null;
  timeoutSeconds?: number;
}

export interface BackupPolicy {
  id: string;
  name: string;
  scope: BackupScope;
  node_id?: string | null;
  source_bucket_id: string;
  backup_bucket_id: string;
  backup_type: BackupType;
  schedule_kind: BackupSchedule;
  strategy: BackupStrategy;
  retention_count: number;
  enabled: boolean;
  external_targets_json: unknown;
  last_run_at?: string | null;
  created_by_user_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface BackupRun {
  id: string;
  policy_id: string;
  snapshot_id?: string | null;
  backup_type: BackupType;
  changed_since?: string | null;
  trigger_kind: string;
  status: string;
  archive_format: 'tar' | 'tar.gz';
  archive_object_key?: string | null;
  archive_size_bytes?: number | null;
  error_text?: string | null;
  started_at: string;
  completed_at?: string | null;
}

export type ReplicaSubMode = 'delivery' | 'backup';

export interface ReplicaModeResponse {
  node_id: string;
  sub_mode: ReplicaSubMode;
}

export interface BackupTargetTestResponse {
  ok: boolean;
  message: string;
}

export interface BucketStats {
  name: string;
  sizeBytes: number;
  objectCount: number;
}

export interface ObjectItem {
  key: string;
  sizeBytes: number;
  etag?: string | null;
  contentType?: string | null;
  lastModified: string;
}

export interface ObjectDetail {
  key: string;
  sizeBytes: number;
  etag?: string | null;
  contentType?: string | null;
  lastModified: string;
  metadata: Record<string, string>;
}

export interface ObjectUrlResponse {
  url: string;
  public: boolean;
}

export interface NodeInfo {
  nodeId: string;
  role: string;
  addressInternal: string;
  status: string;
  lastHeartbeatAt?: string | null;
  capacityBytes?: number | null;
  freeBytes?: number | null;
}

export interface JoinToken {
  token: string;
  expiresAt: string;
}

export interface AuditLog {
  id: string;
  ts: string;
  actorUserId?: string | null;
  actorIp?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  outcome: string;
  details: Record<string, unknown>;
}

export interface LoginResponse {
  token: string;
  user: User;
}

export type AuthMode = 'internal' | 'oidc' | 'oauth2' | 'saml2';

export interface AuthConfig {
  mode: AuthMode;
  externalAuthEnabled: boolean;
  externalAuthType?: Exclude<AuthMode, 'internal'> | null;
  externalLoginPath?: string | null;
  oidcEnabled: boolean;
  oidcLoginPath?: string | null;
}

export interface SecretKeyResponse {
  accessKeyId: string;
  secretAccessKey: string;
}

export interface PresignResponse {
  url: string;
  headers?: Record<string, string> | null;
}
