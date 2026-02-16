import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatListModule } from '@angular/material/list';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTabsModule } from '@angular/material/tabs';
import {
  changePassword,
  createBackupPolicy,
  createJoinToken,
  createSnapshot,
  createUser,
  createAccessKey,
  deleteAccessKey,
  exportBackupRun,
  getAuthConfig,
  getMe,
  getObjectDownloadUrl,
  getObjectDetail,
  listAccessKeys,
  listAuditLogs,
  listBackupPolicies,
  listBackupRuns,
  listBuckets,
  listNodes,
  listSnapshotPolicies,
  listSnapshots,
  listUsers,
  listObjects,
  login,
  logout,
  presignUrl,
  renameBucket,
  renameObject,
  restoreSnapshot,
  runBackupPolicy,
  testBackupTargetConnection,
  updateUser,
  updateAccessKey,
  updateBackupPolicy,
  updateBucketPublic,
  updateBucketVolumes,
  updateBucketVersioning,
  updateBucketWorm,
  updateObjectMetadata,
  updateReplicaMode,
  upsertSnapshotPolicy
} from '../api';
import { ConsoleHeaderComponent } from './components/console-header.component';
import { SecretBannerComponent } from './components/secret-banner.component';
import { SettingsModalComponent } from './components/settings-modal.component';
import { StorageAdminComponent } from './components/storage-admin.component';
import { LoginPageComponent } from './pages/login-page.component';
import { PasswordChangePageComponent } from './pages/password-change-page.component';
import type {
  AccessKey,
  AuthMode,
  AuditLog,
  BackupPolicy,
  BackupRun,
  BackupSchedule,
  BackupScope,
  BackupStrategy,
  BackupType,
  Bucket,
  BucketVersioningStatus,
  BucketSnapshot,
  BucketSnapshotPolicy,
  BucketStats,
  ExternalBackupTarget,
  JoinToken,
  NodeInfo,
  ObjectDetail,
  ObjectItem,
  ObjectUrlResponse,
  ReplicaSubMode,
  SnapshotTrigger,
  User
} from '../types';

type TabKey = 'buckets' | 'objects' | 'keys' | 'admin';
type ThemeMode = 'auto' | 'light' | 'dark';

const DEFAULT_LABEL = 'console-key';
const SETTINGS_KEY = 'nss-console-settings';
const SNAPSHOT_TRIGGERS: SnapshotTrigger[] = ['hourly', 'daily', 'weekly', 'monthly', 'on_create_change'];
const BACKUP_TYPES: BackupType[] = ['full', 'incremental', 'differential'];
const BACKUP_SCHEDULES: BackupSchedule[] = ['hourly', 'daily', 'weekly', 'monthly', 'on_demand'];
const BACKUP_STRATEGIES: BackupStrategy[] = ['3-2-1', '3-2-1-1-0', '4-3-2'];
const BUCKET_VERSIONING_OPTIONS: BucketVersioningStatus[] = ['off', 'enabled', 'suspended'];
const BACKUP_WIZARD_STEPS = ['Scope', 'Buckets', 'Policy', 'Targets'];
const TARGET_KIND_OPTIONS: ExternalBackupTarget['kind'][] = ['s3', 'sftp', 'ssh', 'glacier', 'other'];
const TARGET_METHOD_OPTIONS: Array<ExternalBackupTarget['method'] | ''> = ['', 'PUT', 'POST'];

interface WizardTarget {
  name: string;
  kind: ExternalBackupTarget['kind'];
  endpoint: string;
  method: ExternalBackupTarget['method'] | '';
  enabled: boolean;
  headerKey: string;
  headerValue: string;
  headers: Array<{ key: string; value: string }>;
  timeoutSeconds: string;
}

type WizardTargetScalarField =
  | 'name' | 'kind' | 'endpoint' | 'method'
  | 'enabled' | 'headerKey' | 'headerValue'
  | 'timeoutSeconds';

interface AppSettings {
  theme: ThemeMode;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatListModule,
    MatSelectModule,
    MatSlideToggleModule,
    MatTabsModule,
    ConsoleHeaderComponent,
    LoginPageComponent,
    PasswordChangePageComponent,
    SecretBannerComponent,
    SettingsModalComponent,
    StorageAdminComponent
  ],
  templateUrl: './app.component.html'
})
export class AppComponent {
  private readonly cdr = inject(ChangeDetectorRef);
  readonly appVm = this;
  readonly activeTab = signal<TabKey>('buckets');
  readonly user = signal<User | null>(null);
  readonly isAdmin = computed(() => this.user()?.isAdmin ?? false);
  readonly buckets = signal<Bucket[]>([]);
  readonly bucketStats = signal<Map<string, BucketStats>>(new Map());
  readonly bucketStatsLoading = signal(false);
  private statsWorkerInterval: ReturnType<typeof setInterval> | null = null;
  readonly keys = signal<AccessKey[]>([]);
  readonly adminUsers = signal<User[]>([]);
  readonly nodes = signal<NodeInfo[]>([]);
  readonly joinToken = signal<JoinToken | null>(null);
  readonly auditLogs = signal<AuditLog[]>([]);
  readonly auditLoading = signal(false);
  readonly selectedBucket = signal('');
  readonly objects = signal<ObjectItem[]>([]);
  readonly currentPrefix = signal('');
  readonly searchTerm = signal('');
  readonly uploadKey = signal('');
  readonly objectLoading = signal(false);
  readonly uploading = signal(false);
  readonly error = signal('');
  readonly loading = signal(true);
  readonly secret = signal<{ accessKeyId: string; secretAccessKey: string } | null>(null);
  readonly label = signal(DEFAULT_LABEL);
  readonly newBucketName = signal('');
  readonly bucketBusy = signal(false);
  readonly renamingBucket = signal<string | null>(null);
  readonly renameBucketValue = signal('');
  readonly selectedObject = signal<ObjectItem | null>(null);
  readonly objectDetail = signal<ObjectDetail | null>(null);
  readonly objectUrl = signal<ObjectUrlResponse | null>(null);
  readonly objectUrlLoading = signal(false);
  readonly metadataDraft = signal('');
  readonly editingMetadata = signal(false);
  readonly renameObjectValue = signal('');
  readonly renamingObjectKey = signal<string | null>(null);
  readonly loginUsername = signal('');
  readonly loginPassword = signal('');
  readonly authMode = signal<AuthMode>('internal');
  readonly externalLoginPath = signal<string | null>(null);
  readonly newUsername = signal('');
  readonly newDisplay = signal('');
  readonly newPassword = signal('');
  readonly newUserTempPassword = signal(true);

  // Theme and settings
  readonly themeMode = signal<ThemeMode>('auto');
  readonly userMenuOpen = signal(false);
  readonly settingsOpen = signal(false);

  // Password change
  readonly mustChangePassword = signal(false);
  readonly currentPassword = signal('');
  readonly newPasswordInput = signal('');
  readonly confirmPassword = signal('');
  readonly passwordChangeError = signal('');
  readonly passwordChanging = signal(false);

  // Audit pagination
  readonly auditPage = signal(0);
  readonly auditPageSize = 20;
  readonly auditHasMore = signal(true);
  readonly storageLoading = signal(false);
  readonly snapshotPolicies = signal<BucketSnapshotPolicy[]>([]);
  readonly snapshots = signal<BucketSnapshot[]>([]);
  readonly backupPolicies = signal<BackupPolicy[]>([]);
  readonly backupRuns = signal<BackupRun[]>([]);
  readonly replicaModes = signal<Map<string, ReplicaSubMode>>(new Map());
  readonly storageBucketName = signal('');
  readonly wormBucketName = signal('');
  readonly volumeBucketName = signal('');
  readonly selectedVolumeNodeIds = signal<string[]>([]);
  readonly wormEnabled = signal(true);
  readonly snapshotTrigger = signal<SnapshotTrigger>('daily');
  readonly snapshotRetention = signal(7);
  readonly snapshotPolicyEnabled = signal(true);
  readonly backupName = signal('');
  readonly backupScope = signal<BackupScope>('master');
  readonly backupNodeId = signal('');
  readonly backupSourceBucketName = signal('');
  readonly backupTargetBucketName = signal('');
  readonly backupType = signal<BackupType>('full');
  readonly backupSchedule = signal<BackupSchedule>('daily');
  readonly backupStrategy = signal<BackupStrategy>('3-2-1');
  readonly backupRetention = signal(7);
  readonly backupEnabled = signal(true);
  readonly backupExternalTargets = signal('[]');
  readonly backupWizardOpen = signal(false);
  readonly backupWizardStep = signal(0);
  readonly externalTargetsExampleOpen = signal(false);
  readonly wizardTargets = signal<WizardTarget[]>([]);
  readonly editingSnapshotPolicyId = signal('');
  readonly editingBackupPolicyId = signal('');

  readonly snapshotTriggerOptions = SNAPSHOT_TRIGGERS;
  readonly backupTypeOptions = BACKUP_TYPES;
  readonly backupScheduleOptions = BACKUP_SCHEDULES;
  readonly backupStrategyOptions = BACKUP_STRATEGIES;
  readonly bucketVersioningOptions = BUCKET_VERSIONING_OPTIONS;
  readonly backupWizardSteps = BACKUP_WIZARD_STEPS;
  readonly targetKindOptions = TARGET_KIND_OPTIONS;
  readonly targetMethodOptions = TARGET_METHOD_OPTIONS;
  readonly backupExternalTargetsExample = JSON.stringify(
    [
      {
        name: 'offsite-s3',
        kind: 's3',
        endpoint: 'https://storage.example.com/offsite/{objectKey}',
        method: 'PUT',
        enabled: true,
        timeoutSeconds: 20,
        headers: {
          Authorization: 'Bearer <token>'
        }
      },
      {
        name: 'archive-sftp-gateway',
        kind: 'sftp',
        endpoint: 'https://gateway.example.com/sftp/upload/{objectKey}',
        method: 'PUT',
        enabled: true,
        timeoutSeconds: 20,
        headers: {
          Authorization: 'Bearer <token>'
        }
      },
      {
        name: 'archive-ssh-gateway',
        kind: 'ssh',
        endpoint: 'https://gateway.example.com/ssh/upload/{objectKey}',
        method: 'PUT',
        enabled: true,
        timeoutSeconds: 20,
        headers: {
          Authorization: 'Bearer <token>'
        }
      }
    ],
    null,
    2
  );

  readonly effectiveTheme = computed(() => {
    const mode = this.themeMode();
    if (mode === 'auto') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return mode;
  });

  readonly breadcrumbs = computed(() => {
    const segments = this.currentPrefix().split('/').filter((segment) => segment.length > 0);
    const items: { label: string; prefix: string }[] = [];
    let built = '';
    for (const segment of segments) {
      built += `${segment}/`;
      items.push({ label: segment, prefix: built });
    }
    return items;
  });

  readonly availableTabs = computed<TabKey[]>(() => {
    if (this.isAdmin()) {
      return ['buckets', 'objects', 'keys', 'admin'];
    }
    return ['buckets', 'objects', 'keys'];
  });

  readonly tabIndex = computed(() => {
    const index = this.availableTabs().indexOf(this.activeTab());
    return index >= 0 ? index : 0;
  });

  readonly recentAudit = computed(() => this.auditLogs());

  readonly totalStorageUsed = computed(() => {
    let total = 0;
    this.bucketStats().forEach(stat => {
      total += stat.sizeBytes;
    });
    return total;
  });

  readonly bucketNameById = computed(() => {
    const map = new Map<string, string>();
    for (const bucket of this.buckets()) {
      map.set(bucket.id, bucket.name);
    }
    return map;
  });

  readonly bucketIdByName = computed(() => {
    const map = new Map<string, string>();
    for (const bucket of this.buckets()) {
      map.set(bucket.name, bucket.id);
    }
    return map;
  });

  readonly replicaNodes = computed(() => this.nodes().filter((node) => node.role === 'replica'));
  readonly volumeEligibleNodes = computed(() =>
    this.nodes().filter((node) => this.isVolumeEligibleNode(node))
  );
  readonly selectedVolumeBucketMaxAvailable = computed(() => {
    const bucket = this.buckets().find((entry) => entry.name === this.volumeBucketName());
    return bucket?.maxAvailableBytes ?? 0;
  });
  readonly editingBackupPolicy = computed(() => this.editingBackupPolicyId().length > 0);

  readonly snapshotPoliciesForBucket = computed(() => {
    const bucketId = this.bucketIdByName().get(this.storageBucketName()) ?? '';
    if (!bucketId) {
      return [];
    }
    return this.snapshotPolicies().filter((policy) => policy.bucket_id === bucketId);
  });

  readonly bucketStatsForChart = computed(() => {
    const stats: BucketStats[] = [];
    this.bucketStats().forEach(stat => {
      if (stat.sizeBytes > 0) {
        stats.push(stat);
      }
    });
    return stats.sort((a, b) => b.sizeBytes - a.sizeBytes);
  });

  readonly viewState = computed(() => {
    const prefix = this.currentPrefix();
    const grouped = this.groupObjectsForPrefix(prefix);
    const search = this.searchTerm().trim().toLowerCase();
    const baseState = this.buildBaseViewState(grouped.folderSet, grouped.fileItems);
    const filtered = this.filterViewState(baseState.folders, baseState.files, search);
    const folders = filtered.folders;
    const files = filtered.files;
    return { folders, files };
  });

  readonly metadataEntries = computed(() => {
    const detail = this.objectDetail();
    if (!detail) {
      const empty: Array<[string, string]> = [];
      return empty;
    }
    return Object.entries(detail.metadata);
  });

  constructor() {
    this.loadSettings();
    this.applyTheme();
    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (this.themeMode() === 'auto') {
        this.applyTheme();
      }
    });
    void this.bootstrap();
  }

  loadSettings(): void {
    try {
      const stored = localStorage.getItem(SETTINGS_KEY);
      if (stored) {
        const settings: AppSettings = JSON.parse(stored);
        if (settings.theme) {
          this.themeMode.set(settings.theme);
        }
      }
    } catch {
      // Ignore parse errors
    }
  }

  saveSettings(): void {
    const settings: AppSettings = {
      theme: this.themeMode()
    };
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  }

  applyTheme(): void {
    const theme = this.effectiveTheme();
    document.documentElement.setAttribute('data-theme', theme);
  }

  setTheme(mode: ThemeMode): void {
    this.themeMode.set(mode);
    this.applyTheme();
    this.saveSettings();
  }

  toggleUserMenu(): void {
    this.userMenuOpen.update(v => !v);
  }

  closeUserMenu(): void {
    this.userMenuOpen.set(false);
  }

  openSettings(): void {
    this.userMenuOpen.set(false);
    this.settingsOpen.set(true);
  }

  closeSettings(): void {
    this.settingsOpen.set(false);
    this.clearPasswordForm();
  }

  clearPasswordForm(): void {
    this.currentPassword.set('');
    this.newPasswordInput.set('');
    this.confirmPassword.set('');
    this.passwordChangeError.set('');
  }

  async handleChangePassword(): Promise<void> {
    const current = this.currentPassword();
    const newPwd = this.newPasswordInput();
    const confirm = this.confirmPassword();

    if (!current || !newPwd || !confirm) {
      this.passwordChangeError.set('All fields are required');
      return;
    }
    if (newPwd !== confirm) {
      this.passwordChangeError.set('Passwords do not match');
      return;
    }
    if (newPwd.length < 8) {
      this.passwordChangeError.set('Password must be at least 8 characters');
      return;
    }

    this.passwordChanging.set(true);
    this.passwordChangeError.set('');
    try {
      await changePassword(current, newPwd);
      this.clearPasswordForm();
      if (this.mustChangePassword()) {
        this.mustChangePassword.set(false);
        await this.refresh();
      }
    } catch (err) {
      this.passwordChangeError.set(this.getErrorMessage(err));
    } finally {
      this.passwordChanging.set(false);
    }
  }

  async loadAuthConfig(): Promise<void> {
    try {
      const config = await getAuthConfig();
      this.authMode.set(config.mode);
      this.externalLoginPath.set(config.externalLoginPath ?? config.oidcLoginPath ?? null);
    } catch {
      this.authMode.set('internal');
      this.externalLoginPath.set(null);
    }
  }

  async bootstrap(): Promise<void> {
    this.loading.set(true);
    this.error.set('');
    await this.loadAuthConfig();
    try {
      const me = await getMe();
      this.user.set(me);
      if (me.mustChangePassword) {
        this.mustChangePassword.set(true);
        this.loading.set(false);
        return;
      }
      this.activeTab.set('buckets');
      await this.refresh();
      this.startStatsWorker();
    } catch {
      this.user.set(null);
      this.clearAdminState();
    } finally {
      this.loading.set(false);
    }
  }

  async refresh(): Promise<void> {
    const [bucketList, keyList] = await Promise.all([listBuckets(), listAccessKeys()]);
    this.buckets.set(bucketList);
    this.syncWormSelection();
    this.keys.set(keyList);
    if (this.isAdmin()) {
      await this.refreshAdmin();
    } else {
      this.clearAdminState();
    }
    // Start bucket stats calculation in background
    void this.calculateBucketStats();

    const activeBucket = bucketList.find((bucket) => bucket.name === this.selectedBucket());
    if (activeBucket) {
      await this.loadObjects(this.selectedBucket(), this.currentPrefix());
      return;
    }
    if (bucketList.length > 0) {
      this.selectedBucket.set(bucketList[0].name);
      this.currentPrefix.set('');
      await this.loadObjects(bucketList[0].name, '');
      return;
    }
    this.selectedBucket.set('');
    this.objects.set([]);
    this.selectedObject.set(null);
    this.objectDetail.set(null);
    this.objectUrl.set(null);
  }

  async calculateBucketStats(): Promise<void> {
    const bucketList = this.buckets();
    if (bucketList.length === 0) {
      this.bucketStats.set(new Map());
      return;
    }

    this.bucketStatsLoading.set(true);
    const stats = new Map<string, BucketStats>();

    try {
      // Calculate stats for each bucket in parallel (max 5 concurrent)
      const batchSize = 5;
      for (let i = 0; i < bucketList.length; i += batchSize) {
        const batch = bucketList.slice(i, i + batchSize);
        const results = await Promise.all(
          batch.map(async (bucket) => {
            try {
              const objects = await listObjects(bucket.name);
              let totalSize = 0;
              for (const obj of objects) {
                totalSize += obj.sizeBytes;
              }
              return {
                name: bucket.name,
                sizeBytes: totalSize,
                objectCount: objects.length
              };
            } catch {
              return {
                name: bucket.name,
                sizeBytes: 0,
                objectCount: 0
              };
            }
          })
        );
        for (const stat of results) {
          stats.set(stat.name, stat);
        }
        // Update stats progressively
        this.bucketStats.set(new Map(stats));
      }
    } finally {
      this.bucketStatsLoading.set(false);
    }
  }

  startStatsWorker(): void {
    // Refresh stats every 60 seconds
    if (this.statsWorkerInterval) {
      clearInterval(this.statsWorkerInterval);
    }
    this.statsWorkerInterval = setInterval(() => {
      if (this.user() && !this.mustChangePassword()) {
        void this.calculateBucketStats();
      }
    }, 60000);
  }

  stopStatsWorker(): void {
    if (this.statsWorkerInterval) {
      clearInterval(this.statsWorkerInterval);
      this.statsWorkerInterval = null;
    }
  }

  getBucketSize(bucketName: string): number {
    return this.bucketStats().get(bucketName)?.sizeBytes ?? 0;
  }

  getBucketObjectCount(bucketName: string): number {
    return this.bucketStats().get(bucketName)?.objectCount ?? 0;
  }

  async refreshAdmin(): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    try {
      const [users, nodes] = await Promise.all([listUsers(), listNodes()]);
      this.adminUsers.set(users);
      this.nodes.set(nodes);
      this.syncReplicaModesFromNodes(nodes);
      await Promise.all([this.refreshAudit(), this.refreshStorageAdmin()]);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async loadObjects(bucketName: string, prefix: string): Promise<void> {
    this.objectLoading.set(true);
    try {
      const list = await listObjects(bucketName, prefix || undefined);
      this.objects.set(list);
      this.selectedObject.set(null);
      this.objectDetail.set(null);
      this.objectUrl.set(null);
      this.editingMetadata.set(false);
      this.renamingObjectKey.set(null);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.objectLoading.set(false);
    }
  }

  async handleLogin(): Promise<void> {
    if (this.authMode() !== 'internal') {
      this.handleExternalLogin();
      return;
    }
    const username = this.loginUsername().trim();
    const password = this.loginPassword();
    if (!username || !password) {
      this.error.set('Username and password are required');
      return;
    }
    this.loading.set(true);
    this.error.set('');
    try {
      const response = await login(username, password);
      this.user.set(response.user);
      this.activeTab.set('buckets');
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
      this.user.set(null);
      this.clearAdminState();
    } finally {
      this.loading.set(false);
    }
  }

  handleExternalLogin(): void {
    const path = this.externalLoginPath() ?? '/console/v1/oidc/start';
    window.location.href = path;
  }

  handleOidcLogin(): void {
    this.handleExternalLogin();
  }

  async handleLogout(): Promise<void> {
    this.closeUserMenu();
    this.stopStatsWorker();
    await logout();
    this.user.set(null);
    this.buckets.set([]);
    this.bucketStats.set(new Map());
    this.keys.set([]);
    this.selectedBucket.set('');
    this.objects.set([]);
    this.activeTab.set('buckets');
    this.clearAdminState();
  }

  async handleCreateUser(): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    const username = this.newUsername().trim();
    const password = this.newPassword();
    const displayName = this.newDisplay().trim();
    const temporaryPassword = this.newUserTempPassword();
    if (!username || !password) {
      this.error.set('Username and password are required');
      return;
    }
    this.error.set('');
    try {
      await createUser(username, password, displayName || undefined, temporaryPassword);
      this.newUsername.set('');
      this.newPassword.set('');
      this.newDisplay.set('');
      this.newUserTempPassword.set(true);
      await this.refreshAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleToggleUser(target: User): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    const nextStatus = target.status === 'active' ? 'disabled' : 'active';
    await updateUser(target.id, { status: nextStatus });
    await this.refreshAdmin();
  }

  async handleResetPassword(target: User): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    const password = window.prompt(`Enter new password for ${target.username}`);
    if (password === null) {
      return;
    }
    if (!password) {
      this.error.set('Password is required');
      return;
    }
    this.error.set('');
    try {
      await updateUser(target.id, { password, temporaryPassword: true });
      await this.refreshAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleJoinToken(): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    this.error.set('');
    try {
      const token = await createJoinToken();
      this.joinToken.set(token);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  dismissJoinToken(): void {
    this.joinToken.set(null);
  }

  async refreshAudit(reset = true): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    this.auditLoading.set(true);
    if (reset) {
      this.auditPage.set(0);
    }
    try {
      const offset = this.auditPage() * this.auditPageSize;
      const logs = await listAuditLogs(offset, this.auditPageSize + 1);
      const hasMore = logs.length > this.auditPageSize;
      this.auditHasMore.set(hasMore);
      this.auditLogs.set(hasMore ? logs.slice(0, this.auditPageSize) : logs);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.auditLoading.set(false);
    }
  }

  async auditPrevPage(): Promise<void> {
    if (this.auditPage() > 0) {
      this.auditPage.update(p => p - 1);
      await this.refreshAudit(false);
    }
  }

  async auditNextPage(): Promise<void> {
    if (this.auditHasMore()) {
      this.auditPage.update(p => p + 1);
      await this.refreshAudit(false);
    }
  }

  async refreshStorageAdmin(): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    this.storageLoading.set(true);
    try {
      const [snapshotPolicies, backupPolicies, backupRuns] = await Promise.all([
        listSnapshotPolicies(),
        listBackupPolicies(),
        listBackupRuns(0, 50)
      ]);
      this.snapshotPolicies.set(snapshotPolicies);
      this.backupPolicies.set(backupPolicies);
      this.backupRuns.set(backupRuns);
      this.reconcileStorageEditors(snapshotPolicies, backupPolicies);
      this.syncStorageDefaults();
      await this.refreshSnapshots();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.storageLoading.set(false);
    }
  }

  async refreshSnapshots(): Promise<void> {
    const bucketName = this.storageBucketName();
    if (!bucketName) {
      this.snapshots.set([]);
      return;
    }
    try {
      const snapshots = await listSnapshots(bucketName, 0, 50);
      this.snapshots.set(snapshots);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  handleSelectStorageBucket(bucketName: string): void {
    this.storageBucketName.set(bucketName);
    if (!this.wormBucketName()) {
      this.syncWormSelection(bucketName);
    }
    void this.refreshSnapshots();
  }

  handleSelectWormBucket(bucketName: string): void {
    this.syncWormSelection(bucketName);
  }

  handleSelectVolumeBucket(bucketName: string): void {
    this.volumeBucketName.set(bucketName);
    this.selectedVolumeNodeIds.set(this.resolveBoundNodesForBucket(bucketName));
  }

  handleVolumeNodeSelection(nodeIds: string[]): void {
    this.selectedVolumeNodeIds.set([...nodeIds]);
  }

  async handleSetBucketVolumes(): Promise<void> {
    const bucketName = this.volumeBucketName().trim();
    if (!bucketName) {
      this.error.set('Volume binding bucket is required');
      return;
    }
    this.error.set('');
    try {
      await updateBucketVolumes(bucketName, this.selectedVolumeNodeIds());
      await this.refresh();
      await this.refreshStorageAdmin();
      this.handleSelectVolumeBucket(bucketName);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  setSnapshotRetention(raw: string): void {
    this.snapshotRetention.set(this.parsePositiveInteger(raw, this.snapshotRetention()));
  }

  setBackupRetention(raw: string): void {
    this.backupRetention.set(this.parsePositiveInteger(raw, this.backupRetention()));
  }

  editSnapshotPolicy(policy: BucketSnapshotPolicy): void {
    this.editingSnapshotPolicyId.set(policy.id);
    this.storageBucketName.set(this.resolveBucketName(policy.bucket_id));
    this.snapshotTrigger.set(policy.trigger_kind);
    this.snapshotRetention.set(policy.retention_count);
    this.snapshotPolicyEnabled.set(policy.enabled);
    void this.refreshSnapshots();
  }

  clearSnapshotPolicyEditor(): void {
    this.editingSnapshotPolicyId.set('');
  }

  async handleSetBucketWorm(): Promise<void> {
    const bucketName = this.wormBucketName().trim();
    if (!bucketName) {
      this.error.set('WORM bucket name is required');
      return;
    }
    this.error.set('');
    try {
      await updateBucketWorm(bucketName, this.wormEnabled());
      await this.refresh();
      await this.refreshStorageAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleSaveSnapshotPolicy(): Promise<void> {
    const bucketName = this.storageBucketName().trim();
    if (!bucketName) {
      this.error.set('Snapshot bucket is required');
      return;
    }
    if (this.snapshotRetention() < 1) {
      this.error.set('Snapshot retention must be at least 1');
      return;
    }
    this.error.set('');
    try {
      await upsertSnapshotPolicy(
        bucketName,
        this.snapshotTrigger(),
        this.snapshotRetention(),
        this.snapshotPolicyEnabled()
      );
      this.editingSnapshotPolicyId.set('');
      await this.refreshStorageAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleCreateSnapshotNow(): Promise<void> {
    const bucketName = this.storageBucketName().trim();
    if (!bucketName) {
      this.error.set('Snapshot bucket is required');
      return;
    }
    this.error.set('');
    try {
      await createSnapshot(bucketName, 'on_demand');
      await this.refreshSnapshots();
      await this.refreshStorageAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleRestoreSnapshot(snapshot: BucketSnapshot): Promise<void> {
    const sourceBucket = this.resolveBucketName(snapshot.bucket_id);
    const fallbackName = `${sourceBucket}-restore-${Date.now().toString().slice(-6)}`;
    const response = window.prompt('Restore snapshot to new bucket name', fallbackName);
    if (response === null) {
      return;
    }
    const bucketName = response.trim();
    if (!bucketName) {
      this.error.set('Restore bucket name is required');
      return;
    }
    this.error.set('');
    try {
      await restoreSnapshot(snapshot.id, bucketName);
      await this.refresh();
      await this.refreshStorageAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  openBackupWizard(policy?: BackupPolicy): void {
    if (policy) {
      this.editBackupPolicy(policy);
    } else {
      this.clearBackupPolicyEditor();
    }
    this.syncWizardTargetsFromJson();
    this.error.set('');
    this.backupWizardStep.set(0);
    this.backupWizardOpen.set(true);
  }

  closeBackupWizard(): void {
    this.backupWizardOpen.set(false);
    this.backupWizardStep.set(0);
    this.externalTargetsExampleOpen.set(false);
  }

  nextBackupWizardStep(): void {
    const error = this.validateBackupWizardStep(this.backupWizardStep());
    if (error) {
      this.error.set(error);
      return;
    }
    this.error.set('');
    const max = this.backupWizardSteps.length - 1;
    this.backupWizardStep.set(Math.min(this.backupWizardStep() + 1, max));
  }

  previousBackupWizardStep(): void {
    this.error.set('');
    this.backupWizardStep.set(Math.max(this.backupWizardStep() - 1, 0));
  }

  async saveBackupWizard(): Promise<void> {
    this.syncJsonFromWizardTargets();
    const error = this.validateBackupWizardStep(this.backupWizardSteps.length - 1);
    if (error) {
      this.error.set(error);
      return;
    }
    await this.handleSaveBackupPolicy();
    if (!this.error()) {
      this.closeBackupWizard();
    }
  }

  openExternalTargetsExample(): void {
    this.externalTargetsExampleOpen.set(true);
  }

  closeExternalTargetsExample(): void {
    this.externalTargetsExampleOpen.set(false);
  }

  applyExternalTargetsExample(): void {
    this.backupExternalTargets.set(this.backupExternalTargetsExample);
    this.syncWizardTargetsFromJson();
    this.externalTargetsExampleOpen.set(false);
  }

  addWizardTarget(): void {
    const targets = [...this.wizardTargets()];
    targets.push(this.emptyWizardTarget());
    this.wizardTargets.set(targets);
  }

  removeWizardTarget(index: number): void {
    const targets = this.wizardTargets().filter((_, i) => i !== index);
    this.wizardTargets.set(targets);
  }

  updateWizardTarget(index: number, field: WizardTargetScalarField, value: string | boolean): void {
    const targets = [...this.wizardTargets()];
    const target = { ...targets[index] };
    (target as Record<WizardTargetScalarField, string | boolean>)[field] = value;
    targets[index] = target;
    this.wizardTargets.set(targets);
  }

  addWizardTargetHeader(index: number): void {
    const targets = [...this.wizardTargets()];
    const target = { ...targets[index] };
    if (!target.headerKey.trim() || !target.headerValue.trim()) {
      return;
    }
    target.headers = [...target.headers, { key: target.headerKey.trim(), value: target.headerValue.trim() }];
    target.headerKey = '';
    target.headerValue = '';
    targets[index] = target;
    this.wizardTargets.set(targets);
  }

  removeWizardTargetHeader(targetIndex: number, headerIndex: number): void {
    const targets = [...this.wizardTargets()];
    const target = { ...targets[targetIndex] };
    target.headers = target.headers.filter((_, i) => i !== headerIndex);
    targets[targetIndex] = target;
    this.wizardTargets.set(targets);
  }

  removeHeaderFromTarget(target: WizardTarget, headerIndex: number): void {
    const targets = [...this.wizardTargets()];
    const idx = targets.indexOf(target);
    if (idx < 0) {
      return;
    }
    const updated = { ...targets[idx] };
    updated.headers = updated.headers.filter((_, i) => i !== headerIndex);
    targets[idx] = updated;
    this.wizardTargets.set(targets);
  }

  trackWizardTarget(index: number, _item: WizardTarget): number {
    return index;
  }

  trackHeader(index: number, _item: { key: string; value: string }): number {
    return index;
  }

  syncJsonFromWizardTargets(): void {
    const targets = this.wizardTargets().map(wt => this.wizardTargetToExternal(wt));
    this.backupExternalTargets.set(JSON.stringify(targets, null, 2));
  }

  testWizardTargets(): void {
    this.syncJsonFromWizardTargets();
    this.handleTestExternalTargets();
  }

  async handleSaveBackupPolicy(): Promise<void> {
    const validationError = this.validateBackupPolicyForm();
    if (validationError) {
      this.error.set(validationError);
      return;
    }
    const externalTargets = this.parseExternalTargets(this.backupExternalTargets());
    if (!externalTargets) {
      this.error.set('External targets must be valid JSON');
      return;
    }
    this.error.set('');
    try {
      await this.persistBackupPolicy(externalTargets);
      this.clearBackupPolicyEditor();
      await this.refreshStorageAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleCreateBackupPolicy(): Promise<void> {
    await this.handleSaveBackupPolicy();
  }

  handleShowExternalTargetsExample(): void {
    this.openExternalTargetsExample();
  }

  async handleTestExternalTargets(): Promise<void> {
    const externalTargets = this.parseExternalTargets(this.backupExternalTargets());
    if (!externalTargets) {
      this.error.set('External targets must be valid JSON target objects');
      return;
    }
    if (externalTargets.length === 0) {
      this.error.set('At least one external target is required for connection testing');
      return;
    }
    this.error.set('');
    try {
      for (const target of externalTargets) {
        await testBackupTargetConnection(target);
      }
      window.alert('All configured external targets are reachable');
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  editBackupPolicy(policy: BackupPolicy): void {
    this.editingBackupPolicyId.set(policy.id);
    this.backupName.set(policy.name);
    this.backupScope.set(policy.scope);
    this.backupNodeId.set(policy.node_id ?? '');
    this.backupSourceBucketName.set(this.resolveBucketName(policy.source_bucket_id));
    this.backupTargetBucketName.set(this.resolveBucketName(policy.backup_bucket_id));
    this.backupType.set(policy.backup_type);
    this.backupSchedule.set(policy.schedule_kind);
    this.backupStrategy.set(policy.strategy);
    this.backupRetention.set(policy.retention_count);
    this.backupEnabled.set(policy.enabled);
    this.backupExternalTargets.set(this.stringifyExternalTargets(policy.external_targets_json));
  }

  clearBackupPolicyEditor(): void {
    this.editingBackupPolicyId.set('');
    this.backupName.set('');
    this.backupScope.set('master');
    this.backupNodeId.set('');
    this.backupType.set('full');
    this.backupSchedule.set('daily');
    this.backupStrategy.set('3-2-1');
    this.backupRetention.set(7);
    this.backupEnabled.set(true);
    this.backupExternalTargets.set('[]');
    this.wizardTargets.set([]);
    this.syncStorageDefaults();
  }

  async handleRunBackupPolicy(policy: BackupPolicy): Promise<void> {
    this.error.set('');
    try {
      await runBackupPolicy(policy.id);
      await this.refreshStorageAdmin();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleExportBackupRun(run: BackupRun, format: 'tar' | 'tar.gz'): Promise<void> {
    this.error.set('');
    try {
      const blob = await exportBackupRun(run.id, format);
      const filename = `backup-${run.id}.${format}`;
      this.downloadBlob(blob, filename);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleSetReplicaMode(node: NodeInfo, mode: ReplicaSubMode): Promise<void> {
    this.error.set('');
    try {
      const updated = await updateReplicaMode(node.nodeId, mode);
      this.replicaModes.update((map) => {
        const copy = new Map(map);
        copy.set(updated.nodeId, updated.subMode);
        return copy;
      });
      this.nodes.set(
        this.nodes().map((entry) =>
          entry.nodeId === updated.nodeId ? { ...entry, subMode: updated.subMode } : entry
        )
      );
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  getReplicaMode(nodeId: string): ReplicaSubMode {
    return this.replicaModes().get(nodeId) ?? 'delivery';
  }

  resolveBucketName(bucketId: string): string {
    return this.bucketNameById().get(bucketId) ?? bucketId;
  }

  async handleCreateKey(): Promise<void> {
    this.error.set('');
    try {
      const created = await createAccessKey(this.label() || DEFAULT_LABEL);
      this.secret.set(created);
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleDisable(key: AccessKey): Promise<void> {
    await updateAccessKey(key.accessKeyId, 'disabled');
    await this.refresh();
  }

  async handleDelete(key: AccessKey): Promise<void> {
    await deleteAccessKey(key.accessKeyId);
    await this.refresh();
  }

  async handleCreateBucket(): Promise<void> {
    const name = this.newBucketName().trim();
    if (!name) {
      this.error.set('Bucket name is required');
      return;
    }
    this.bucketBusy.set(true);
    this.error.set('');
    try {
      const presign = await presignUrl('PUT', name);
      const response = await fetch(presign.url, { method: 'PUT', headers: presign.headers ?? undefined });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Create bucket failed: ${response.status}`);
      }
      this.newBucketName.set('');
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.bucketBusy.set(false);
    }
  }

  startRenameBucket(bucketName: string): void {
    this.renamingBucket.set(bucketName);
    this.renameBucketValue.set(bucketName);
  }

  async handleRenameBucket(bucket: Bucket): Promise<void> {
    const name = this.renameBucketValue().trim();
    if (!name) {
      this.error.set('Bucket name is required');
      return;
    }
    this.bucketBusy.set(true);
    this.error.set('');
    try {
      await renameBucket(bucket.name, name);
      if (this.selectedBucket() === bucket.name) {
        this.selectedBucket.set(name);
      }
      this.renamingBucket.set(null);
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.bucketBusy.set(false);
    }
  }

  async handleTogglePublic(bucket: Bucket): Promise<void> {
    const nextValue = !bucket.publicRead;
    this.buckets.set(
      this.buckets().map((entry) => (entry.id === bucket.id ? { ...entry, publicRead: nextValue } : entry))
    );
    this.bucketBusy.set(true);
    this.error.set('');
    try {
      await updateBucketPublic(bucket.name, nextValue);
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
      this.buckets.set(
        this.buckets().map((entry) => (entry.id === bucket.id ? { ...entry, publicRead: bucket.publicRead } : entry))
      );
    } finally {
      this.bucketBusy.set(false);
    }
  }

  async handleBucketVersioningChange(
    bucket: Bucket,
    versioningStatus: BucketVersioningStatus
  ): Promise<void> {
    if (bucket.versioningStatus === versioningStatus) {
      return;
    }
    this.buckets.set(
      this.buckets().map((entry) =>
        entry.id === bucket.id ? { ...entry, versioningStatus } : entry
      )
    );
    this.bucketBusy.set(true);
    this.error.set('');
    try {
      await updateBucketVersioning(bucket.name, versioningStatus);
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
      this.buckets.set(
        this.buckets().map((entry) =>
          entry.id === bucket.id ? { ...entry, versioningStatus: bucket.versioningStatus } : entry
        )
      );
    } finally {
      this.bucketBusy.set(false);
    }
  }

  async handleDeleteBucket(bucketName: string): Promise<void> {
    const ok = window.confirm(`Delete bucket ${bucketName}?`);
    if (!ok) {
      return;
    }
    this.bucketBusy.set(true);
    this.error.set('');
    try {
      const presign = await presignUrl('DELETE', bucketName);
      const response = await fetch(presign.url, { method: 'DELETE', headers: presign.headers ?? undefined });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Delete bucket failed: ${response.status}`);
      }
      if (this.selectedBucket() === bucketName) {
        this.selectedBucket.set('');
        this.objects.set([]);
        this.selectedObject.set(null);
        this.objectDetail.set(null);
        this.objectUrl.set(null);
      }
      await this.refresh();
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.bucketBusy.set(false);
    }
  }

  async handleSelectBucket(bucketName: string): Promise<void> {
    this.selectedBucket.set(bucketName);
    this.currentPrefix.set('');
    if (bucketName) {
      await this.loadObjects(bucketName, '');
    } else {
      this.objects.set([]);
      this.selectedObject.set(null);
      this.objectDetail.set(null);
      this.objectUrl.set(null);
    }
  }

  async handleRefreshObjects(): Promise<void> {
    if (!this.selectedBucket()) {
      return;
    }
    await this.loadObjects(this.selectedBucket(), this.currentPrefix());
  }

  async handleUpload(fileInput: HTMLInputElement): Promise<void> {
    if (!this.selectedBucket()) {
      return;
    }
    const file = fileInput.files?.item(0);
    if (!file) {
      return;
    }
    this.uploading.set(true);
    this.error.set('');
    try {
      const desiredKey = this.uploadKey().trim();
      const baseKey = desiredKey || file.name;
      const finalKey = baseKey.includes('/') ? baseKey : `${this.currentPrefix()}${baseKey}`;
      const presign = await presignUrl('PUT', this.selectedBucket(), finalKey);
      const response = await fetch(presign.url, {
        method: 'PUT',
        headers: presign.headers ?? undefined,
        body: file
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Upload failed: ${response.status}`);
      }
      this.uploadKey.set('');
      await this.loadObjects(this.selectedBucket(), this.currentPrefix());
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.uploading.set(false);
      fileInput.value = '';
    }
  }

  async handleDownload(key: string): Promise<void> {
    if (!this.selectedBucket()) {
      return;
    }
    this.error.set('');
    try {
      const presign = await presignUrl('GET', this.selectedBucket(), key);
      window.open(presign.url, '_blank', 'noopener');
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleDeleteObject(key: string): Promise<void> {
    if (!this.selectedBucket()) {
      return;
    }
    const ok = window.confirm(`Delete object ${key}?`);
    if (!ok) {
      return;
    }
    this.error.set('');
    try {
      const presign = await presignUrl('DELETE', this.selectedBucket(), key);
      const response = await fetch(presign.url, { method: 'DELETE', headers: presign.headers ?? undefined });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Delete failed: ${response.status}`);
      }
      await this.loadObjects(this.selectedBucket(), this.currentPrefix());
      if (this.selectedObject()?.key === key) {
        this.selectedObject.set(null);
        this.objectDetail.set(null);
        this.objectUrl.set(null);
      }
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async openObjectDetails(object: ObjectItem): Promise<void> {
    if (!this.selectedBucket()) {
      return;
    }
    this.error.set('');
    this.selectedObject.set(object);
    this.editingMetadata.set(false);
    this.objectUrl.set(null);
    try {
      const detail = await getObjectDetail(this.selectedBucket(), object.key);
      this.objectDetail.set(detail);
      this.metadataDraft.set(this.buildMetadataDraft(detail.metadata));
      this.renameObjectValue.set(this.getBaseName(object.key));
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
      this.objectDetail.set(null);
      this.objectUrl.set(null);
    }
  }

  async startRenameObject(key: string): Promise<void> {
    if (!this.selectedBucket()) {
      return;
    }
    const object = this.objects().find((item) => item.key === key);
    if (!object) {
      return;
    }
    this.error.set('');
    this.renamingObjectKey.set(key);
    await this.openObjectDetails(object);
    this.renameObjectValue.set(this.getBaseName(key));
  }

  cancelRenameObject(): void {
    this.renamingObjectKey.set(null);
    this.renameObjectValue.set('');
  }

  async handleRenameObject(keyOverride?: string): Promise<void> {
    const selected = this.selectedObject();
    const bucket = this.selectedBucket();
    const targetKey = keyOverride ?? this.renamingObjectKey() ?? selected?.key ?? '';
    if (!bucket || !targetKey) {
      return;
    }
    const newName = this.renameObjectValue().trim();
    if (!newName) {
      this.error.set('New object name is required');
      return;
    }
    this.error.set('');
    try {
      const prefix = this.getDirName(targetKey);
      const newKey = `${prefix}${newName}`;
      await renameObject(bucket, targetKey, newKey);
      await this.loadObjects(bucket, this.currentPrefix());
      if (selected && selected.key === targetKey) {
        const detail = await getObjectDetail(bucket, newKey);
        this.selectedObject.set({ ...selected, key: newKey });
        this.objectDetail.set(detail);
        this.metadataDraft.set(this.buildMetadataDraft(detail.metadata));
      } else {
        this.objectDetail.set(null);
      }
      this.renamingObjectKey.set(null);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  async handleSaveMetadata(): Promise<void> {
    if (!this.selectedBucket() || !this.selectedObject()) {
      return;
    }
    const parsed = this.parseMetadataDraft(this.metadataDraft());
    if (!parsed) {
      this.error.set('Metadata must be valid JSON with string values');
      return;
    }
    this.error.set('');
    try {
      await updateObjectMetadata(this.selectedBucket(), this.selectedObject()?.key ?? '', parsed);
      const detail = await getObjectDetail(this.selectedBucket(), this.selectedObject()?.key ?? '');
      this.objectDetail.set(detail);
      this.metadataDraft.set(this.buildMetadataDraft(detail.metadata));
      this.editingMetadata.set(false);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    }
  }

  enterFolder(folderName: string): void {
    const nextPrefix = `${this.currentPrefix()}${folderName}/`;
    this.currentPrefix.set(nextPrefix);
    if (this.selectedBucket()) {
      void this.loadObjects(this.selectedBucket(), nextPrefix);
    }
  }

  goRoot(): void {
    this.currentPrefix.set('');
    if (this.selectedBucket()) {
      void this.loadObjects(this.selectedBucket(), '');
    }
  }

  goToPrefix(prefix: string): void {
    this.currentPrefix.set(prefix);
    if (this.selectedBucket()) {
      void this.loadObjects(this.selectedBucket(), prefix);
    }
  }

  goUp(): void {
    const prefix = this.currentPrefix();
    if (!prefix) {
      return;
    }
    const trimmed = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    const idx = trimmed.lastIndexOf('/');
    const parent = idx >= 0 ? `${trimmed.slice(0, idx + 1)}` : '';
    this.currentPrefix.set(parent);
    if (this.selectedBucket()) {
      void this.loadObjects(this.selectedBucket(), parent);
    }
  }

  closeObjectDetails(): void {
    this.selectedObject.set(null);
    this.objectDetail.set(null);
    this.objectUrl.set(null);
    this.editingMetadata.set(false);
    this.renamingObjectKey.set(null);
  }

  async handleGenerateObjectUrl(): Promise<void> {
    const bucket = this.selectedBucket();
    const object = this.selectedObject();
    if (!bucket || !object) {
      return;
    }
    this.objectUrlLoading.set(true);
    this.error.set('');
    try {
      const url = await getObjectDownloadUrl(bucket, object.key);
      this.objectUrl.set(url);
    } catch (err) {
      this.error.set(this.getErrorMessage(err));
    } finally {
      this.objectUrlLoading.set(false);
    }
  }

  async handleCopyObjectUrl(): Promise<void> {
    const url = this.objectUrl()?.url;
    if (!url) {
      return;
    }
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      this.error.set('Failed to copy URL');
    }
  }

  handleOpenObjectUrl(): void {
    const url = this.objectUrl()?.url;
    if (!url) {
      return;
    }
    window.open(url, '_blank', 'noopener');
  }

  clearSecret(): void {
    this.secret.set(null);
    this.cdr.detectChanges();
  }

  maskAccessKey(value: string): string {
    if (value.length <= 8) {
      return value;
    }
    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }

  setTab(tab: TabKey): void {
    this.activeTab.set(tab);
  }

  setTabIndex(index: number): void {
    const tab = this.availableTabs()[index] ?? 'buckets';
    this.activeTab.set(tab);
    if (tab === 'admin') {
      void this.refreshAdmin();
    }
  }

  formatBytes(size: number): string {
    if (size < 1024) {
      return `${size} B`;
    }
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = size / 1024;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex += 1;
    }
    const precision = value >= 10 ? 0 : 1;
    return `${value.toFixed(precision)} ${units[unitIndex]}`;
  }

  readonly chartColors = [
    '#3b82f6', '#ef4444', '#22c55e', '#f59e0b', '#8b5cf6',
    '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1'
  ];

  getChartColor(index: number): string {
    return this.chartColors[index % this.chartColors.length];
  }

  getPieChartPath(index: number, total: number, stats: BucketStats[]): string {
    if (total === 0) return '';

    let startAngle = 0;
    for (let i = 0; i < index; i++) {
      startAngle += (stats[i].sizeBytes / total) * 360;
    }

    const sliceAngle = (stats[index].sizeBytes / total) * 360;
    const endAngle = startAngle + sliceAngle;

    const startRad = (startAngle - 90) * Math.PI / 180;
    const endRad = (endAngle - 90) * Math.PI / 180;

    const x1 = 50 + 45 * Math.cos(startRad);
    const y1 = 50 + 45 * Math.sin(startRad);
    const x2 = 50 + 45 * Math.cos(endRad);
    const y2 = 50 + 45 * Math.sin(endRad);

    const largeArc = sliceAngle > 180 ? 1 : 0;

    return `M 50 50 L ${x1} ${y1} A 45 45 0 ${largeArc} 1 ${x2} ${y2} Z`;
  }

  getBaseName(key: string): string {
    const segments = key.split('/').filter((segment) => segment.length > 0);
    if (segments.length === 0) {
      return key;
    }
    return segments[segments.length - 1];
  }

  private groupObjectsForPrefix(prefix: string): { folderSet: Set<string>; fileItems: ObjectItem[] } {
    const folderSet = new Set<string>();
    const fileItems: ObjectItem[] = [];
    for (const item of this.objects()) {
      if (!item.key.startsWith(prefix)) {
        continue;
      }
      const remainder = item.key.slice(prefix.length);
      if (!remainder) {
        continue;
      }
      const slashIndex = remainder.indexOf('/');
      if (slashIndex >= 0) {
        const folder = remainder.slice(0, slashIndex);
        if (folder) {
          folderSet.add(folder);
        }
        continue;
      }
      fileItems.push(item);
    }
    return { folderSet, fileItems };
  }

  private buildBaseViewState(folderSet: Set<string>, fileItems: ObjectItem[]): {
    folders: string[];
    files: ObjectItem[];
  } {
    const folders = Array.from(folderSet).sort();
    const files = [...fileItems].sort((a, b) => a.key.localeCompare(b.key));
    return { folders, files };
  }

  private filterViewState(
    folders: string[],
    files: ObjectItem[],
    search: string
  ): { folders: string[]; files: ObjectItem[] } {
    if (!search) {
      return { folders, files };
    }
    const selectedKey = this.selectedObject()?.key ?? '';
    const filteredFolders = folders.filter((name) => name.toLowerCase().includes(search));
    const filteredFiles = files.filter((item) => {
      if (this.getBaseName(item.key).toLowerCase().includes(search)) {
        return true;
      }
      return selectedKey.length > 0 && item.key === selectedKey;
    });
    return { folders: filteredFolders, files: filteredFiles };
  }

  private getDirName(key: string): string {
    const idx = key.lastIndexOf('/');
    if (idx < 0) {
      return '';
    }
    return key.slice(0, idx + 1);
  }

  private buildMetadataDraft(metadata: Record<string, string>): string {
    return JSON.stringify(metadata, null, 2);
  }

  private parseMetadataDraft(raw: string): Record<string, string> | null {
    const trimmed = raw.trim();
    if (!trimmed) {
      return {};
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return null;
    }
    if (!this.isRecord(parsed)) {
      return null;
    }
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value !== 'string') {
        return null;
      }
      result[key] = value;
    }
    return result;
  }

  private syncStorageDefaults(): void {
    const firstBucket = this.buckets().at(0)?.name ?? '';
    if (!this.storageBucketName() && firstBucket) {
      this.storageBucketName.set(firstBucket);
    }
    if (!this.wormBucketName() && firstBucket) {
      this.syncWormSelection(firstBucket);
    }
    if (!this.backupSourceBucketName() && firstBucket) {
      this.backupSourceBucketName.set(firstBucket);
    }
    if (!this.backupTargetBucketName() && firstBucket) {
      this.backupTargetBucketName.set(firstBucket);
    }
    if (!this.volumeBucketName() && firstBucket) {
      this.handleSelectVolumeBucket(firstBucket);
    }
    if (!this.backupExternalTargets().trim()) {
      this.backupExternalTargets.set('[]');
    }
    this.syncWormSelection();
    if (this.volumeBucketName()) {
      this.selectedVolumeNodeIds.set(this.resolveBoundNodesForBucket(this.volumeBucketName()));
    }
  }

  private syncWormSelection(bucketName?: string): void {
    const chosen = (bucketName ?? this.wormBucketName()).trim();
    if (!chosen) {
      this.wormEnabled.set(false);
      return;
    }
    this.wormBucketName.set(chosen);
    const bucket = this.buckets().find((entry) => entry.name === chosen);
    this.wormEnabled.set(bucket?.isWorm ?? false);
  }

  private reconcileStorageEditors(
    snapshotPolicies: BucketSnapshotPolicy[],
    backupPolicies: BackupPolicy[]
  ): void {
    const editingSnapshotId = this.editingSnapshotPolicyId();
    if (editingSnapshotId && !snapshotPolicies.some((entry) => entry.id === editingSnapshotId)) {
      this.editingSnapshotPolicyId.set('');
    }
    const editingBackupId = this.editingBackupPolicyId();
    if (editingBackupId && !backupPolicies.some((entry) => entry.id === editingBackupId)) {
      this.clearBackupPolicyEditor();
    }
  }

  private resolveBoundNodesForBucket(bucketName: string): string[] {
    const bucket = this.buckets().find((entry) => entry.name === bucketName);
    return bucket?.boundNodeIds ? [...bucket.boundNodeIds] : [];
  }

  private syncReplicaModesFromNodes(nodes: NodeInfo[]): void {
    const map = new Map<string, ReplicaSubMode>();
    for (const node of nodes) {
      if (node.role !== 'replica') {
        continue;
      }
      const mode = node.subMode ?? 'delivery';
      map.set(node.nodeId, mode);
    }
    this.replicaModes.set(map);
  }

  private isVolumeEligibleNode(node: NodeInfo): boolean {
    if (node.role === 'master') {
      return true;
    }
    if (node.role !== 'replica') {
      return false;
    }
    return this.getReplicaMode(node.nodeId) === 'volume';
  }

  private async persistBackupPolicy(externalTargets: ExternalBackupTarget[]): Promise<void> {
    const editingId = this.editingBackupPolicyId();
    if (!editingId) {
      await createBackupPolicy(this.buildCreateBackupPolicyPayload(externalTargets));
      return;
    }
    await updateBackupPolicy(editingId, this.buildUpdateBackupPolicyPayload(externalTargets));
  }

  private buildCreateBackupPolicyPayload(externalTargets: ExternalBackupTarget[]) {
    return {
      name: this.backupName().trim(),
      scope: this.backupScope(),
      nodeId: this.backupScope() === 'replica' ? this.backupNodeId() : undefined,
      sourceBucketName: this.backupSourceBucketName(),
      backupBucketName: this.backupTargetBucketName(),
      backupType: this.backupType(),
      scheduleKind: this.backupSchedule(),
      strategy: this.backupStrategy(),
      retentionCount: this.backupRetention(),
      enabled: this.backupEnabled(),
      externalTargets
    };
  }

  private buildUpdateBackupPolicyPayload(externalTargets: ExternalBackupTarget[]) {
    return {
      name: this.backupName().trim(),
      backupType: this.backupType(),
      scheduleKind: this.backupSchedule(),
      strategy: this.backupStrategy(),
      retentionCount: this.backupRetention(),
      enabled: this.backupEnabled(),
      externalTargets
    };
  }

  private validateBackupPolicyForm(): string | null {
    if (!this.backupName().trim()) {
      return 'Backup policy name is required';
    }
    if (!this.backupSourceBucketName().trim()) {
      return 'Source bucket is required';
    }
    if (!this.backupTargetBucketName().trim()) {
      return 'Backup bucket is required';
    }
    if (this.backupRetention() < 1) {
      return 'Backup retention must be at least 1';
    }
    if (this.backupScope() === 'replica') {
      const nodeId = this.backupNodeId().trim();
      if (!nodeId) {
        return 'Slave scope requires a slave node';
      }
      const mode = this.replicaModes().get(nodeId);
      if (mode && mode !== 'backup') {
        return 'Slave scope requires node in slave-backup mode';
      }
    }
    return null;
  }

  private validateBackupWizardStep(step: number): string | null {
    if (step === 0 && this.backupScope() === 'replica' && !this.backupNodeId().trim()) {
      return 'Select a slave node for slave scope';
    }
    if (step === 1) {
      if (!this.backupSourceBucketName().trim()) {
        return 'Source bucket is required';
      }
      if (!this.backupTargetBucketName().trim()) {
        return 'Backup bucket is required';
      }
    }
    if (step === 2) {
      if (!this.backupName().trim()) {
        return 'Backup policy name is required';
      }
      if (this.backupRetention() < 1) {
        return 'Backup retention must be at least 1';
      }
    }
    if (step === this.backupWizardSteps.length - 1) {
      this.syncJsonFromWizardTargets();
      return this.validateBackupPolicyForm();
    }
    return null;
  }

  private syncWizardTargetsFromJson(): void {
    const parsed = this.parseExternalTargets(this.backupExternalTargets());
    if (!parsed) {
      this.wizardTargets.set([]);
      return;
    }
    this.wizardTargets.set(parsed.map(t => this.externalToWizardTarget(t)));
  }

  private externalToWizardTarget(t: ExternalBackupTarget): WizardTarget {
    const headers: Array<{ key: string; value: string }> = [];
    if (t.headers) {
      for (const [key, value] of Object.entries(t.headers)) {
        headers.push({ key, value });
      }
    }
    return {
      name: t.name,
      kind: t.kind,
      endpoint: t.endpoint,
      method: t.method ?? '',
      enabled: t.enabled ?? true,
      headerKey: '',
      headerValue: '',
      headers,
      timeoutSeconds: t.timeoutSeconds !== undefined ? String(t.timeoutSeconds) : ''
    };
  }

  private wizardTargetToExternal(wt: WizardTarget): ExternalBackupTarget {
    const target: ExternalBackupTarget = {
      name: wt.name.trim(),
      kind: wt.kind,
      endpoint: wt.endpoint.trim(),
      enabled: wt.enabled
    };
    if (wt.method === 'PUT' || wt.method === 'POST') {
      target.method = wt.method;
    }
    if (wt.headers.length > 0) {
      const headers: Record<string, string> = {};
      for (const h of wt.headers) {
        headers[h.key] = h.value;
      }
      target.headers = headers;
    }
    const timeout = Number.parseInt(wt.timeoutSeconds, 10);
    if (!Number.isNaN(timeout) && timeout > 0) {
      target.timeoutSeconds = timeout;
    }
    return target;
  }

  private emptyWizardTarget(): WizardTarget {
    return {
      name: '',
      kind: 's3',
      endpoint: '',
      method: 'PUT',
      enabled: true,
      headerKey: '',
      headerValue: '',
      headers: [],
      timeoutSeconds: '20'
    };
  }

  private stringifyExternalTargets(raw: unknown): string {
    try {
      return JSON.stringify(raw, null, 2);
    } catch {
      return '[]';
    }
  }

  private parseExternalTargets(raw: string): ExternalBackupTarget[] | null {
    const trimmed = raw.trim();
    if (!trimmed) {
      return [];
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return null;
    }
    if (!Array.isArray(parsed)) {
      return null;
    }
    const targets: ExternalBackupTarget[] = [];
    for (const entry of parsed) {
      const target = this.parseExternalTarget(entry);
      if (!target) {
        return null;
      }
      targets.push(target);
    }
    return targets;
  }

  private parseExternalTarget(value: unknown): ExternalBackupTarget | null {
    if (!this.isRecord(value)) {
      return null;
    }
    const name = this.parseRequiredString(value['name']);
    const endpoint = this.parseRequiredString(value['endpoint']);
    const kind = this.parseExternalTargetKind(value['kind']);
    const method = this.parseExternalTargetMethod(value['method']);
    const enabled = this.parseOptionalBoolean(value['enabled']);
    const headers = this.parseOptionalStringRecord(value['headers']);
    const timeoutSeconds = this.parseOptionalPositiveInteger(value['timeoutSeconds']);
    if (!name || !endpoint || !kind || method === null || enabled === null) {
      return null;
    }
    if (headers === undefined || timeoutSeconds === null) {
      return null;
    }
    return this.buildExternalTarget(name, kind, endpoint, method, enabled, headers, timeoutSeconds);
  }

  private buildExternalTarget(
    name: string,
    kind: ExternalBackupTarget['kind'],
    endpoint: string,
    method: 'PUT' | 'POST' | undefined,
    enabled: boolean | undefined,
    headers: Record<string, string> | null,
    timeoutSeconds: number | undefined
  ): ExternalBackupTarget {
    const target: ExternalBackupTarget = { name, kind, endpoint };
    if (method) {
      target.method = method;
    }
    if (enabled !== undefined) {
      target.enabled = enabled;
    }
    if (headers) {
      target.headers = headers;
    }
    if (timeoutSeconds !== undefined) {
      target.timeoutSeconds = timeoutSeconds;
    }
    return target;
  }

  private parseRequiredString(value: unknown): string | null {
    if (typeof value !== 'string') {
      return null;
    }
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }

  private parseExternalTargetKind(value: unknown): ExternalBackupTarget['kind'] | null {
    const isKnownKind =
      value === 's3' || value === 'glacier' || value === 'sftp' || value === 'ssh' || value === 'other';
    if (isKnownKind) {
      return value;
    }
    return null;
  }

  private parseExternalTargetMethod(value: unknown): 'PUT' | 'POST' | undefined | null {
    if (value === undefined || value === null || value === '') {
      return undefined;
    }
    if (typeof value !== 'string') {
      return null;
    }
    const method = value.trim().toUpperCase();
    if (method === 'PUT') {
      return 'PUT';
    }
    if (method === 'POST') {
      return 'POST';
    }
    return null;
  }

  private parseOptionalBoolean(value: unknown): boolean | undefined | null {
    if (value === undefined) {
      return undefined;
    }
    if (typeof value === 'boolean') {
      return value;
    }
    return null;
  }

  private parseOptionalStringRecord(
    value: unknown
  ): Record<string, string> | null | undefined {
    if (value === undefined) {
      return null;
    }
    if (value === null) {
      return null;
    }
    if (!this.isRecord(value)) {
      return undefined;
    }
    const out: Record<string, string> = {};
    for (const [key, entry] of Object.entries(value)) {
      if (typeof entry !== 'string') {
        return undefined;
      }
      out[key] = entry;
    }
    return out;
  }

  private parseOptionalPositiveInteger(value: unknown): number | undefined | null {
    if (value === undefined || value === null || value === '') {
      return undefined;
    }
    if (typeof value !== 'number' || Number.isNaN(value) || value < 1) {
      return null;
    }
    return Math.trunc(value);
  }

  private parsePositiveInteger(raw: string, fallback: number): number {
    const parsed = Number.parseInt(raw, 10);
    if (Number.isNaN(parsed) || parsed < 1) {
      return fallback;
    }
    return parsed;
  }

  private downloadBlob(blob: Blob, filename: string): void {
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    window.URL.revokeObjectURL(url);
  }

  private clearAdminState(): void {
    this.adminUsers.set([]);
    this.nodes.set([]);
    this.joinToken.set(null);
    this.auditLogs.set([]);
    this.auditLoading.set(false);
    this.snapshotPolicies.set([]);
    this.snapshots.set([]);
    this.backupPolicies.set([]);
    this.backupRuns.set([]);
    this.replicaModes.set(new Map());
    this.volumeBucketName.set('');
    this.selectedVolumeNodeIds.set([]);
    this.backupWizardOpen.set(false);
    this.backupWizardStep.set(0);
    this.externalTargetsExampleOpen.set(false);
    this.wizardTargets.set([]);
    this.editingSnapshotPolicyId.set('');
    this.editingBackupPolicyId.set('');
    this.newUsername.set('');
    this.newDisplay.set('');
    this.newPassword.set('');
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private getErrorMessage(err: unknown): string {
    if (err instanceof Error) {
      return err.message;
    }
    return 'Request failed';
  }

  displayNameSummary(item: User): string {
    if (item.displayName && !item.displayName.includes(item.username)) {
      return item.displayName;
    }
    if (item.displayName) {
      return 'Display name set';
    }
    return '—';
  }

  trackUser(index: number, item: User): string {
    return item.id;
  }

  trackNode(index: number, item: NodeInfo): string {
    return item.nodeId;
  }

  trackAudit(index: number, item: AuditLog): string {
    return item.id;
  }

  trackBucket(index: number, item: Bucket): string {
    return item.id;
  }

  trackAccessKey(index: number, item: AccessKey): string {
    return item.accessKeyId;
  }

  trackObject(index: number, item: ObjectItem): string {
    return item.key;
  }

  trackFolder(index: number, item: string): string {
    return item;
  }

  trackCrumb(index: number, item: { label: string; prefix: string }): string {
    return item.prefix;
  }

  trackMetadata(index: number, item: [string, string]): string {
    return item[0];
  }

  trackSnapshotPolicy(index: number, item: BucketSnapshotPolicy): string {
    return item.id;
  }

  trackSnapshot(index: number, item: BucketSnapshot): string {
    return item.id;
  }

  trackBackupPolicy(index: number, item: BackupPolicy): string {
    return item.id;
  }

  trackBackupRun(index: number, item: BackupRun): string {
    return item.id;
  }

  trackReplicaMode(index: number, item: NodeInfo): string {
    return item.nodeId;
  }
}
