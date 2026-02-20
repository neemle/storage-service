export interface RuntimeSettings {
  apiBaseUrl: string;
}

declare global {
  interface Window {
    __NSS_SETTINGS__?: RuntimeSettings;
    __API_BASE__?: string;
    __CONSOLE_API_BASE__?: string;
    __ADMIN_API_BASE__?: string;
  }
}

function normalizeBaseUrl(value: unknown): string {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim().replace(/\/+$/, '');
}

function readLegacyApiBase(): string {
  if (typeof window === 'undefined') {
    return '';
  }
  return normalizeBaseUrl(
    window.__NSS_SETTINGS__?.apiBaseUrl ??
      window.__API_BASE__ ??
      window.__CONSOLE_API_BASE__ ??
      window.__ADMIN_API_BASE__ ??
      ''
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseRuntimeSettings(payload: unknown): RuntimeSettings | null {
  if (!isRecord(payload)) {
    return null;
  }
  const direct = normalizeBaseUrl(payload['apiBaseUrl']);
  if (direct) {
    return { apiBaseUrl: direct };
  }
  const nested = payload['api'];
  if (isRecord(nested)) {
    const fromNested = normalizeBaseUrl(nested['baseUrl']);
    if (fromNested) {
      return { apiBaseUrl: fromNested };
    }
  }
  return null;
}

function applyRuntimeSettings(settings: RuntimeSettings): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.__NSS_SETTINGS__ = settings;
  window.__API_BASE__ = settings.apiBaseUrl;
}

export async function loadRuntimeSettings(): Promise<void> {
  if (typeof window === 'undefined') {
    return;
  }

  const fallback: RuntimeSettings = { apiBaseUrl: readLegacyApiBase() };
  try {
    const response = await fetch('/settings.json', { cache: 'no-store' });
    if (!response.ok) {
      applyRuntimeSettings(fallback);
      return;
    }
    const payload: unknown = await response.json();
    const parsed = parseRuntimeSettings(payload) ?? fallback;
    applyRuntimeSettings(parsed);
  } catch {
    applyRuntimeSettings(fallback);
  }
}

export function getApiBaseUrl(): string {
  return readLegacyApiBase();
}
