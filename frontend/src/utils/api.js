// ── API CLIENT ─────────────────────────────────────────
// Handles auth headers, token refresh, and error normalisation

const BASE = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) || 'http://localhost:4000/api';

let accessToken  = localStorage.getItem('access_token')  || null;
let refreshToken = localStorage.getItem('refresh_token') || null;

export const setTokens = (at, rt) => {
  accessToken  = at;
  refreshToken = rt;
  localStorage.setItem('access_token',  at || '');
  localStorage.setItem('refresh_token', rt || '');
};

export const clearTokens = () => {
  accessToken = refreshToken = null;
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
};

export const getAccessToken  = () => accessToken;
export const getRefreshToken = () => refreshToken;

// ── FETCH WRAPPER ─────────────────────────────────────
let isRefreshing = false;
let failQueue    = [];

const processQueue = (error) => {
  failQueue.forEach(({ resolve, reject }) => error ? reject(error) : resolve());
  failQueue = [];
};

export async function apiFetch(method, path, body, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (accessToken && !opts.skipAuth) headers['Authorization'] = `Bearer ${accessToken}`;
  if (opts.token)                     headers['Authorization'] = `Bearer ${opts.token}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  // Auto-refresh on 401 TOKEN_EXPIRED
  if (res.status === 401 && !opts.skipRefresh) {
    const data = await res.clone().json().catch(() => ({}));
    if (data.code === 'TOKEN_EXPIRED' && refreshToken) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failQueue.push({ resolve, reject });
        }).then(() => apiFetch(method, path, body, { ...opts, skipRefresh: true }));
      }
      isRefreshing = true;
      try {
        const refreshed = await api.post('/auth/refresh', { refreshToken }, { skipAuth: true, skipRefresh: true });
        setTokens(refreshed.accessToken, refreshed.refreshToken);
        processQueue(null);
        return apiFetch(method, path, body, { ...opts, skipRefresh: true });
      } catch (err) {
        processQueue(err);
        clearTokens();
        window.dispatchEvent(new Event('auth:logout'));
        throw new Error('Session expired. Please log in again.');
      } finally {
        isRefreshing = false;
      }
    }
  }

  const json = await res.json().catch(() => ({ error: 'Invalid server response.' }));
  if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
  return json;
}

export const api = {
  get:    (path, opts)       => apiFetch('GET',    path, null, opts),
  post:   (path, body, opts) => apiFetch('POST',   path, body, opts),
  put:    (path, body, opts) => apiFetch('PUT',    path, body, opts),
  delete: (path, opts)       => apiFetch('DELETE', path, null, opts),
};
