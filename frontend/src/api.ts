import { Alert, Rule, SourceStatus, SystemStats } from './types';

const API_BASE = '/api';

let token: string | null = localStorage.getItem('token');

export function setToken(newToken: string) {
  token = newToken;
  localStorage.setItem('token', newToken);
}

export function clearToken() {
  token = null;
  localStorage.removeItem('token');
}

export function getToken() {
  return token;
}

async function fetchAPI(endpoint: string, options: RequestInit = {}) {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearToken();
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    throw new Error(`API Error: ${response.statusText}`);
  }

  return response.json();
}

export const api = {
  // Auth
  login: async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password }),
    });
    if (!response.ok) throw new Error('Login failed');
    const data = await response.json();
    setToken(data.access_token);
    return data;
  },

  // Sources
  getSources: (): Promise<SourceStatus[]> => fetchAPI('/sources'),

  // Alerts
  getAlerts: (limit = 100): Promise<Alert[]> => fetchAPI(`/alerts?limit=${limit}`),
  acknowledgeAlert: (alertId: string) => fetchAPI(`/alerts/${alertId}/acknowledge`, { method: 'POST' }),

  // Rules
  getRules: (): Promise<Rule[]> => fetchAPI('/rules'),
  createRule: (rule: any): Promise<Rule> => fetchAPI('/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  }),
  updateRule: (ruleId: string, rule: any): Promise<Rule> => fetchAPI(`/rules/${ruleId}`, {
    method: 'PUT',
    body: JSON.stringify(rule),
  }),
  deleteRule: (ruleId: string) => fetchAPI(`/rules/${ruleId}`, { method: 'DELETE' }),
  toggleRule: (ruleId: string) => fetchAPI(`/rules/${ruleId}/toggle`, { method: 'POST' }),

  // Stats
  getStats: (): Promise<SystemStats> => fetchAPI('/stats'),

  // File sources
  addFileSource: (filepath: string) => fetchAPI('/sources/file/add', {
    method: 'POST',
    body: JSON.stringify({ filepath }),
  }),
};
