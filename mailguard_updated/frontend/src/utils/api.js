const BASE = '/api/v1'

function getToken() {
  return localStorage.getItem('mg_token')
}

async function request(path, opts = {}) {
  const token = getToken()
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...opts.headers,
  }
  const res = await fetch(`${BASE}${path}`, { ...opts, headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  authHeaders: () => { const t = getToken(); return t ? { Authorization: `Bearer ${t}` } : {} },
  // Auth
  login:          (username, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  changePassword: (token, newPassword) => request('/auth/change-password', { method: 'POST', body: JSON.stringify({ token, new_password: newPassword }) }),

  // Tenants
  listTenants:  ()     => request('/tenants/'),
  createTenant: (data) => request('/tenants/', { method: 'POST', body: JSON.stringify(data) }),
  deleteTenant: (id)   => request(`/tenants/${id}`, { method: 'DELETE' }),

  // Scans
  triggerScan: (tenantId) => request(`/scans/${tenantId}/trigger`, { method: 'POST' }),
  scanStatus:  (scanId)   => request(`/scans/status/${scanId}`),
  scanResult:  (scanId)   => request(`/scans/result/${scanId}`),
  scanHistory: (tenantId) => request(`/scans/${tenantId}/history`),

  // Reports
  reportPdfUrl: (scanId) => `${BASE}/reports/${scanId}/pdf`,
}
