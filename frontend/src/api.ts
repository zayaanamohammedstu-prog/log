import axios from 'axios'

const BASE = '/api'

axios.interceptors.request.use(config => {
  const token = localStorage.getItem('logguard_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export const login = (username: string, password: string) =>
  axios.post(`${BASE}/auth/login`, { username, password }).then(r => r.data)

export const register = (username: string, password: string, email?: string, role?: string) =>
  axios.post(`${BASE}/auth/register`, { username, password, email, role }).then(r => r.data)

export const getMe = () =>
  axios.get(`${BASE}/auth/me`).then(r => r.data)

export const analyzeFile = (file: File) => {
  const form = new FormData()
  form.append('file', file)
  return axios.post(`${BASE}/analyze`, form).then(r => r.data)
}

export const analyzeSample = () =>
  axios.post(`${BASE}/analyze`, { use_sample: true }).then(r => r.data)

export const getRuns = () =>
  axios.get(`${BASE}/runs`).then(r => r.data)

export const getRun = (id: number) =>
  axios.get(`${BASE}/runs/${id}`).then(r => r.data)

export const getRunSummary = (id: number) =>
  axios.get(`${BASE}/runs/${id}/summary`).then(r => r.data)

export const getHtmlReport = (id: number) =>
  `${BASE}/runs/${id}/report`

export const exportCsv = (id?: number) =>
  id ? `${BASE}/runs/${id}/export/csv` : `${BASE}/export/csv`

export const sendEmail = (runId: number, to: string) =>
  axios.post(`${BASE}/runs/${runId}/send/email`, { to }).then(r => r.data)

export const sendWhatsApp = (runId: number, to: string) =>
  axios.post(`${BASE}/runs/${runId}/send/whatsapp`, { to }).then(r => r.data)

export const getUsers = () =>
  axios.get(`${BASE}/admin/users`).then(r => r.data)

export const getPendingUsers = () =>
  axios.get(`${BASE}/admin/users/pending`).then(r => r.data)

export const approveUser = (id: number) =>
  axios.post(`${BASE}/admin/users/${id}/approve`).then(r => r.data)

export const rejectUser = (id: number) =>
  axios.post(`${BASE}/admin/users/${id}/reject`).then(r => r.data)

export const deleteUser = (id: number) =>
  axios.delete(`${BASE}/admin/users/${id}`).then(r => r.data)

export const restoreUser = (id: number) =>
  axios.post(`${BASE}/admin/users/${id}/restore`).then(r => r.data)

export const getDeletedUsers = () =>
  axios.get(`${BASE}/admin/users/deleted`).then(r => r.data)

export const createUser = (data: Record<string, string>) =>
  axios.post(`${BASE}/admin/users`, data).then(r => r.data)

export const getAuditEntries = () =>
  axios.get(`${BASE}/audit/entries`).then(r => r.data)

export const verifyAuditChain = () =>
  axios.get(`${BASE}/audit/verify`).then(r => r.data)

export const getAdminStats = () =>
  axios.get(`${BASE}/admin/stats`).then(r => r.data)

export const updateUserRole = (id: number, role: string) =>
  axios.patch(`${BASE}/admin/users/${id}/role`, { role }).then(r => r.data)

export const getDeletedRuns = () =>
  axios.get(`${BASE}/admin/runs/deleted`).then(r => r.data)

export const restoreRun = (id: number) =>
  axios.post(`${BASE}/admin/runs/${id}/restore`).then(r => r.data)
