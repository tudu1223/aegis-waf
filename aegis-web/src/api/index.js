import axios from 'axios'

/**
 * 控制台 API 客户端。
 *
 * 统一处理超时与错误，避免每个调用点重复编写异常处理。
 */
const http = axios.create({
  baseURL: '/api',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' }
})

http.interceptors.response.use(
  (response) => response.data,
  (error) => {
    // 网络异常或服务不可达时返回结构化的失败结果，
    // 使调用方无需区分"业务失败"与"网络失败"两种异常路径
    const message = error.response?.data?.message || error.message || '请求失败'
    return Promise.reject(new Error(message))
  }
)

// ==================== 统计 ====================

export const fetchOverview = () => http.get('/stats/overview')
export const fetchThreatDistribution = () => http.get('/stats/threat-distribution')
export const fetchTopAttackers = (limit = 8) =>
  http.get('/stats/top-attackers', { params: { limit } })
export const fetchTopEndpoints = (limit = 8) =>
  http.get('/stats/top-endpoints', { params: { limit } })
export const fetchTimeline = (minutes = 30, buckets = 30) =>
  http.get('/stats/timeline', { params: { minutes, buckets } })

// ==================== 事件 ====================

export const fetchEvents = (params = {}) => http.get('/events', { params })
export const fetchEventDetail = (eventId) => http.get(`/events/${eventId}`)
export const fetchTraceChain = (traceId) => http.get(`/events/trace/${traceId}`)
export const verifyHashChain = () => http.get('/events/verify-chain')
export const clearEvents = () => http.delete('/events/all')

// ==================== 策略 ====================

export const fetchPolicy = () => http.get('/policy')
export const updatePolicy = (payload) => http.put('/policy', payload)

// ==================== 基线 ====================

export const fetchBaselines = (endpoint) =>
  http.get('/baselines', { params: endpoint ? { endpoint } : {} })
export const addBaseline = (endpoint, sql) => http.post('/baselines', { endpoint, sql })
export const confirmBaseline = (id) => http.post(`/baselines/${id}/confirm`)
export const disableBaseline = (id) => http.post(`/baselines/${id}/disable`)
export const deleteBaseline = (id) => http.delete(`/baselines/${id}`)
export const clearBaselines = () => http.delete('/baselines')

// ==================== 靶场（演练台使用）====================

/** 经网关发起请求，用于验证防护效果。 */
const gateway = axios.create({ baseURL: '/range-gw', timeout: 20000 })

/** 直连靶场，用于对比展示无防护时的危害。 */
const direct = axios.create({ baseURL: '/range-direct', timeout: 20000 })

/**
 * 通过指定通道执行一次攻击载荷。
 *
 * @param {object} payload 载荷定义
 * @param {boolean} viaGateway 是否经过网关防护
 * @returns 统一结构的执行结果，含状态码、耗时与响应体
 */
export async function executePayload(payload, viaGateway = true) {
  const client = viaGateway ? gateway : direct
  const started = performance.now()
  try {
    const config = { validateStatus: () => true }
    let response
    if (payload.method === 'GET') {
      response = await client.get(payload.path, { params: payload.params, ...config })
    } else {
      response = await client.post(payload.path, payload.body || {}, config)
    }
    return {
      ok: true,
      status: response.status,
      blocked: response.status === 403 || response.status === 429,
      data: response.data,
      durationMs: Math.round(performance.now() - started),
      traceId: response.headers?.['x-aegis-trace'] || ''
    }
  } catch (error) {
    return {
      ok: false,
      status: -1,
      blocked: false,
      data: { message: error.message },
      durationMs: Math.round(performance.now() - started),
      traceId: ''
    }
  }
}

/** 查询靶场的漏洞修复开关状态。 */
export async function fetchVulnStatus() {
  const response = await direct.get('/api/vuln/status', { validateStatus: () => true })
  return response.data
}

/** 切换靶场的漏洞修复开关，用于第三轮"修复验证"。 */
export async function toggleVuln(id, patched) {
  const response = await direct.post('/api/vuln/toggle', { id, patched },
    { validateStatus: () => true })
  return response.data
}

export async function toggleAllVuln(patched) {
  const response = await direct.post('/api/vuln/toggle-all', { patched },
    { validateStatus: () => true })
  return response.data
}

export default http
