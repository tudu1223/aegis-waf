import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as api from '@/api'

/**
 * 全局态势 Store。
 *
 * 集中管理指标、事件流与防护策略，并维护 WebSocket 长连接。
 * 大屏各组件订阅此 store，保证数据一致性与推送时效。
 */
export const useSituationStore = defineStore('situation', () => {
  // ---------- 状态 ----------
  const overview = ref({
    totalRequests: 0,
    totalEvents: 0,
    blockedCount: 0,
    monitoredCount: 0,
    criticalCount: 0,
    highCount: 0,
    interceptRate: 100,
    threatLevel: 0,
    threatLevelLabel: '安全',
    avgDetectionMillis: 0,
    baselineTotal: 0,
    baselineConfirmed: 0,
    recentHourEvents: 0
  })

  /** 实时事件流，最多保留 60 条以控制内存与渲染开销。 */
  const liveEvents = ref([])
  const MAX_LIVE_EVENTS = 60

  const threatDistribution = ref([])
  const topAttackers = ref([])
  const topEndpoints = ref([])
  const timeline = ref([])

  const policy = ref({
    mode: 'BLOCK',
    learningMode: false,
    blockThreshold: 70,
    rateLimitCapacity: 100,
    rateLimitRefillPerSecond: 20,
    slidingWindowThreshold: 600
  })

  const connected = ref(false)
  const loading = ref(false)
  const lastError = ref('')

  // ---------- 计算属性 ----------

  /** 威胁水位对应的语义色，用于仪表盘与徽标。 */
  const threatColor = computed(() => {
    const level = overview.value.threatLevel
    if (level >= 80) return '#E11D48'
    if (level >= 60) return '#EA580C'
    if (level >= 40) return '#D97706'
    if (level >= 20) return '#0891B2'
    return '#059669'
  })

  /** 防护是否处于启用状态。 */
  const isProtected = computed(() => policy.value.mode !== 'OFF')

  // ---------- 动作 ----------

  async function loadAll() {
    loading.value = true
    lastError.value = ''
    try {
      const [ov, dist, attackers, endpoints, tl, pol] = await Promise.all([
        api.fetchOverview(),
        api.fetchThreatDistribution(),
        api.fetchTopAttackers(8),
        api.fetchTopEndpoints(8),
        api.fetchTimeline(30, 30),
        api.fetchPolicy()
      ])
      if (ov?.data) overview.value = { ...overview.value, ...ov.data }
      if (dist?.data) threatDistribution.value = dist.data
      if (attackers?.data) topAttackers.value = attackers.data
      if (endpoints?.data) topEndpoints.value = endpoints.data
      if (tl?.data) timeline.value = tl.data
      if (pol?.data) policy.value = { ...policy.value, ...pol.data }
    } catch (error) {
      lastError.value = error.message
    } finally {
      loading.value = false
    }
  }

  async function loadRecentEvents() {
    try {
      const result = await api.fetchEvents({ size: 30 })
      if (result?.data) {
        liveEvents.value = result.data.map((e) => ({ ...e, isNew: false }))
      }
    } catch (error) {
      lastError.value = error.message
    }
  }

  /** 接收 WebSocket 推送的新事件。 */
  function pushEvent(event) {
    liveEvents.value.unshift({ ...event, isNew: true })
    if (liveEvents.value.length > MAX_LIVE_EVENTS) {
      liveEvents.value.pop()
    }
    // 300ms 后移除"新增"标记，使入场动画只播放一次
    setTimeout(() => {
      const target = liveEvents.value.find((e) => e.eventId === event.eventId)
      if (target) target.isNew = false
    }, 800)
  }

  async function changeMode(mode) {
    try {
      const result = await api.updatePolicy({ mode })
      if (result?.data) policy.value = { ...policy.value, ...result.data }
      return true
    } catch (error) {
      lastError.value = error.message
      return false
    }
  }

  async function changeLearningMode(enabled) {
    try {
      const result = await api.updatePolicy({ learningMode: enabled })
      if (result?.data) policy.value = { ...policy.value, ...result.data }
    } catch (error) {
      lastError.value = error.message
    }
  }

  async function clearAllEvents() {
    try {
      await api.clearEvents()
      liveEvents.value = []
      await loadAll()
    } catch (error) {
      lastError.value = error.message
    }
  }

  // ---------- WebSocket ----------

  let socket = null
  let reconnectTimer = null
  let reconnectDelay = 1000

  function connect() {
    if (socket && socket.readyState === WebSocket.OPEN) return

    const protocol = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${protocol}://${location.host}/ws/aegis`

    try {
      socket = new WebSocket(url)
    } catch (error) {
      scheduleReconnect()
      return
    }

    socket.onopen = () => {
      connected.value = true
      reconnectDelay = 1000
    }

    socket.onmessage = (message) => {
      try {
        const packet = JSON.parse(message.data)
        if (packet.type === 'EVENT') {
          pushEvent(packet.data)
          // 事件到达时同步刷新指标，保证大屏数字与事件流一致
          refreshMetricsDebounced()
        } else if (packet.type === 'POLICY') {
          policy.value = { ...policy.value, ...packet.data }
        } else if (packet.type === 'METRICS') {
          overview.value = { ...overview.value, ...packet.data }
        }
      } catch (error) {
        // 忽略无法解析的消息，避免单条异常影响连接
      }
    }

    socket.onclose = () => {
      connected.value = false
      scheduleReconnect()
    }

    socket.onerror = () => {
      connected.value = false
    }
  }

  function scheduleReconnect() {
    if (reconnectTimer) return
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      // 指数退避，上限 15 秒，避免服务不可用时的高频重连
      reconnectDelay = Math.min(reconnectDelay * 1.6, 15000)
      connect()
    }, reconnectDelay)
  }

  function disconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (socket) {
      socket.onclose = null
      socket.close()
      socket = null
    }
    connected.value = false
  }

  // 指标刷新节流：高频攻击时避免过多请求
  let metricsTimer = null
  function refreshMetricsDebounced() {
    if (metricsTimer) return
    metricsTimer = setTimeout(async () => {
      metricsTimer = null
      try {
        const [ov, dist, attackers, tl] = await Promise.all([
          api.fetchOverview(),
          api.fetchThreatDistribution(),
          api.fetchTopAttackers(8),
          api.fetchTimeline(30, 30)
        ])
        if (ov?.data) overview.value = { ...overview.value, ...ov.data }
        if (dist?.data) threatDistribution.value = dist.data
        if (attackers?.data) topAttackers.value = attackers.data
        if (tl?.data) timeline.value = tl.data
      } catch (error) {
        // 静默失败，下次推送时重试
      }
    }, 700)
  }

  return {
    overview, liveEvents, threatDistribution, topAttackers, topEndpoints,
    timeline, policy, connected, loading, lastError,
    threatColor, isProtected,
    loadAll, loadRecentEvents, pushEvent, changeMode, changeLearningMode,
    clearAllEvents, connect, disconnect, refreshMetricsDebounced
  }
})
