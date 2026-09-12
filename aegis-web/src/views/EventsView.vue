<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import * as api from '@/api'
import { useSituationStore } from '@/stores/situation'

/**
 * 威胁事件列表页。
 *
 * 支持按威胁类型、严重级别、检测层次与来源 IP 多维筛选，
 * 并提供审计日志哈希链的完整性校验入口。
 */
const router = useRouter()
const store = useSituationStore()

const events = ref([])
const total = ref(0)
const page = ref(0)
const size = ref(20)
const loading = ref(false)

const filters = ref({
  threatType: '',
  severity: '',
  layer: '',
  sourceIp: ''
})

const chainResult = ref(null)
const verifying = ref(false)

const threatOptions = [
  { value: '', label: '全部类型' },
  { value: 'SQL_INJECTION', label: 'SQL 注入' },
  { value: 'XSS', label: '跨站脚本' },
  { value: 'COMMAND_INJECTION', label: '命令注入' },
  { value: 'PATH_TRAVERSAL', label: '路径穿越' },
  { value: 'RATE_ABUSE', label: '速率异常' }
]

const severityOptions = [
  { value: '', label: '全部级别' },
  { value: 'CRITICAL', label: '严重' },
  { value: 'HIGH', label: '高危' },
  { value: 'MEDIUM', label: '中危' },
  { value: 'LOW', label: '低危' }
]

const layerOptions = [
  { value: '', label: '全部层次' },
  { value: 'GATEWAY', label: '网关层' },
  { value: 'RASP', label: '探针层' }
]

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, size: size.value }
    Object.entries(filters.value).forEach(([key, value]) => {
      if (value) params[key] = value
    })
    const result = await api.fetchEvents(params)
    events.value = result?.data || []
    total.value = result?.total || 0
  } catch (e) {
    events.value = []
  } finally {
    loading.value = false
  }
}

async function verifyChain() {
  verifying.value = true
  try {
    chainResult.value = await api.verifyHashChain()
  } catch (e) {
    chainResult.value = { intact: false, message: e.message }
  } finally {
    verifying.value = false
  }
}

async function clearAll() {
  if (!confirm('确定清空全部检测事件？此操作不可撤销。')) return
  await store.clearAllEvents()
  chainResult.value = null
  await load()
}

function resetFilters() {
  filters.value = { threatType: '', severity: '', layer: '', sourceIp: '' }
  page.value = 0
  load()
}

watch(filters, () => { page.value = 0; load() }, { deep: true })
onMounted(load)

const totalPages = computed(() => Math.ceil(total.value / size.value) || 1)

const severityMap = {
  CRITICAL: { cls: 'critical', label: '严重' },
  HIGH: { cls: 'high', label: '高危' },
  MEDIUM: { cls: 'medium', label: '中危' },
  LOW: { cls: 'low', label: '低危' },
  INFO: { cls: 'neutral', label: '信息' }
}

const threatNameMap = {
  SQL_INJECTION: 'SQL 注入',
  XSS: '跨站脚本',
  COMMAND_INJECTION: '命令注入',
  PATH_TRAVERSAL: '路径穿越',
  BROKEN_ACCESS_CONTROL: '越权访问',
  RATE_ABUSE: '速率异常',
  SSRF: '服务端请求伪造'
}

function formatTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('zh-CN', { hour12: false })
}

function goPage(delta) {
  const next = page.value + delta
  if (next < 0 || next >= totalPages.value) return
  page.value = next
  load()
}
</script>

<template>
  <div class="events">
    <!-- 筛选栏 -->
    <div class="panel filter-bar">
      <div class="filter-bar__left">
        <select v-model="filters.threatType" class="select">
          <option v-for="o in threatOptions" :key="o.value" :value="o.value">
            {{ o.label }}
          </option>
        </select>
        <select v-model="filters.severity" class="select">
          <option v-for="o in severityOptions" :key="o.value" :value="o.value">
            {{ o.label }}
          </option>
        </select>
        <select v-model="filters.layer" class="select">
          <option v-for="o in layerOptions" :key="o.value" :value="o.value">
            {{ o.label }}
          </option>
        </select>
        <input v-model="filters.sourceIp" class="input" placeholder="来源 IP" />
        <button class="btn btn--ghost btn--sm" @click="resetFilters">重置</button>
      </div>

      <div class="filter-bar__right">
        <button class="btn btn--secondary btn--sm" :disabled="verifying"
                @click="verifyChain">
          {{ verifying ? '校验中…' : '校验审计链' }}
        </button>
        <button class="btn btn--ghost btn--sm" @click="clearAll">清空事件</button>
      </div>
    </div>

    <!-- 哈希链校验结果 -->
    <div v-if="chainResult" class="chain-result"
         :class="chainResult.intact ? 'is-ok' : 'is-broken'">
      <span class="chain-result__icon">{{ chainResult.intact ? '✓' : '✕' }}</span>
      <div class="chain-result__text">
        <b>{{ chainResult.intact ? '审计日志完整性校验通过' : '审计日志完整性校验失败' }}</b>
        <span>
          {{ chainResult.message }}
          <template v-if="chainResult.totalRecords !== undefined">
            · 共校验 {{ chainResult.totalRecords }} 条记录
          </template>
        </span>
      </div>
      <button class="btn btn--ghost btn--sm" @click="chainResult = null">关闭</button>
    </div>

    <!-- 事件表格 -->
    <div class="panel">
      <div class="panel__header">
        <div class="panel__title-group">
          <span class="panel__accent" />
          <span class="panel__title">检测事件</span>
          <span class="panel__subtitle">Detection Events</span>
        </div>
        <span class="panel__hint mono-num">共 {{ total }} 条</span>
      </div>

      <div class="panel__body panel__body--flush">
        <div v-if="loading" style="padding:20px">
          <div v-for="i in 6" :key="i" class="skeleton"
               style="height:38px;margin-bottom:8px" />
        </div>

        <table v-else-if="events.length" class="data-table">
          <thead>
            <tr>
              <th style="width:150px">时间</th>
              <th style="width:80px">层次</th>
              <th style="width:110px">威胁类型</th>
              <th style="width:70px">级别</th>
              <th style="width:70px">处置</th>
              <th style="width:120px">来源 IP</th>
              <th>接口</th>
              <th style="width:70px">风险</th>
              <th style="width:80px">耗时</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="event in events" :key="event.eventId"
                class="event-row" @click="router.push(`/analysis/${event.eventId}`)">
              <td class="mono-num">{{ formatTime(event.timestamp) }}</td>
              <td>
                <span class="layer-tag">
                  {{ event.layer === 'RASP' ? '探针' : '网关' }}
                </span>
              </td>
              <td>{{ threatNameMap[event.threatType] || event.threatType }}</td>
              <td>
                <span class="badge"
                      :class="`badge--${(severityMap[event.severity] || {}).cls || 'neutral'}`">
                  {{ (severityMap[event.severity] || {}).label || '—' }}
                </span>
              </td>
              <td>
                <span :class="event.verdict === 'BLOCK' ? 'verdict-block' : 'verdict-monitor'">
                  {{ event.verdict === 'BLOCK' ? '拦截' : '记录' }}
                </span>
              </td>
              <td class="mono-num">{{ event.sourceIp || '—' }}</td>
              <td class="mono-num text-truncate" style="max-width:280px">
                {{ event.endpoint || event.uri || '—' }}
              </td>
              <td class="mono-num">
                <b :style="{ color: event.riskScore >= 90 ? '#E11D48' : '#EA580C' }">
                  {{ event.riskScore ?? 0 }}
                </b>
              </td>
              <td class="mono-num" style="color:#9AA3B0">
                {{ event.detectionCostMicros
                   ? (event.detectionCostMicros / 1000).toFixed(2) + 'ms' : '—' }}
              </td>
            </tr>
          </tbody>
        </table>

        <div v-else class="empty-state">
          <div class="empty-state__icon">◈</div>
          <div class="empty-state__title">暂无匹配的事件</div>
          <div class="empty-state__desc">
            调整筛选条件，或前往「攻防演练」发起测试攻击。
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="total > size" class="pagination">
        <button class="btn btn--ghost btn--sm" :disabled="page === 0"
                @click="goPage(-1)">‹ 上一页</button>
        <span class="pagination__info mono-num">
          {{ page + 1 }} / {{ totalPages }}
        </span>
        <button class="btn btn--ghost btn--sm" :disabled="page >= totalPages - 1"
                @click="goPage(1)">下一页 ›</button>
      </div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.events {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

.filter-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: $sp-4;
  padding: $sp-3 $sp-5;
  flex-wrap: wrap;

  &__left,
  &__right {
    display: flex;
    align-items: center;
    gap: $sp-2;
    flex-wrap: wrap;
  }
}

.select,
.input {
  height: 32px;
  padding: 0 $sp-3;
  font-size: $fs-small;
  font-family: inherit;
  color: $text-secondary;
  background: $bg-surface;
  border: 1px solid $border-default;
  border-radius: $r-sm;
  transition: all $dur-fast $ease-out;
  outline: none;

  &:hover { border-color: $border-strong; }
  &:focus {
    border-color: $primary-400;
    box-shadow: 0 0 0 3px $primary-glow;
  }
}

.select { cursor: pointer; min-width: 116px; }
.input  { width: 140px; }

.chain-result {
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-3 $sp-5;
  border-radius: $r-md;
  border: 1px solid;
  animation: fade-in $dur-normal $ease-out;

  &.is-ok {
    background: $safe-bg;
    border-color: $safe-border;
    .chain-result__icon { color: $safe; }
    b { color: $safe; }
  }

  &.is-broken {
    background: $critical-bg;
    border-color: $critical-border;
    .chain-result__icon { color: $critical; }
    b { color: $critical; }
  }

  &__icon {
    font-size: 18px;
    font-weight: $fw-bold;
    flex-shrink: 0;
  }

  &__text {
    flex: 1;
    display: flex;
    flex-direction: column;
    font-size: $fs-small;
    b { font-weight: $fw-semibold; }
    span { font-size: $fs-caption; color: $text-secondary; }
  }
}

@keyframes fade-in {
  from { opacity: 0; transform: translateY(-6px); }
  to   { opacity: 1; transform: translateY(0); }
}

.event-row {
  cursor: pointer;
}

.layer-tag {
  font-size: 10px;
  padding: 2px 7px;
  border-radius: $r-full;
  background: $bg-subtle;
  color: $text-secondary;
  border: 1px solid $border-subtle;
}

.verdict-block   { color: $safe;   font-weight: $fw-semibold; }
.verdict-monitor { color: $medium; font-weight: $fw-semibold; }

.pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: $sp-4;
  padding: $sp-3;
  border-top: 1px solid $border-subtle;

  &__info {
    font-size: $fs-small;
    color: $text-secondary;
  }
}

.panel__hint { font-size: $fs-micro; color: $text-tertiary; }
</style>
