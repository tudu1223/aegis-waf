<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import * as api from '@/api'
import AstGraph from '@/components/AstGraph.vue'

/**
 * AST 语义分析页。
 *
 * 展示单次攻击的完整取证信息：
 *   AST 结构差分 → 判定结论 → 变异节点 → 证据链 → SQL 对照
 * 这是"结构指纹 + 差分定位"技术路线最直观的呈现。
 */
const route = useRoute()
const router = useRouter()

const loading = ref(false)
const error = ref('')
const event = ref(null)
const traceChain = ref([])
const recentEvents = ref([])

const eventId = computed(() => route.params.eventId || '')

async function loadEvent(id) {
  if (!id) {
    await loadRecent()
    return
  }
  loading.value = true
  error.value = ''
  try {
    const result = await api.fetchEventDetail(id)
    event.value = result?.data || null
    if (event.value?.traceId) {
      const chain = await api.fetchTraceChain(event.value.traceId)
      traceChain.value = chain?.chain || []
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function loadRecent() {
  loading.value = true
  try {
    const result = await api.fetchEvents({ size: 20, severity: '' })
    recentEvents.value = (result?.data || []).filter((e) => e.layer === 'RASP')
    // 默认展示最近一条探针层事件，其包含完整的 AST 差分数据
    if (recentEvents.value.length && !eventId.value) {
      router.replace(`/analysis/${recentEvents.value[0].eventId}`)
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

onMounted(() => loadEvent(eventId.value))
watch(eventId, (id) => loadEvent(id))

/** 可视化树数据，来自后端的结构差分导出。 */
const visualTree = computed(() => {
  const diff = event.value?.diff
  const tree = diff?.visualTree?.tree
  return tree && tree.id ? tree : null
})

const annotations = computed(() => event.value?.diff?.visualTree?.annotations || [])
const evidence = computed(() => {
  const raw = event.value?.evidence
  return Array.isArray(raw) ? raw : []
})

const similarity = computed(() => {
  const value = event.value?.similarity ?? 0
  return Math.round(value * 1000) / 10
})

const riskScore = computed(() => event.value?.riskScore ?? 0)

const severityMeta = computed(() => ({
  CRITICAL: { cls: 'critical', label: '严重' },
  HIGH: { cls: 'high', label: '高危' },
  MEDIUM: { cls: 'medium', label: '中危' },
  LOW: { cls: 'low', label: '低危' },
  INFO: { cls: 'neutral', label: '信息' }
}[event.value?.severity] || { cls: 'neutral', label: '未知' }))

const verdictMeta = computed(() => ({
  BLOCK: { cls: 'safe', label: '已拦截' },
  MONITOR: { cls: 'medium', label: '已记录' },
  PASS: { cls: 'neutral', label: '已放行' }
}[event.value?.verdict] || { cls: 'neutral', label: '—' }))

/** SQL 语法高亮：区分关键字、字符串、危险函数。 */
function highlightSql(sql) {
  if (!sql) return ''
  const escaped = sql
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  const dangerous = /\b(SLEEP|BENCHMARK|LOAD_FILE|EXTRACTVALUE|UPDATEXML|OUTFILE|DUMPFILE|INFORMATION_SCHEMA)\b/gi
  const keywords = /\b(SELECT|FROM|WHERE|AND|OR|NOT|UNION|ALL|INSERT|INTO|VALUES|UPDATE|SET|DELETE|DROP|CREATE|ALTER|TABLE|JOIN|LEFT|RIGHT|INNER|ON|GROUP|ORDER|BY|HAVING|LIMIT|OFFSET|AS|IN|LIKE|BETWEEN|IS|NULL|EXISTS|CASE|WHEN|THEN|ELSE|END|DISTINCT)\b/gi
  const strings = /'([^']*)'/g
  const comments = /(--[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)/g

  return escaped
    .replace(comments, '<span class="sql-comment">$1</span>')
    .replace(strings, "<span class=\"sql-string\">'$1'</span>")
    .replace(dangerous, '<span class="sql-danger">$&</span>')
    .replace(keywords, '<span class="sql-keyword">$&</span>')
}

function formatTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('zh-CN', { hour12: false })
}

function selectEvent(id) {
  router.push(`/analysis/${id}`)
}
</script>

<template>
  <div class="analysis">
    <!-- 加载与空状态 -->
    <div v-if="loading" class="panel">
      <div class="panel__body">
        <div class="skeleton" style="height:22px;width:40%;margin-bottom:16px" />
        <div class="skeleton" style="height:400px" />
      </div>
    </div>

    <div v-else-if="!event" class="panel">
      <div class="empty-state">
        <div class="empty-state__icon">⌘</div>
        <div class="empty-state__title">暂无可分析的事件</div>
        <div class="empty-state__desc">
          前往「攻防演练」发起一次 SQL 注入测试，系统将在此展示完整的
          AST 结构差分与取证信息。
        </div>
        <RouterLink to="/range" class="btn btn--primary" style="margin-top:16px">
          前往演练台
        </RouterLink>
      </div>
    </div>

    <template v-else>
      <!-- ==================== 事件头部 ==================== -->
      <div class="panel event-header">
        <div class="event-header__left">
          <button class="btn btn--ghost btn--sm" @click="router.back()">‹ 返回</button>
          <div class="event-header__ids">
            <div class="event-header__title">
              <span class="badge" :class="`badge--${severityMeta.cls}`">
                {{ severityMeta.label }}
              </span>
              <span class="event-header__type">SQL 注入语义分析</span>
              <span class="badge badge--neutral">
                {{ event.layer === 'RASP' ? '探针层判定' : '网关层判定' }}
              </span>
            </div>
            <div class="event-header__meta mono-num">
              事件 {{ String(event.eventId).slice(0, 8) }} ·
              追踪 {{ String(event.traceId).slice(0, 8) || '—' }} ·
              {{ formatTime(event.timestamp) }}
            </div>
          </div>
        </div>

        <div class="event-header__right">
          <div class="metric-chip">
            <span class="metric-chip__key">风险评分</span>
            <span class="metric-chip__val mono-num"
                  :style="{ color: riskScore >= 90 ? '#E11D48' : '#EA580C' }">
              {{ riskScore }}
            </span>
          </div>
          <div class="metric-chip">
            <span class="metric-chip__key">结构相似度</span>
            <span class="metric-chip__val mono-num">{{ similarity }}%</span>
          </div>
          <div class="metric-chip">
            <span class="metric-chip__key">处置</span>
            <span class="badge" :class="`badge--${verdictMeta.cls}`">
              {{ verdictMeta.label }}
            </span>
          </div>
        </div>
      </div>

      <!-- ==================== 主体：AST 树 + 判定 ==================== -->
      <div class="analysis-grid">
        <div class="panel">
          <div class="panel__header">
            <div class="panel__title-group">
              <span class="panel__accent" />
              <span class="panel__title">语法树结构差分</span>
              <span class="panel__subtitle">AST Structural Diff</span>
            </div>
            <span class="panel__hint">红色节点为检出的注入变异结构</span>
          </div>
          <div class="panel__body">
            <AstGraph v-if="visualTree" :tree="visualTree" height="520px" />
            <div v-else class="empty-state" style="padding:56px 16px">
              <div class="empty-state__icon">⌘</div>
              <div class="empty-state__title">该事件无 AST 结构数据</div>
              <div class="empty-state__desc">
                仅探针层（RASP）捕获真实 SQL 的事件包含语法树信息。
                网关层事件基于 HTTP 参数做启发式判定，不产生语法树。
              </div>
            </div>
          </div>
        </div>

        <div class="side-column">
          <!-- 变异节点清单 -->
          <div class="panel">
            <div class="panel__header">
              <div class="panel__title-group">
                <span class="panel__accent" />
                <span class="panel__title">变异节点</span>
                <span class="panel__subtitle">Mutations</span>
              </div>
              <span class="panel__hint mono-num">{{ annotations.length }}</span>
            </div>
            <div class="panel__body panel__body--flush">
              <div v-if="annotations.length" class="mutation-list">
                <div v-for="(item, index) in annotations" :key="index"
                     class="mutation-item"
                     :class="{ 'is-critical': item.critical }">
                  <div class="mutation-item__head">
                    <span class="mutation-item__index mono-num">{{ index + 1 }}</span>
                    <span class="mutation-item__name">{{ item.kindName }}</span>
                    <span v-if="item.critical" class="badge badge--critical">严重</span>
                  </div>
                  <div class="mutation-item__detail">{{ item.detail }}</div>
                  <div class="mutation-item__path mono-num">{{ item.path }}</div>
                </div>
              </div>
              <div v-else class="empty-state" style="padding:28px 16px">
                <div class="empty-state__title">无结构变异</div>
              </div>
            </div>
          </div>

          <!-- 判定依据 -->
          <div class="panel">
            <div class="panel__header">
              <div class="panel__title-group">
                <span class="panel__accent" />
                <span class="panel__title">判定依据</span>
                <span class="panel__subtitle">Evidence</span>
              </div>
            </div>
            <div class="panel__body panel__body--flush">
              <div v-if="evidence.length" class="evidence-list">
                <div v-for="(item, index) in evidence" :key="index" class="evidence-item">
                  <span class="evidence-item__marker" />
                  <span class="evidence-item__text">{{ item }}</span>
                </div>
              </div>
              <div v-else class="empty-state" style="padding:24px 16px">
                <div class="empty-state__title">无</div>
              </div>
            </div>
          </div>

          <!-- 指纹对照 -->
          <div class="panel">
            <div class="panel__header">
              <div class="panel__title-group">
                <span class="panel__accent" />
                <span class="panel__title">结构指纹</span>
                <span class="panel__subtitle">Fingerprint</span>
              </div>
            </div>
            <div class="panel__body">
              <div class="fp-row">
                <span class="fp-row__key">基线</span>
                <code class="fp-row__val">
                  {{ event.baselineFingerprint || '（无基线，冷启动判定）' }}
                </code>
              </div>
              <div class="fp-row">
                <span class="fp-row__key">实际</span>
                <code class="fp-row__val is-mismatch">
                  {{ event.actualFingerprint || '—' }}
                </code>
              </div>
              <div class="fp-note">
                指纹由归一化语法树的规范序列化结果计算得出，
                与参数取值和文本形态无关，仅反映 SQL 的语义结构。
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ==================== 证据链 ==================== -->
      <div class="panel" v-if="traceChain.length">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">攻击证据链</span>
            <span class="panel__subtitle">Evidence Chain</span>
          </div>
          <span class="panel__hint">
            同一 TraceID 关联的网关层与探针层事件，构成完整的攻击路径
          </span>
        </div>
        <div class="panel__body">
          <div class="chain">
            <div v-for="(node, index) in traceChain" :key="node.eventId"
                 class="chain-node"
                 :class="{ 'is-current': node.eventId === event.eventId }">
              <div class="chain-node__badge">
                {{ node.layer === 'RASP' ? '探针层' : '网关层' }}
              </div>
              <div class="chain-node__body">
                <div class="chain-node__title">
                  {{ node.layer === 'RASP' ? '真实 SQL 结构判定' : 'HTTP 参数启发式判定' }}
                </div>
                <div class="chain-node__desc mono-num">
                  {{ node.paramName ? `参数 ${node.paramName}` : node.endpoint }}
                </div>
                <div class="chain-node__foot">
                  <span class="badge"
                        :class="node.verdict === 'BLOCK' ? 'badge--safe' : 'badge--medium'">
                    {{ node.verdict === 'BLOCK' ? '已拦截' : '已记录' }}
                  </span>
                  <span class="chain-node__score mono-num">风险 {{ node.riskScore }}</span>
                </div>
              </div>
              <div v-if="index < traceChain.length - 1" class="chain-arrow">→</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ==================== SQL 原文 ==================== -->
      <div class="panel" v-if="event.rawSql || event.rawPayload">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">{{ event.rawSql ? '捕获的真实 SQL' : '攻击载荷' }}</span>
            <span class="panel__subtitle">{{ event.rawSql ? 'Captured SQL' : 'Payload' }}</span>
          </div>
          <span v-if="event.rawSql" class="panel__hint">
            由 RASP 探针在语句送达数据库前捕获
          </span>
        </div>
        <div class="panel__body">
          <pre class="sql-block"><code v-html="highlightSql(event.rawSql || event.rawPayload)" /></pre>
          <div v-if="event.normalizedPayload && event.normalizedPayload !== event.rawPayload"
               class="normalized-block">
            <div class="normalized-block__label">归一化后</div>
            <code class="normalized-block__code">{{ event.normalizedPayload }}</code>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.analysis {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

// ---------- 事件头部 ----------
.event-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: $sp-4;
  padding: $sp-4 $sp-5;
  flex-wrap: wrap;

  &__left {
    display: flex;
    align-items: center;
    gap: $sp-3;
    min-width: 0;
  }

  &__ids { min-width: 0; }

  &__title {
    display: flex;
    align-items: center;
    gap: $sp-2;
    flex-wrap: wrap;
  }

  &__type {
    font-size: $fs-h3;
    font-weight: $fw-semibold;
    color: $text-primary;
  }

  &__meta {
    margin-top: 2px;
    font-size: $fs-micro;
    color: $text-tertiary;
  }

  &__right {
    display: flex;
    align-items: center;
    gap: $sp-5;
  }
}

.metric-chip {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 2px;

  &__key {
    font-size: 10px;
    color: $text-tertiary;
    letter-spacing: 0.04em;
  }

  &__val {
    font-size: $fs-h3;
    font-weight: $fw-semibold;
    color: $text-primary;
    line-height: 1;
  }
}

// ---------- 主体网格 ----------
.analysis-grid {
  display: grid;
  grid-template-columns: 1fr 372px;
  gap: $sp-4;
  align-items: start;
}

.side-column {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

// ---------- 变异节点 ----------
.mutation-list {
  display: flex;
  flex-direction: column;
  max-height: 250px;
  overflow-y: auto;
}

.mutation-item {
  padding: $sp-3 $sp-5;
  border-bottom: 1px solid $border-subtle;
  border-left: 3px solid transparent;
  transition: background $dur-instant;

  &:last-child { border-bottom: none; }
  &:hover { background: $bg-hover; }
  &.is-critical { border-left-color: $critical; background: rgba(255, 241, 242, 0.4); }

  &__head {
    display: flex;
    align-items: center;
    gap: $sp-2;
    margin-bottom: 3px;
  }

  &__index {
    width: 18px;
    height: 18px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 10px;
    border-radius: $r-xs;
    background: $bg-subtle;
    color: $text-tertiary;
    flex-shrink: 0;
  }

  &__name {
    font-size: $fs-small;
    font-weight: $fw-semibold;
    color: $text-primary;
  }

  &__detail {
    font-size: $fs-caption;
    color: $text-secondary;
    line-height: 1.5;
  }

  &__path {
    margin-top: 3px;
    font-size: 10px;
    color: $text-tertiary;
    word-break: break-all;
  }
}

// ---------- 证据 ----------
.evidence-list {
  display: flex;
  flex-direction: column;
  max-height: 190px;
  overflow-y: auto;
  padding: $sp-2 0;
}

.evidence-item {
  display: flex;
  align-items: flex-start;
  gap: $sp-2;
  padding: $sp-2 $sp-5;

  &__marker {
    width: 5px;
    height: 5px;
    margin-top: 7px;
    border-radius: $r-full;
    background: $primary-400;
    flex-shrink: 0;
  }

  &__text {
    font-size: $fs-caption;
    color: $text-secondary;
    line-height: 1.55;
  }
}

// ---------- 指纹 ----------
.fp-row {
  display: flex;
  align-items: center;
  gap: $sp-3;
  margin-bottom: $sp-2;

  &__key {
    width: 32px;
    font-size: $fs-micro;
    color: $text-tertiary;
    flex-shrink: 0;
  }

  &__val {
    flex: 1;
    min-width: 0;
    padding: $sp-1 $sp-2;
    font-family: $font-mono;
    font-size: 10.5px;
    color: $text-secondary;
    background: $bg-subtle;
    border: 1px solid $border-subtle;
    border-radius: $r-xs;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;

    &.is-mismatch {
      color: $critical;
      background: $critical-bg;
      border-color: $critical-border;
    }
  }
}

.fp-note {
  margin-top: $sp-3;
  padding-top: $sp-3;
  border-top: 1px dashed $border-default;
  font-size: 10.5px;
  line-height: 1.6;
  color: $text-tertiary;
}

// ---------- 证据链 ----------
.chain {
  display: flex;
  align-items: stretch;
  gap: $sp-2;
  flex-wrap: wrap;
}

.chain-node {
  position: relative;
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-3 $sp-4;
  min-width: 232px;
  background: $bg-surface;
  border: 1px solid $border-default;
  border-radius: $r-md;
  transition: all $dur-fast $ease-out;

  &.is-current {
    border-color: $primary-300;
    background: $primary-50;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.08);
  }

  &__badge {
    padding: 2px $sp-2;
    font-size: 10px;
    font-weight: $fw-semibold;
    color: $primary-600;
    background: $primary-50;
    border: 1px solid $primary-200;
    border-radius: $r-full;
    white-space: nowrap;
    flex-shrink: 0;
  }

  &__body { min-width: 0; }

  &__title {
    font-size: $fs-caption;
    font-weight: $fw-semibold;
    color: $text-primary;
  }

  &__desc {
    font-size: 10px;
    color: $text-tertiary;
    margin: 1px 0 4px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 190px;
  }

  &__foot {
    display: flex;
    align-items: center;
    gap: $sp-2;
  }

  &__score {
    font-size: 10px;
    color: $text-tertiary;
  }
}

.chain-arrow {
  display: flex;
  align-items: center;
  font-size: 18px;
  color: $text-tertiary;
  padding: 0 $sp-1;
}

// ---------- SQL 展示 ----------
.sql-block {
  margin: 0;
  padding: $sp-4;
  background: #FBFCFE;
  border: 1px solid $border-subtle;
  border-radius: $r-md;
  font-family: $font-mono;
  font-size: 12.5px;
  line-height: 1.75;
  color: $text-primary;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;

  :deep(.sql-keyword) { color: #5b4be0; font-weight: 600; }
  :deep(.sql-string)  { color: #059669; }
  :deep(.sql-comment) { color: #9AA3B0; font-style: italic; }
  :deep(.sql-danger)  {
    color: #E11D48;
    font-weight: 700;
    background: rgba(225, 29, 72, 0.08);
    padding: 0 3px;
    border-radius: 3px;
  }
}

.normalized-block {
  margin-top: $sp-3;
  padding: $sp-3;
  background: $primary-50;
  border: 1px solid $primary-100;
  border-radius: $r-sm;

  &__label {
    font-size: 10px;
    font-weight: $fw-semibold;
    color: $primary-600;
    letter-spacing: 0.06em;
    margin-bottom: 3px;
  }

  &__code {
    font-family: $font-mono;
    font-size: 11.5px;
    color: $text-secondary;
    word-break: break-all;
  }
}

.panel__hint {
  font-size: $fs-micro;
  color: $text-tertiary;
}

@media (max-width: 1400px) {
  .analysis-grid { grid-template-columns: 1fr; }
}
</style>
