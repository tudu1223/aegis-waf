<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { PAYLOAD_CATEGORIES, ALL_PAYLOADS } from '@/data/payloads'
import { useSituationStore } from '@/stores/situation'
import * as api from '@/api'

/**
 * 攻防演练台。
 *
 * 内置 OWASP Top 10 测试载荷库，支持单发与全量演练，
 * 并以流水线动画实时呈现"发起 → 检测 → 处置"的完整过程。
 * 这是验收演示中最具冲击力的环节。
 */
const router = useRouter()
const store = useSituationStore()

const expandedCategories = ref(new Set(['sqli']))
const running = ref(false)
const currentPayload = ref(null)
/** 流水线阶段：idle / sending / detecting / done */
const stage = ref('idle')
const lastResult = ref(null)
const results = ref([])
const useGateway = ref(true)
const vulnStatus = ref({})

function toggleCategory(key) {
  const next = new Set(expandedCategories.value)
  next.has(key) ? next.delete(key) : next.add(key)
  expandedCategories.value = next
}

/** 构造 alg=none 的伪造 JWT，用于 TC-19 算法混淆测试。 */
function forgeNoneJwt() {
  const b64 = (obj) => btoa(JSON.stringify(obj))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const header = b64({ alg: 'none', typ: 'JWT' })
  const payload = b64({
    sub: '1', username: 'admin', role: 'ADMIN',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  })
  return `${header}.${payload}.`
}

async function runPayload(payload) {
  if (running.value) return
  running.value = true
  currentPayload.value = payload
  lastResult.value = null

  // 阶段一：发送
  stage.value = 'sending'
  await sleep(340)

  // 阶段二：检测
  stage.value = 'detecting'

  let result
  if (payload.repeat && payload.repeat > 1) {
    // 暴力破解类用例需连续发送以触发限流
    result = await runBurst(payload)
  } else if (payload.customJwt) {
    result = await runForgedJwt(payload)
  } else {
    result = await api.executePayload(payload, useGateway.value)
  }

  await sleep(260)

  // 阶段三：完成
  stage.value = 'done'
  lastResult.value = result
  results.value.unshift({
    id: payload.id,
    name: payload.name,
    severity: payload.severity,
    blocked: result.blocked,
    status: result.status,
    durationMs: result.durationMs,
    timestamp: Date.now(),
    viaGateway: useGateway.value
  })
  if (results.value.length > 40) results.value.pop()

  running.value = false
  // 演练产生的事件需要时间上报，稍后刷新指标
  setTimeout(() => store.refreshMetricsDebounced(), 900)
}

/** 连续发送以触发速率限制。 */
async function runBurst(payload) {
  let blockedCount = 0
  let lastResponse = null
  const total = payload.repeat
  for (let i = 0; i < total; i++) {
    const r = await api.executePayload(payload, useGateway.value)
    lastResponse = r
    if (r.blocked) blockedCount++
    // 触发限流后即可停止，无需跑完全部
    if (blockedCount >= 3) break
  }
  return {
    ...lastResponse,
    blocked: blockedCount > 0,
    data: {
      ...(lastResponse?.data || {}),
      burstSummary: `连续发送后有 ${blockedCount} 次被限流拦截`
    }
  }
}

/** 使用伪造的 alg=none 令牌访问受保护接口。 */
async function runForgedJwt(payload) {
  const token = forgeNoneJwt()
  const client = useGateway.value ? '/range-gw' : '/range-direct'
  const started = performance.now()
  try {
    const response = await fetch(`${client}${payload.path}`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    const data = await response.json().catch(() => ({}))
    return {
      ok: true,
      status: response.status,
      blocked: response.status === 403 || response.status === 401,
      data,
      durationMs: Math.round(performance.now() - started),
      traceId: response.headers.get('x-aegis-trace') || ''
    }
  } catch (e) {
    return {
      ok: false, status: -1, blocked: false,
      data: { message: e.message },
      durationMs: Math.round(performance.now() - started), traceId: ''
    }
  }
}

/** 全量演练：依次执行所有载荷，是演示的高潮环节。 */
async function runAll() {
  if (running.value) return
  results.value = []
  for (const payload of ALL_PAYLOADS) {
    await runPayload(payload)
    await sleep(420)
  }
  stage.value = 'idle'
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function loadVulnStatus() {
  try {
    const result = await api.fetchVulnStatus()
    vulnStatus.value = result?.vulnerabilities || {}
  } catch (e) {
    vulnStatus.value = {}
  }
}

/** 切换靶场的修复开关，用于验证"修复后攻击失效"。 */
async function toggleAllFixes(patched) {
  await api.toggleAllVuln(patched)
  await loadVulnStatus()
}

const allPatched = computed(() => {
  const items = Object.values(vulnStatus.value)
  return items.length > 0 && items.every((v) => v.patched)
})

const summary = computed(() => {
  const total = results.value.length
  const blocked = results.value.filter((r) => r.blocked).length
  return {
    total,
    blocked,
    passed: total - blocked,
    rate: total ? Math.round((blocked / total) * 1000) / 10 : 0
  }
})

onMounted(loadVulnStatus)
</script>

<template>
  <div class="range">
    <!-- ==================== 控制条 ==================== -->
    <div class="panel range-toolbar">
      <div class="range-toolbar__left">
        <div class="channel-switch">
          <span class="channel-switch__label">攻击通道</span>
          <div class="segmented">
            <button class="segmented__item" :class="{ 'is-active': useGateway }"
                    @click="useGateway = true" title="请求经过 AEGIS 网关与探针防护">
              经 AEGIS 防护
            </button>
            <button class="segmented__item" :class="{ 'is-active': !useGateway }"
                    @click="useGateway = false" title="直连靶场，绕过网关（探针仍生效）">
              直连靶场
            </button>
          </div>
        </div>

        <div class="fix-switch">
          <span class="channel-switch__label">靶场代码</span>
          <div class="segmented">
            <button class="segmented__item" :class="{ 'is-active': !allPatched }"
                    @click="toggleAllFixes(false)" title="使用含漏洞的实现">
              脆弱实现
            </button>
            <button class="segmented__item" :class="{ 'is-active': allPatched }"
                    @click="toggleAllFixes(true)" title="使用已修复的安全实现">
              安全实现
            </button>
          </div>
        </div>
      </div>

      <div class="range-toolbar__right">
        <div v-if="summary.total" class="summary-chips">
          <span class="summary-chip">
            演练 <b class="mono-num">{{ summary.total }}</b>
          </span>
          <span class="summary-chip is-blocked">
            拦截 <b class="mono-num">{{ summary.blocked }}</b>
          </span>
          <span class="summary-chip is-passed">
            放行 <b class="mono-num">{{ summary.passed }}</b>
          </span>
          <span class="summary-chip is-rate">
            拦截率 <b class="mono-num">{{ summary.rate }}%</b>
          </span>
        </div>
        <button class="btn btn--primary" :disabled="running" @click="runAll">
          {{ running ? '演练进行中…' : '▶▶ 一键全量演练' }}
        </button>
      </div>
    </div>

    <div class="range-grid">
      <!-- ==================== 载荷库 ==================== -->
      <div class="panel payload-panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">攻击载荷库</span>
            <span class="panel__subtitle">Payload Library</span>
          </div>
          <span class="panel__hint mono-num">{{ ALL_PAYLOADS.length }} 个用例</span>
        </div>

        <div class="panel__body panel__body--flush payload-scroll">
          <div v-for="category in PAYLOAD_CATEGORIES" :key="category.key" class="category">
            <button class="category__head" @click="toggleCategory(category.key)">
              <span class="category__chevron"
                    :class="{ 'is-open': expandedCategories.has(category.key) }">›</span>
              <span class="category__icon" :style="{ color: category.color }">
                {{ category.icon }}
              </span>
              <span class="category__name">{{ category.name }}</span>
              <span class="category__owasp">{{ category.owasp }}</span>
              <span class="category__count mono-num">{{ category.payloads.length }}</span>
            </button>

            <div v-show="expandedCategories.has(category.key)" class="category__list">
              <div v-for="payload in category.payloads" :key="payload.id"
                   class="payload-item"
                   :class="{
                     'is-running': running && currentPayload?.id === payload.id,
                     'is-highlight': payload.highlight
                   }">
                <div class="payload-item__main">
                  <div class="payload-item__head">
                    <span class="payload-item__id mono-num">{{ payload.id }}</span>
                    <span class="payload-item__name">{{ payload.name }}</span>
                    <span v-if="payload.highlight" class="badge badge--info">核心验证</span>
                  </div>
                  <div class="payload-item__desc">{{ payload.desc }}</div>
                  <div class="payload-item__meta">
                    <span class="badge" :class="`badge--${payload.severity.toLowerCase()}`">
                      CVSS {{ payload.cvss }}
                    </span>
                    <span class="payload-item__detect">{{ payload.detectBy }}</span>
                  </div>
                </div>
                <button class="payload-item__run btn btn--secondary btn--sm"
                        :disabled="running"
                        @click="runPayload(payload)">
                  {{ running && currentPayload?.id === payload.id ? '···' : '▶ 发起' }}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ==================== 实时对抗 ==================== -->
      <div class="side">
        <div class="panel">
          <div class="panel__header">
            <div class="panel__title-group">
              <span class="panel__accent" />
              <span class="panel__title">实时对抗</span>
              <span class="panel__subtitle">Live Combat</span>
            </div>
          </div>
          <div class="panel__body">
            <!-- 流水线动画 -->
            <div class="pipeline">
              <div class="pipeline__node" :class="{ 'is-active': stage !== 'idle' }">
                <div class="pipeline__dot">◉</div>
                <div class="pipeline__label">发起攻击</div>
              </div>

              <div class="pipeline__link">
                <div class="pipeline__beam"
                     :class="{ 'is-flowing': stage === 'sending' || stage === 'detecting' }" />
              </div>

              <div class="pipeline__node"
                   :class="{ 'is-active': stage === 'detecting' || stage === 'done' }">
                <div class="pipeline__dot">
                  <span :class="{ 'is-scanning': stage === 'detecting' }">◈</span>
                </div>
                <div class="pipeline__label">语义检测</div>
              </div>

              <div class="pipeline__link">
                <div class="pipeline__beam"
                     :class="{ 'is-flowing': stage === 'detecting' }" />
              </div>

              <div class="pipeline__node"
                   :class="{
                     'is-active': stage === 'done',
                     'is-blocked': stage === 'done' && lastResult?.blocked,
                     'is-passed': stage === 'done' && !lastResult?.blocked
                   }">
                <div class="pipeline__dot">
                  {{ stage === 'done' ? (lastResult?.blocked ? '⊘' : '✓') : '○' }}
                </div>
                <div class="pipeline__label">
                  {{ stage === 'done' ? (lastResult?.blocked ? '已拦截' : '已放行') : '处置' }}
                </div>
              </div>
            </div>

            <!-- 结果详情 -->
            <div v-if="lastResult" class="result-box"
                 :class="lastResult.blocked ? 'is-blocked' : 'is-passed'">
              <div class="result-box__head">
                <span class="result-box__verdict">
                  {{ lastResult.blocked ? '攻击被成功拦截' : '请求已放行' }}
                </span>
                <span class="result-box__status mono-num">
                  HTTP {{ lastResult.status }} · {{ lastResult.durationMs }}ms
                </span>
              </div>
              <div class="result-box__body">
                <div v-if="lastResult.data?.message" class="result-box__msg">
                  {{ lastResult.data.message }}
                </div>
                <div v-else-if="lastResult.data?.burstSummary" class="result-box__msg">
                  {{ lastResult.data.burstSummary }}
                </div>
                <div v-else-if="lastResult.data?.success" class="result-box__msg is-danger">
                  ⚠ 攻击成功执行，目标系统已受影响
                  <span v-if="lastResult.data?.user">
                    （以 {{ lastResult.data.user.username }} /
                    {{ lastResult.data.user.role }} 身份）
                  </span>
                  <span v-else-if="lastResult.data?.count !== undefined">
                    （返回 {{ lastResult.data.count }} 条记录）
                  </span>
                </div>
              </div>
              <button v-if="lastResult.traceId" class="btn btn--ghost btn--sm"
                      @click="router.push('/events')">
                查看检测事件 ›
              </button>
            </div>

            <div v-else class="pipeline-hint">
              点击左侧任一载荷的「发起」按钮开始演练
            </div>
          </div>
        </div>

        <!-- 演练记录 -->
        <div class="panel">
          <div class="panel__header">
            <div class="panel__title-group">
              <span class="panel__accent" />
              <span class="panel__title">演练记录</span>
              <span class="panel__subtitle">History</span>
            </div>
            <button v-if="results.length" class="btn btn--ghost btn--sm"
                    @click="results = []">清空</button>
          </div>
          <div class="panel__body panel__body--flush">
            <div v-if="results.length" class="result-list">
              <TransitionGroup name="result">
                <div v-for="item in results" :key="item.timestamp" class="result-item">
                  <span class="result-item__id mono-num">{{ item.id }}</span>
                  <span class="result-item__name">{{ item.name }}</span>
                  <span class="result-item__verdict"
                        :class="item.blocked ? 'is-blocked' : 'is-passed'">
                    {{ item.blocked ? '拦截' : '放行' }}
                  </span>
                  <span class="result-item__time mono-num">{{ item.durationMs }}ms</span>
                </div>
              </TransitionGroup>
            </div>
            <div v-else class="empty-state" style="padding:28px 16px">
              <div class="empty-state__title">暂无演练记录</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.range {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

// ---------- 工具栏 ----------
.range-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: $sp-4;
  padding: $sp-3 $sp-5;
  flex-wrap: wrap;

  &__left {
    display: flex;
    align-items: center;
    gap: $sp-6;
    flex-wrap: wrap;
  }

  &__right {
    display: flex;
    align-items: center;
    gap: $sp-4;
  }
}

.channel-switch,
.fix-switch {
  display: flex;
  align-items: center;
  gap: $sp-3;

  &__label {
    font-size: $fs-micro;
    color: $text-tertiary;
    white-space: nowrap;
  }
}

.summary-chips {
  display: flex;
  align-items: center;
  gap: $sp-3;
}

.summary-chip {
  font-size: $fs-micro;
  color: $text-tertiary;
  b {
    font-size: $fs-body;
    font-weight: $fw-semibold;
    color: $text-primary;
    margin-left: 3px;
  }
  &.is-blocked b { color: $safe; }
  &.is-passed b  { color: $critical; }
  &.is-rate b    { color: $primary-600; }
}

// ---------- 布局 ----------
.range-grid {
  display: grid;
  grid-template-columns: 1fr 400px;
  gap: $sp-4;
  align-items: start;
}

.side {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

.payload-scroll {
  max-height: 660px;
  overflow-y: auto;
}

// ---------- 载荷分类 ----------
.category {
  border-bottom: 1px solid $border-subtle;
  &:last-child { border-bottom: none; }

  &__head {
    display: flex;
    align-items: center;
    gap: $sp-2;
    width: 100%;
    padding: $sp-3 $sp-5;
    text-align: left;
    transition: background $dur-instant;
    &:hover { background: $bg-hover; }
  }

  &__chevron {
    font-size: 15px;
    color: $text-tertiary;
    transition: transform $dur-fast $ease-spring;
    &.is-open { transform: rotate(90deg); }
  }

  &__icon { font-size: 13px; }

  &__name {
    font-size: $fs-small;
    font-weight: $fw-semibold;
    color: $text-primary;
  }

  &__owasp {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: $r-full;
    background: $bg-subtle;
    color: $text-tertiary;
    border: 1px solid $border-subtle;
  }

  &__count {
    margin-left: auto;
    font-size: $fs-micro;
    color: $text-tertiary;
  }

  &__list {
    background: rgba(247, 249, 252, 0.5);
  }
}

.payload-item {
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-3 $sp-5 $sp-3 $sp-8;
  border-top: 1px solid $border-subtle;
  transition: background $dur-fast;

  &:hover { background: $bg-surface; }

  &.is-running {
    background: $primary-50;
    animation: payload-pulse 1s $ease-in-out infinite;
  }

  &.is-highlight {
    border-left: 3px solid $info;
    padding-left: calc(#{$sp-8} - 3px);
  }

  &__main { flex: 1; min-width: 0; }

  &__head {
    display: flex;
    align-items: center;
    gap: $sp-2;
    margin-bottom: 2px;
    flex-wrap: wrap;
  }

  &__id {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: $r-xs;
    background: $bg-muted;
    color: $text-secondary;
  }

  &__name {
    font-size: $fs-small;
    font-weight: $fw-medium;
    color: $text-primary;
  }

  &__desc {
    font-size: $fs-micro;
    color: $text-tertiary;
    line-height: 1.5;
    margin-bottom: 4px;
  }

  &__meta {
    display: flex;
    align-items: center;
    gap: $sp-2;
    flex-wrap: wrap;
  }

  &__detect {
    font-size: 10px;
    color: $primary-600;
  }

  &__run { flex-shrink: 0; }
}

@keyframes payload-pulse {
  0%, 100% { background: $primary-50; }
  50%      { background: $primary-100; }
}

// ---------- 流水线动画 ----------
.pipeline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: $sp-4 $sp-2 $sp-5;

  &__node {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: $sp-2;
    opacity: 0.4;
    transition: opacity $dur-normal $ease-out;

    &.is-active { opacity: 1; }

    &.is-blocked .pipeline__dot {
      background: $critical-bg;
      border-color: $critical;
      color: $critical;
      animation: dot-pop $dur-slow $ease-spring;
    }

    &.is-passed .pipeline__dot {
      background: $safe-bg;
      border-color: $safe;
      color: $safe;
      animation: dot-pop $dur-slow $ease-spring;
    }
  }

  &__dot {
    width: 44px;
    height: 44px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 17px;
    color: $primary-600;
    background: $primary-50;
    border: 1.6px solid $primary-200;
    border-radius: $r-full;
    transition: all $dur-normal $ease-out;

    .is-scanning {
      display: inline-block;
      animation: scan-rotate 1.1s linear infinite;
    }
  }

  &__label {
    font-size: $fs-micro;
    font-weight: $fw-medium;
    color: $text-secondary;
    white-space: nowrap;
  }

  &__link {
    flex: 1;
    height: 2px;
    margin: 0 $sp-2;
    margin-bottom: 22px;
    background: $border-default;
    border-radius: $r-full;
    overflow: hidden;
    position: relative;
  }

  &__beam {
    position: absolute;
    inset: 0;
    width: 40%;
    background: linear-gradient(90deg, transparent, $primary-500, transparent);
    transform: translateX(-100%);
    opacity: 0;

    &.is-flowing {
      opacity: 1;
      animation: beam-flow 800ms $ease-in-out infinite;
    }
  }
}

@keyframes beam-flow {
  0%   { transform: translateX(-100%); }
  100% { transform: translateX(320%); }
}

@keyframes scan-rotate {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

@keyframes dot-pop {
  0%   { transform: scale(0.7); }
  55%  { transform: scale(1.14); }
  100% { transform: scale(1); }
}

.pipeline-hint {
  text-align: center;
  font-size: $fs-caption;
  color: $text-tertiary;
  padding: $sp-4 0 $sp-2;
}

// ---------- 结果框 ----------
.result-box {
  padding: $sp-3 $sp-4;
  border-radius: $r-md;
  border: 1px solid;
  animation: result-in $dur-normal $ease-out;

  &.is-blocked {
    background: $safe-bg;
    border-color: $safe-border;
    .result-box__verdict { color: $safe; }
  }

  &.is-passed {
    background: $critical-bg;
    border-color: $critical-border;
    .result-box__verdict { color: $critical; }
  }

  &__head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: $sp-2;
    margin-bottom: $sp-2;
  }

  &__verdict {
    font-size: $fs-small;
    font-weight: $fw-semibold;
  }

  &__status {
    font-size: 10px;
    color: $text-tertiary;
  }

  &__msg {
    font-size: $fs-micro;
    color: $text-secondary;
    line-height: 1.6;
    word-break: break-word;

    &.is-danger { color: $critical; font-weight: $fw-medium; }
  }
}

@keyframes result-in {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}

// ---------- 演练记录 ----------
.result-list {
  max-height: 260px;
  overflow-y: auto;
}

.result-item {
  display: flex;
  align-items: center;
  gap: $sp-2;
  padding: $sp-2 $sp-5;
  border-bottom: 1px solid $border-subtle;
  font-size: $fs-micro;

  &:last-child { border-bottom: none; }

  &__id {
    font-size: 10px;
    color: $text-tertiary;
    flex-shrink: 0;
  }

  &__name {
    flex: 1;
    min-width: 0;
    color: $text-secondary;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  &__verdict {
    font-weight: $fw-semibold;
    flex-shrink: 0;
    &.is-blocked { color: $safe; }
    &.is-passed  { color: $critical; }
  }

  &__time {
    font-size: 10px;
    color: $text-tertiary;
    width: 46px;
    text-align: right;
    flex-shrink: 0;
  }
}

.result-enter-active { transition: all $dur-normal $ease-out; }
.result-enter-from   { opacity: 0; transform: translateX(14px); }
.result-move         { transition: transform $dur-normal $ease-out; }

.panel__hint { font-size: $fs-micro; color: $text-tertiary; }

@media (max-width: 1400px) {
  .range-grid { grid-template-columns: 1fr; }
}
</style>
