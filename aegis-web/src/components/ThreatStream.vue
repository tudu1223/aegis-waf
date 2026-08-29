<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'

/**
 * 实时威胁流。
 *
 * 新事件以侧向飞入动画呈现，营造"实时感"——
 * 这是大屏演示中最直观的动态元素。
 */
const props = defineProps({
  events: { type: Array, default: () => [] },
  maxHeight: { type: String, default: '380px' },
  compact: { type: Boolean, default: false }
})

const router = useRouter()

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
  AUTH_FAILURE: '认证失败',
  INSECURE_DESERIALIZATION: '反序列化',
  SSRF: '服务端请求伪造',
  RATE_ABUSE: '速率异常',
  INFO_DISCLOSURE: '信息泄露'
}

const verdictMap = {
  BLOCK: { cls: 'block', label: '已拦截' },
  MONITOR: { cls: 'monitor', label: '已记录' },
  PASS: { cls: 'pass', label: '已放行' }
}

function formatTime(timestamp) {
  if (!timestamp) return '--:--:--'
  const d = new Date(timestamp)
  return d.toLocaleTimeString('zh-CN', { hour12: false })
}

function severityOf(event) {
  return severityMap[event.severity] || severityMap.INFO
}

function threatName(event) {
  return threatNameMap[event.threatType] || event.threatType
}

function verdictOf(event) {
  return verdictMap[event.verdict] || verdictMap.PASS
}

function shortEndpoint(event) {
  const value = event.endpoint || event.uri || ''
  return value.length > 42 ? value.slice(0, 42) + '…' : value
}

function openDetail(event) {
  if (event.eventId) {
    router.push(`/analysis/${event.eventId}`)
  }
}

const hasEvents = computed(() => props.events && props.events.length > 0)
</script>

<template>
  <div class="threat-stream" :style="{ maxHeight }">
    <TransitionGroup name="stream" tag="div" class="threat-stream__list">
      <article
        v-for="event in events"
        :key="event.eventId"
        class="threat-item"
        :class="[`is-${severityOf(event).cls}`, { 'is-new': event.isNew }]"
        @click="openDetail(event)"
      >
        <span class="threat-item__bar" />

        <div class="threat-item__main">
          <div class="threat-item__row">
            <span class="badge" :class="`badge--${severityOf(event).cls}`">
              {{ severityOf(event).label }}
            </span>
            <span class="threat-item__name">{{ threatName(event) }}</span>
            <span class="threat-item__layer">{{ event.layer === 'RASP' ? '探针层' : '网关层' }}</span>
            <span class="threat-item__time mono-num">{{ formatTime(event.timestamp) }}</span>
          </div>

          <div class="threat-item__row threat-item__row--sub" v-if="!compact">
            <span class="threat-item__ip mono-num">{{ event.sourceIp || '—' }}</span>
            <span class="threat-item__arrow">→</span>
            <span class="threat-item__endpoint mono-num">{{ shortEndpoint(event) }}</span>
          </div>

          <div class="threat-item__row threat-item__row--foot">
            <span class="threat-item__verdict" :class="`is-${verdictOf(event).cls}`">
              {{ verdictOf(event).label }}
            </span>
            <span class="threat-item__score">
              风险 <b class="mono-num">{{ event.riskScore ?? 0 }}</b>
            </span>
            <span v-if="event.detectionCostMicros" class="threat-item__cost mono-num">
              {{ (event.detectionCostMicros / 1000).toFixed(2) }}ms
            </span>
          </div>
        </div>

        <span class="threat-item__chevron">›</span>
      </article>
    </TransitionGroup>

    <div v-if="!hasEvents" class="empty-state">
      <div class="empty-state__icon">◎</div>
      <div class="empty-state__title">暂无威胁事件</div>
      <div class="empty-state__desc">
        系统运行正常。可前往「攻防演练」发起测试攻击以验证防护能力。
      </div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.threat-stream {
  overflow-y: auto;
  overflow-x: hidden;

  &__list {
    display: flex;
    flex-direction: column;
  }
}

.threat-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-3 $sp-4 $sp-3 $sp-5;
  border-bottom: 1px solid $border-subtle;
  cursor: pointer;
  transition: background $dur-instant $ease-out;

  &:hover {
    background: $bg-hover;
    .threat-item__chevron { opacity: 1; transform: translateX(2px); }
  }

  &:last-child { border-bottom: none; }

  // 左侧语义色标识条
  &__bar {
    position: absolute;
    left: 0;
    top: 8px;
    bottom: 8px;
    width: 3px;
    border-radius: 0 $r-full $r-full 0;
  }

  &.is-critical &__bar { background: $critical; }
  &.is-high &__bar     { background: $high; }
  &.is-medium &__bar   { background: $medium; }
  &.is-low &__bar      { background: $low; }
  &.is-neutral &__bar  { background: $border-strong; }

  &__main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  &__row {
    display: flex;
    align-items: center;
    gap: $sp-2;
    min-width: 0;

    &--sub  { font-size: $fs-micro; color: $text-tertiary; }
    &--foot { font-size: $fs-micro; }
  }

  &__name {
    font-size: $fs-small;
    font-weight: $fw-semibold;
    color: $text-primary;
  }

  &__layer {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: $r-full;
    background: $bg-subtle;
    color: $text-tertiary;
    border: 1px solid $border-subtle;
  }

  &__time {
    margin-left: auto;
    font-size: $fs-micro;
    color: $text-tertiary;
    flex-shrink: 0;
  }

  &__ip { color: $text-secondary; }
  &__arrow { color: $text-tertiary; }
  &__endpoint {
    color: $text-tertiary;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  &__verdict {
    font-weight: $fw-semibold;
    &.is-block   { color: $safe; }
    &.is-monitor { color: $medium; }
    &.is-pass    { color: $text-tertiary; }
  }

  &__score {
    color: $text-tertiary;
    b { color: $text-secondary; font-weight: $fw-semibold; }
  }

  &__cost {
    margin-left: auto;
    color: $text-tertiary;
    font-size: 10px;
  }

  &__chevron {
    font-size: 18px;
    color: $text-tertiary;
    opacity: 0;
    transition: all $dur-fast $ease-out;
    flex-shrink: 0;
  }

  // ---------- 新事件飞入动效 ----------
  // 这是"实时感"的核心来源：新事件从右侧滑入并短暂高亮
  &.is-new {
    animation: stream-in $dur-slow $ease-out;
  }
}

@keyframes stream-in {
  0% {
    opacity: 0;
    transform: translateX(20px);
    background: $primary-50;
  }
  55% {
    opacity: 1;
    transform: translateX(0);
    background: $primary-50;
  }
  100% {
    background: transparent;
  }
}

// TransitionGroup 的列表位移过渡
.stream-move { transition: transform $dur-normal $ease-out; }
.stream-enter-active { transition: all $dur-normal $ease-out; }
.stream-leave-active {
  transition: all $dur-fast $ease-in-out;
  position: absolute;
  width: 100%;
}
.stream-enter-from { opacity: 0; transform: translateX(20px); }
.stream-leave-to   { opacity: 0; transform: translateX(-12px); }
</style>
