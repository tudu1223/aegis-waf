<script setup>
import { ref, watch, onMounted, computed } from 'vue'

/**
 * 指标卡片。
 *
 * 数值变化时使用滚动动画而非直接跳变，配合等宽数字字体
 * 保证跳动过程中宽度稳定——这是专业感的关键细节。
 */
const props = defineProps({
  label: { type: String, required: true },
  labelEn: { type: String, default: '' },
  value: { type: [Number, String], default: 0 },
  suffix: { type: String, default: '' },
  trend: { type: Number, default: null },
  accent: { type: String, default: 'primary' },
  sparkline: { type: Array, default: () => [] },
  decimals: { type: Number, default: 0 }
})

const displayValue = ref(0)
let animationFrame = null

/** 数值滚动动画：使用 easeOutExpo 曲线，快进慢出更自然。 */
function animateTo(target) {
  if (typeof target !== 'number' || Number.isNaN(target)) {
    displayValue.value = target
    return
  }
  const start = typeof displayValue.value === 'number' ? displayValue.value : 0
  const delta = target - start
  if (delta === 0) return

  const duration = 700
  const startTime = performance.now()

  if (animationFrame) cancelAnimationFrame(animationFrame)

  const step = (now) => {
    const elapsed = now - startTime
    const progress = Math.min(elapsed / duration, 1)
    // easeOutExpo：起步快、末尾平滑收敛
    const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress)
    displayValue.value = start + delta * eased
    if (progress < 1) {
      animationFrame = requestAnimationFrame(step)
    } else {
      displayValue.value = target
    }
  }
  animationFrame = requestAnimationFrame(step)
}

watch(() => props.value, (v) => animateTo(v), { immediate: false })
onMounted(() => animateTo(props.value))

const formatted = computed(() => {
  const v = displayValue.value
  if (typeof v !== 'number') return v
  return props.decimals > 0
    ? v.toFixed(props.decimals)
    : Math.round(v).toLocaleString('zh-CN')
})

/** 迷你趋势线：作为卡片背景的低调装饰，不喧宾夺主。 */
const sparkPath = computed(() => {
  const data = props.sparkline
  if (!data || data.length < 2) return ''
  const max = Math.max(...data, 1)
  const min = Math.min(...data, 0)
  const range = max - min || 1
  const width = 100
  const height = 28
  return data.map((value, index) => {
    const x = (index / (data.length - 1)) * width
    const y = height - ((value - min) / range) * height
    return `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
})

const sparkAreaPath = computed(() => {
  if (!sparkPath.value) return ''
  return `${sparkPath.value} L100,28 L0,28 Z`
})
</script>

<template>
  <div class="kpi-card panel is-interactive" :class="`kpi-card--${accent}`">
    <!-- 背景趋势线 -->
    <svg v-if="sparkPath" class="kpi-card__spark" viewBox="0 0 100 28" preserveAspectRatio="none">
      <defs>
        <linearGradient :id="`spark-${accent}`" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" class="spark-stop-top" />
          <stop offset="100%" class="spark-stop-bottom" />
        </linearGradient>
      </defs>
      <path :d="sparkAreaPath" :fill="`url(#spark-${accent})`" />
      <path :d="sparkPath" fill="none" class="spark-line" stroke-width="1.4"
            vector-effect="non-scaling-stroke" />
    </svg>

    <div class="kpi-card__body">
      <div class="kpi-card__labels">
        <span class="kpi-card__label">{{ label }}</span>
        <span v-if="labelEn" class="kpi-card__label-en">{{ labelEn }}</span>
      </div>

      <div class="kpi-card__value-row">
        <span class="kpi-card__value mono-num">{{ formatted }}</span>
        <span v-if="suffix" class="kpi-card__suffix">{{ suffix }}</span>
      </div>

      <div v-if="trend !== null" class="kpi-card__trend"
           :class="trend >= 0 ? 'is-up' : 'is-down'">
        <span class="kpi-card__trend-arrow">{{ trend >= 0 ? '↗' : '↘' }}</span>
        <span class="mono-num">{{ Math.abs(trend).toFixed(1) }}%</span>
        <span class="kpi-card__trend-label">较上一时段</span>
      </div>
      <slot name="footer" />
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.kpi-card {
  position: relative;
  overflow: hidden;
  min-height: 118px;

  &__spark {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    width: 100%;
    height: 42px;
    opacity: 0.5;
    pointer-events: none;
  }

  &__body {
    position: relative;
    padding: $sp-4 $sp-5;
    display: flex;
    flex-direction: column;
    gap: $sp-2;
  }

  &__labels {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  &__label {
    font-size: $fs-caption;
    font-weight: $fw-medium;
    color: $text-secondary;
  }

  &__label-en {
    font-size: 9px;
    font-weight: $fw-medium;
    color: $text-tertiary;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  &__value-row {
    display: flex;
    align-items: baseline;
    gap: $sp-2;
  }

  &__value {
    font-size: 30px;
    font-weight: $fw-semibold;
    color: $text-primary;
    line-height: 1.1;
  }

  &__suffix {
    font-size: $fs-body;
    font-weight: $fw-medium;
    color: $text-tertiary;
  }

  &__trend {
    display: flex;
    align-items: center;
    gap: $sp-1;
    font-size: $fs-micro;
    font-weight: $fw-medium;

    &.is-up   { color: $safe; }
    &.is-down { color: $critical; }
  }

  &__trend-arrow { font-size: 12px; }
  &__trend-label { color: $text-tertiary; font-weight: $fw-normal; }

  // ---------- 语义色变体 ----------
  &--primary {
    .spark-line { stroke: $primary-500; }
    .spark-stop-top    { stop-color: rgba(59, 130, 246, 0.22); }
    .spark-stop-bottom { stop-color: rgba(59, 130, 246, 0); }
  }
  &--safe {
    .spark-line { stroke: $safe; }
    .spark-stop-top    { stop-color: rgba(5, 150, 105, 0.22); }
    .spark-stop-bottom { stop-color: rgba(5, 150, 105, 0); }
  }
  &--critical {
    .spark-line { stroke: $critical; }
    .spark-stop-top    { stop-color: rgba(225, 29, 72, 0.20); }
    .spark-stop-bottom { stop-color: rgba(225, 29, 72, 0); }
    .kpi-card__value { color: $critical; }
  }
  &--medium {
    .spark-line { stroke: $medium; }
    .spark-stop-top    { stop-color: rgba(217, 119, 6, 0.20); }
    .spark-stop-bottom { stop-color: rgba(217, 119, 6, 0); }
  }
  &--info {
    .spark-line { stroke: $info; }
    .spark-stop-top    { stop-color: rgba(79, 70, 229, 0.20); }
    .spark-stop-bottom { stop-color: rgba(79, 70, 229, 0); }
  }
}
</style>
