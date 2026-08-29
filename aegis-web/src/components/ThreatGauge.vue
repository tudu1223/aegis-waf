<script setup>
import { computed, ref, watch, onMounted } from 'vue'

/**
 * 防护态势环形仪表。
 *
 * 双层圆环：外层为刻度环（模拟精密仪表），内层为进度弧。
 * 常态下不做无意义的旋转动画，仅在数值变化时平滑过渡——
 * 动效服务于信息，而非装饰。
 */
const props = defineProps({
  value: { type: Number, default: 0 },
  label: { type: String, default: '拦截率' },
  sublabel: { type: String, default: '' },
  color: { type: String, default: '#3B82F6' },
  size: { type: Number, default: 176 }
})

const RADIUS = 68
const CIRCUMFERENCE = 2 * Math.PI * RADIUS
/** 圆环留出底部缺口，形成仪表盘观感（270 度弧）。 */
const ARC_RATIO = 0.75

const animated = ref(0)
let frame = null

watch(() => props.value, (target) => {
  const start = animated.value
  const delta = target - start
  if (Math.abs(delta) < 0.01) return
  const duration = 800
  const startTime = performance.now()
  if (frame) cancelAnimationFrame(frame)
  const step = (now) => {
    const p = Math.min((now - startTime) / duration, 1)
    const eased = 1 - Math.pow(1 - p, 3)
    animated.value = start + delta * eased
    if (p < 1) frame = requestAnimationFrame(step)
  }
  frame = requestAnimationFrame(step)
}, { immediate: false })

onMounted(() => { animated.value = props.value })

const dashArray = computed(() => `${CIRCUMFERENCE * ARC_RATIO} ${CIRCUMFERENCE}`)
const dashOffset = computed(() => {
  const ratio = Math.max(0, Math.min(100, animated.value)) / 100
  return CIRCUMFERENCE * ARC_RATIO * (1 - ratio)
})

/** 60 段细刻度，营造精密仪表的质感。 */
const ticks = computed(() => {
  const result = []
  const total = 48
  for (let i = 0; i <= total; i++) {
    const angle = 135 + (270 / total) * i
    const rad = (angle * Math.PI) / 180
    const outer = 82
    const inner = i % 6 === 0 ? 72 : 77
    result.push({
      x1: 88 + outer * Math.cos(rad),
      y1: 88 + outer * Math.sin(rad),
      x2: 88 + inner * Math.cos(rad),
      y2: 88 + inner * Math.sin(rad),
      major: i % 6 === 0,
      active: (i / total) * 100 <= animated.value
    })
  }
  return result
})

const displayValue = computed(() => animated.value.toFixed(1))
</script>

<template>
  <div class="gauge" :style="{ width: `${size}px`, height: `${size}px` }">
    <svg viewBox="0 0 176 176" class="gauge__svg">
      <defs>
        <linearGradient :id="`gauge-grad-${label}`" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" :stop-color="color" stop-opacity="0.95" />
          <stop offset="100%" :stop-color="color" stop-opacity="0.6" />
        </linearGradient>
        <filter :id="`gauge-glow-${label}`" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <!-- 外层刻度环 -->
      <g class="gauge__ticks">
        <line
          v-for="(tick, index) in ticks"
          :key="index"
          :x1="tick.x1" :y1="tick.y1" :x2="tick.x2" :y2="tick.y2"
          :stroke="tick.active ? color : '#E2E8F0'"
          :stroke-width="tick.major ? 1.6 : 1"
          :opacity="tick.active ? 0.85 : 0.5"
          stroke-linecap="round"
        />
      </g>

      <!-- 进度轨道 -->
      <circle
        cx="88" cy="88" :r="RADIUS"
        fill="none" stroke="#EDF1F7" stroke-width="9"
        :stroke-dasharray="dashArray"
        stroke-linecap="round"
        transform="rotate(135 88 88)"
      />

      <!-- 进度弧 -->
      <circle
        cx="88" cy="88" :r="RADIUS"
        fill="none"
        :stroke="`url(#gauge-grad-${label})`"
        stroke-width="9"
        :stroke-dasharray="dashArray"
        :stroke-dashoffset="dashOffset"
        stroke-linecap="round"
        transform="rotate(135 88 88)"
        :filter="`url(#gauge-glow-${label})`"
        class="gauge__arc"
      />
    </svg>

    <div class="gauge__center">
      <div class="gauge__value mono-num" :style="{ color }">
        {{ displayValue }}<span class="gauge__unit">%</span>
      </div>
      <div class="gauge__label">{{ label }}</div>
      <div v-if="sublabel" class="gauge__sublabel">{{ sublabel }}</div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.gauge {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;

  &__svg {
    width: 100%;
    height: 100%;
    display: block;
  }

  &__arc {
    transition: stroke-dashoffset $dur-slower $ease-out,
                stroke $dur-slow $ease-in-out;
  }

  &__center {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    pointer-events: none;
  }

  &__value {
    font-size: 30px;
    font-weight: $fw-semibold;
    line-height: 1.1;
    transition: color $dur-slow $ease-in-out;
  }

  &__unit {
    font-size: 15px;
    margin-left: 1px;
    opacity: 0.75;
  }

  &__label {
    margin-top: 2px;
    font-size: $fs-caption;
    font-weight: $fw-medium;
    color: $text-secondary;
  }

  &__sublabel {
    font-size: 10px;
    color: $text-tertiary;
    letter-spacing: 0.06em;
  }
}
</style>
