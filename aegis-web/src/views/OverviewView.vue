<script setup>
import { computed } from 'vue'
import { useSituationStore } from '@/stores/situation'
import KpiCard from '@/components/KpiCard.vue'
import ThreatGauge from '@/components/ThreatGauge.vue'
import ThreatStream from '@/components/ThreatStream.vue'
import BaseChart from '@/components/BaseChart.vue'

const store = useSituationStore()

/**
 * 迷你趋势线数据。
 *
 * 直接使用原始时序会导致数据点集中在末尾（演示时攻击集中发生），
 * 视觉上挤成一团。此处仅取有数据的尾部区间并补齐到固定长度，
 * 使趋势线在卡片内均匀展开。
 */
function toSparkline(values, length = 16) {
  if (!values.length) return []
  // 找到最后一个非零点，截取其之前的窗口
  let lastIndex = values.length - 1
  while (lastIndex > 0 && values[lastIndex] === 0) lastIndex--
  const start = Math.max(0, lastIndex - length + 1)
  const slice = values.slice(start, lastIndex + 1)
  // 数据不足时在前部补零，保证曲线起点在左侧
  while (slice.length < length) slice.unshift(0)
  return slice
}

const eventSpark = computed(() =>
  toSparkline(store.timeline.map((p) => p.events || 0)))
const blockedSpark = computed(() =>
  toSparkline(store.timeline.map((p) => p.blocked || 0)))

// ==================== 时序趋势图 ====================
const timelineOption = computed(() => {
  const points = store.timeline
  const labels = points.map((p) =>
    new Date(p.timestamp).toLocaleTimeString('zh-CN', {
      hour12: false, hour: '2-digit', minute: '2-digit'
    })
  )
  return {
    grid: { left: 8, right: 12, top: 28, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(240,242,246,0.96)',
      borderColor: '#C6CCD6',
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: '#333333', fontSize: 12 },
      extraCssText: 'box-shadow:0 8px 24px rgba(15,23,42,.10);border-radius:10px;',
      axisPointer: { type: 'line', lineStyle: { color: '#B8BEC9', type: 'dashed' } }
    },
    legend: {
      data: ['检测事件', '已拦截'],
      right: 0, top: 0,
      itemWidth: 10, itemHeight: 10, itemGap: 16,
      textStyle: { color: '#6b7280', fontSize: 11 },
      icon: 'roundRect'
    },
    xAxis: {
      type: 'category',
      data: labels,
      boundaryGap: false,
      axisLine: { lineStyle: { color: '#C6CCD6' } },
      axisTick: { show: false },
      axisLabel: { color: '#9AA3B0', fontSize: 10, interval: 'auto' }
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      splitLine: { lineStyle: { color: '#D4D9E1', type: 'dashed' } },
      axisLabel: { color: '#9AA3B0', fontSize: 10 }
    },
    series: [
      {
        name: '检测事件',
        type: 'line',
        smooth: 0.4,
        symbol: 'none',
        lineStyle: { width: 2, color: '#6d5dfc' },
        areaStyle: {
          color: {
            type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(59,130,246,0.20)' },
              { offset: 1, color: 'rgba(59,130,246,0.01)' }
            ]
          }
        },
        data: points.map((p) => p.events || 0)
      },
      {
        name: '已拦截',
        type: 'bar',
        barWidth: '42%',
        itemStyle: {
          color: {
            type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: '#F43F5E' },
              { offset: 1, color: 'rgba(244,63,94,0.45)' }
            ]
          },
          borderRadius: [3, 3, 0, 0]
        },
        data: points.map((p) => p.blocked || 0)
      }
    ]
  }
})

// ==================== 威胁类型分布 ====================
const PALETTE = ['#6d5dfc', '#E11D48', '#EA580C', '#D97706', '#059669',
                 '#7A6EE0', '#0891B2', '#7C3AED']

const distributionOption = computed(() => {
  const data = store.threatDistribution
  if (!data.length) {
    return { series: [] }
  }
  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(240,242,246,0.96)',
      borderColor: '#C6CCD6',
      textStyle: { color: '#333333', fontSize: 12 },
      extraCssText: 'box-shadow:0 8px 24px rgba(15,23,42,.10);border-radius:10px;',
      formatter: '{b}<br/>数量 {c} · 占比 {d}%'
    },
    legend: {
      orient: 'vertical',
      right: 4, top: 'center',
      itemWidth: 9, itemHeight: 9, itemGap: 10,
      textStyle: { color: '#6b7280', fontSize: 11 },
      icon: 'circle'
    },
    series: [{
      type: 'pie',
      radius: ['46%', '72%'],
      center: ['34%', '50%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 5, borderColor: '#e0e5ec', borderWidth: 2 },
      label: { show: false },
      labelLine: { show: false },
      emphasis: {
        scale: true, scaleSize: 6,
        itemStyle: { shadowBlur: 14, shadowColor: 'rgba(15,23,42,0.14)' }
      },
      data: data.map((item, index) => ({
        name: item.name,
        value: item.value,
        itemStyle: { color: PALETTE[index % PALETTE.length] }
      }))
    }]
  }
})

// ==================== 攻击源排行 ====================
const attackerOption = computed(() => {
  const data = [...store.topAttackers].reverse()
  return {
    grid: { left: 4, right: 40, top: 6, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: 'rgba(240,242,246,0.96)',
      borderColor: '#C6CCD6',
      textStyle: { color: '#333333', fontSize: 12 },
      extraCssText: 'box-shadow:0 8px 24px rgba(15,23,42,.10);border-radius:10px;'
    },
    xAxis: { type: 'value', show: false },
    yAxis: {
      type: 'category',
      data: data.map((d) => d.ip),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: '#6b7280', fontSize: 11,
        fontFamily: 'JetBrains Mono, monospace'
      }
    },
    series: [{
      type: 'bar',
      barWidth: 13,
      itemStyle: {
        borderRadius: [0, 6, 6, 0],
        color: {
          type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
          colorStops: [
            { offset: 0, color: 'rgba(59,130,246,0.35)' },
            { offset: 1, color: '#6d5dfc' }
          ]
        }
      },
      label: {
        show: true, position: 'right',
        color: '#6b7280', fontSize: 11,
        fontFamily: 'JetBrains Mono, monospace'
      },
      data: data.map((d) => d.count)
    }]
  }
})

const modeLabel = computed(() => ({
  OFF: '防护已关闭',
  MONITOR: '仅记录模式',
  BLOCK: '全量拦截中'
}[store.policy.mode] || '未知'))

const modeClass = computed(() => ({
  OFF: 'critical',
  MONITOR: 'medium',
  BLOCK: 'safe'
}[store.policy.mode] || 'neutral'))
</script>

<template>
  <div class="overview">
    <!-- 防护状态提示条 -->
    <div v-if="store.policy.mode === 'OFF'" class="alert-banner">
      <span class="alert-banner__icon">⚠</span>
      <div class="alert-banner__text">
        <b>防护已关闭</b>
        <span>当前所有请求均不做安全检测，仅用于演示漏洞的真实危害。请在演示结束后切回拦截模式。</span>
      </div>
    </div>

    <!-- ==================== KPI 指标区 ==================== -->
    <section class="kpi-grid">
      <KpiCard
        label="请求总量" label-en="Total Requests"
        :value="store.overview.totalRequests"
        accent="primary" :sparkline="eventSpark"
      />
      <KpiCard
        label="威胁事件" label-en="Threat Events"
        :value="store.overview.totalEvents"
        accent="medium" :sparkline="eventSpark"
      />
      <KpiCard
        label="已拦截" label-en="Blocked"
        :value="store.overview.blockedCount"
        accent="safe" :sparkline="blockedSpark"
      />
      <KpiCard
        label="严重威胁" label-en="Critical"
        :value="store.overview.criticalCount"
        accent="critical" :sparkline="blockedSpark"
      />
      <KpiCard
        label="平均检测耗时" label-en="Avg Latency"
        :value="store.overview.avgDetectionMillis" :decimals="2" suffix="ms"
        accent="info"
      />

      <!-- 防护态势仪表 -->
      <div class="panel gauge-panel">
        <div class="gauge-panel__inner">
          <ThreatGauge
            :value="store.overview.interceptRate"
            :color="store.policy.mode === 'OFF' ? '#9AA3B0' : '#059669'"
            label="拦截率" :sublabel="modeLabel"
          />
          <div class="gauge-panel__meta">
            <div class="gauge-panel__row">
              <span class="gauge-panel__key">防护状态</span>
              <span class="badge" :class="`badge--${modeClass}`">{{ modeLabel }}</span>
            </div>
            <div class="gauge-panel__row">
              <span class="gauge-panel__key">威胁水位</span>
              <span class="gauge-panel__val mono-num" :style="{ color: store.threatColor }">
                {{ store.overview.threatLevel }} · {{ store.overview.threatLevelLabel }}
              </span>
            </div>
            <div class="gauge-panel__row">
              <span class="gauge-panel__key">已确认基线</span>
              <span class="gauge-panel__val mono-num">
                {{ store.overview.baselineConfirmed }} / {{ store.overview.baselineTotal }}
              </span>
            </div>
            <div class="gauge-panel__row">
              <span class="gauge-panel__key">近一小时</span>
              <span class="gauge-panel__val mono-num">
                {{ store.overview.recentHourEvents }} 起事件
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== 时序 + 实时流 ==================== -->
    <section class="mid-grid">
      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">攻击态势时序</span>
            <span class="panel__subtitle">Attack Timeline</span>
          </div>
          <span class="panel__hint">最近 30 分钟</span>
        </div>
        <div class="panel__body">
          <BaseChart :option="timelineOption" height="286px" />
        </div>
      </div>

      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">实时威胁流</span>
            <span class="panel__subtitle">Live Stream</span>
          </div>
          <div class="flex-center" style="gap:6px">
            <span class="status-dot" :class="store.connected ? 'status-dot--live' : 'status-dot--idle'" />
            <span class="panel__hint">{{ store.liveEvents.length }} 条</span>
          </div>
        </div>
        <div class="panel__body panel__body--flush">
          <ThreatStream :events="store.liveEvents" max-height="286px" />
        </div>
      </div>
    </section>

    <!-- ==================== 分布 + 排行 ==================== -->
    <section class="bottom-grid">
      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">威胁类型分布</span>
            <span class="panel__subtitle">Threat Types</span>
          </div>
        </div>
        <div class="panel__body">
          <BaseChart v-if="store.threatDistribution.length"
                     :option="distributionOption" height="210px" />
          <div v-else class="empty-state" style="padding:32px 16px">
            <div class="empty-state__icon">◔</div>
            <div class="empty-state__title">暂无数据</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">攻击源排行</span>
            <span class="panel__subtitle">Top Attackers</span>
          </div>
        </div>
        <div class="panel__body">
          <BaseChart v-if="store.topAttackers.length"
                     :option="attackerOption" height="210px" />
          <div v-else class="empty-state" style="padding:32px 16px">
            <div class="empty-state__icon">◔</div>
            <div class="empty-state__title">暂无数据</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">受攻击接口</span>
            <span class="panel__subtitle">Top Endpoints</span>
          </div>
        </div>
        <div class="panel__body panel__body--flush">
          <div v-if="store.topEndpoints.length" class="endpoint-list">
            <div v-for="(item, index) in store.topEndpoints" :key="item.endpoint"
                 class="endpoint-item">
              <span class="endpoint-item__rank mono-num">{{ index + 1 }}</span>
              <span class="endpoint-item__path mono-num">{{ item.endpoint }}</span>
              <span class="endpoint-item__count mono-num">{{ item.count }}</span>
            </div>
          </div>
          <div v-else class="empty-state" style="padding:32px 16px">
            <div class="empty-state__icon">◔</div>
            <div class="empty-state__title">暂无数据</div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.overview {
  display: flex;
  flex-direction: column;
  gap: $sp-5;
}

.alert-banner {
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-3 $sp-5;
  background: $critical-bg;
  border: 1px solid $critical-border;
  border-radius: $r-md;
  animation: banner-in $dur-slow $ease-out;

  &__icon {
    font-size: 18px;
    color: $critical;
    flex-shrink: 0;
  }

  &__text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    font-size: $fs-small;
    b { color: $critical; font-weight: $fw-semibold; }
    span { color: $text-secondary; font-size: $fs-caption; }
  }
}

@keyframes banner-in {
  from { opacity: 0; transform: translateY(-8px); }
  to   { opacity: 1; transform: translateY(0); }
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr) 1.55fr;
  gap: $sp-4;
}

.gauge-panel {
  &__inner {
    display: flex;
    align-items: center;
    gap: $sp-4;
    padding: $sp-3 $sp-4;
    height: 100%;
  }

  &__meta {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: $sp-2;
  }

  &__row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: $sp-2;
  }

  &__key {
    font-size: $fs-micro;
    color: $text-tertiary;
    white-space: nowrap;
  }

  &__val {
    font-size: $fs-caption;
    font-weight: $fw-semibold;
    color: $text-secondary;
    white-space: nowrap;
  }
}

.mid-grid {
  display: grid;
  grid-template-columns: 1.65fr 1fr;
  gap: $sp-4;
}

.bottom-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: $sp-4;
  // 拉伸各卡片至等高，避免内容长度不同造成的参差
  align-items: stretch;

  > .panel {
    display: flex;
    flex-direction: column;
  }

  .panel__body {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
}

.panel__hint {
  font-size: $fs-micro;
  color: $text-tertiary;
}

.endpoint-list {
  display: flex;
  flex-direction: column;
  height: 210px;
  overflow-y: auto;
}

.endpoint-item {
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-2 $sp-5;
  border-bottom: 1px solid $border-subtle;
  transition: background $dur-instant;

  &:hover { background: $bg-hover; }
  &:last-child { border-bottom: none; }

  &__rank {
    width: 18px;
    font-size: $fs-micro;
    color: $text-tertiary;
    flex-shrink: 0;
  }

  &__path {
    flex: 1;
    min-width: 0;
    font-size: $fs-micro;
    color: $text-secondary;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  &__count {
    font-size: $fs-caption;
    font-weight: $fw-semibold;
    color: $primary-600;
    flex-shrink: 0;
  }
}

// ---------- 响应式 ----------
@media (max-width: 1600px) {
  .kpi-grid { grid-template-columns: repeat(3, 1fr) 1.4fr; }
}
@media (max-width: 1280px) {
  .kpi-grid   { grid-template-columns: repeat(2, 1fr); }
  .mid-grid   { grid-template-columns: 1fr; }
  .bottom-grid { grid-template-columns: 1fr; }
  .gauge-panel { grid-column: span 2; }
}
</style>
