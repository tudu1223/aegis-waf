<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart, BarChart, PieChart } from 'echarts/charts'
import {
  GridComponent, TooltipComponent, LegendComponent, TitleComponent
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([
  LineChart, BarChart, PieChart,
  GridComponent, TooltipComponent, LegendComponent, TitleComponent,
  CanvasRenderer
])

/**
 * ECharts 容器组件。
 *
 * 统一封装初始化、尺寸自适应与销毁逻辑，
 * 使各图表只需关注 option 配置本身。
 */
const props = defineProps({
  option: { type: Object, required: true },
  height: { type: String, default: '260px' },
  loading: { type: Boolean, default: false }
})

const container = ref(null)
let chart = null
let observer = null

function render() {
  if (!container.value) return
  if (!chart) {
    chart = echarts.init(container.value, null, { renderer: 'canvas' })
  }
  // notMerge=false 保证数据更新时复用已有配置，动画更平滑
  chart.setOption(props.option, { notMerge: false, lazyUpdate: true })
}

watch(() => props.option, () => render(), { deep: true })

watch(() => props.loading, (v) => {
  if (!chart) return
  v ? chart.showLoading('default', {
    text: '', color: '#6d5dfc', maskColor: 'rgba(224,229,236,0.6)'
  }) : chart.hideLoading()
})

onMounted(async () => {
  await nextTick()
  render()
  // 使用 ResizeObserver 而非 window.resize，
  // 可正确响应侧栏折叠等布局变化引起的容器尺寸改变
  observer = new ResizeObserver(() => chart?.resize())
  if (container.value) observer.observe(container.value)
})

onUnmounted(() => {
  observer?.disconnect()
  chart?.dispose()
  chart = null
})
</script>

<template>
  <div ref="container" class="chart-container" :style="{ height }" />
</template>

<style scoped>
.chart-container {
  width: 100%;
}
</style>
