<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import G6 from '@antv/g6'

/**
 * AST 语法树可视化。
 *
 * 这是整个系统技术展示的核心：将 SQL 的抽象语法树渲染为可视图形，
 * 并将结构差分中判定为"注入"的节点高亮标注。
 *
 * 视觉设计要点：
 *   - 正常节点使用中性冷色，注入节点使用警示红并带脉冲光晕
 *   - 注入子树以"生长"动画出现，形成视觉焦点
 *   - 布局采用从左至右的紧凑树，适配宽屏
 */
const props = defineProps({
  /** 后端导出的可视化树数据 */
  tree: { type: Object, default: null },
  height: { type: String, default: '460px' },
  /** 是否播放注入子树的生长动画 */
  animate: { type: Boolean, default: true }
})

const container = ref(null)
let graph = null
let animationTimers = []

/** 节点配色：正常态偏冷静，注入态强烈但不刺目。 */
const STYLE = {
  normal: {
    fill: '#F0F6FF',
    stroke: '#93C5FD',
    text: '#1E40AF'
  },
  injected: {
    fill: '#FFF1F2',
    stroke: '#F43F5E',
    text: '#9F1239'
  },
  root: {
    fill: '#EEF2FF',
    stroke: '#6d5dfc',
    text: '#3730A3'
  }
}

/** 将后端树结构转换为 G6 所需的数据格式。 */
function toG6Data(node) {
  if (!node || !node.id) return null
  const injected = node.status === 'injected'
  return {
    id: node.id,
    label: truncateLabel(node.label || node.type || '?'),
    rawLabel: node.label,
    nodeType: node.type,
    injected,
    kind: node.kind,
    inlineComment: node.inlineComment,
    children: (node.children || []).map(toG6Data).filter(Boolean)
  }
}

function truncateLabel(text) {
  const s = String(text)
  return s.length > 22 ? s.slice(0, 22) + '…' : s
}

/** 注册自定义节点：圆角矩形 + 可选的脉冲光晕。 */
function registerNode() {
  if (G6.__aegisNodeRegistered) return
  G6.registerNode('aegis-ast-node', {
    draw(cfg, group) {
      const injected = cfg.injected
      const isRoot = cfg.nodeType === 'SELECT_STATEMENT'
        || cfg.nodeType === 'STATEMENT_LIST'
      const style = injected ? STYLE.injected : (isRoot ? STYLE.root : STYLE.normal)

      const label = cfg.label || ''
      const width = Math.max(74, label.length * 8.2 + 26)
      const height = 32

      // 注入节点的外发光：先绘制底层模糊矩形营造光晕
      if (injected) {
        group.addShape('rect', {
          attrs: {
            x: -4, y: -4,
            width: width + 8, height: height + 8,
            radius: 10,
            fill: '#F43F5E',
            opacity: 0.16
          },
          name: 'glow-shape'
        })
      }

      const keyShape = group.addShape('rect', {
        attrs: {
          x: 0, y: 0, width, height,
          radius: 7,
          fill: style.fill,
          stroke: style.stroke,
          lineWidth: injected ? 1.6 : 1.1,
          shadowColor: injected ? 'rgba(244,63,94,0.22)' : 'rgba(15,23,42,0.05)',
          shadowBlur: injected ? 10 : 4,
          shadowOffsetY: 1,
          cursor: 'pointer'
        },
        name: 'node-rect',
        draggable: true
      })

      group.addShape('text', {
        attrs: {
          x: width / 2, y: height / 2,
          text: label,
          fontSize: 11.5,
          fontFamily: 'JetBrains Mono, SF Mono, Consolas, monospace',
          fontWeight: injected ? 600 : 500,
          fill: style.text,
          textAlign: 'center',
          textBaseline: 'middle',
          cursor: 'pointer'
        },
        name: 'node-text',
        draggable: true
      })

      // 注入节点右上角的警示标记
      if (injected) {
        group.addShape('circle', {
          attrs: {
            x: width - 3, y: 3, r: 4.5,
            fill: '#E11D48',
            stroke: '#fff',
            lineWidth: 1.4
          },
          name: 'alert-dot'
        })
      }

      return keyShape
    },

    /** 注入节点的呼吸脉冲，是大屏上最醒目的动效。 */
    afterDraw(cfg, group) {
      if (!cfg.injected) return
      const glow = group.find((el) => el.get('name') === 'glow-shape')
      if (!glow) return
      glow.animate(
        (ratio) => {
          const opacity = 0.10 + 0.18 * Math.sin(ratio * Math.PI)
          const spread = 4 + 3 * Math.sin(ratio * Math.PI)
          return {
            opacity,
            x: -spread,
            y: -spread,
            width: glow.attr('width'),
            height: glow.attr('height')
          }
        },
        { repeat: true, duration: 1800, easing: 'easeCubic' }
      )
    }
  })
  G6.__aegisNodeRegistered = true
}

function destroyGraph() {
  animationTimers.forEach(clearTimeout)
  animationTimers = []
  if (graph) {
    graph.destroy()
    graph = null
  }
}

function render() {
  destroyGraph()
  if (!container.value || !props.tree) return

  const data = toG6Data(props.tree)
  if (!data) return

  registerNode()

  // 容器尺寸必须在图初始化前确定，否则 fitView 会基于错误的
  // 画布尺寸计算缩放比例，导致节点溢出可视区域
  const rect = container.value.getBoundingClientRect()
  const width = Math.max(320, Math.round(rect.width))
  const height = Math.max(240, Math.round(rect.height))

  graph = new G6.TreeGraph({
    container: container.value,
    width,
    height,
    // 关闭初始 fitView，改为渲染完成后手动执行，
    // 保证此时布局已完成、节点包围盒已确定
    fitView: false,
    animate: props.animate,
    animateCfg: { duration: 420, easing: 'easeCubic' },
    modes: {
      default: ['drag-canvas', 'zoom-canvas', 'collapse-expand']
    },
    defaultNode: {
      type: 'aegis-ast-node',
      anchorPoints: [[0, 0.5], [1, 0.5]]
    },
    defaultEdge: {
      type: 'cubic-horizontal',
      style: {
        stroke: '#B8BEC9',
        lineWidth: 1.1,
        endArrow: {
          path: G6.Arrow.triangle(4, 5, 0),
          fill: '#B8BEC9',
          d: 0
        }
      }
    },
    layout: {
      type: 'compactBox',
      direction: 'LR',
      getId: (d) => d.id,
      getHeight: () => 32,
      getWidth: (d) => Math.max(74, String(d.label || '').length * 8.2 + 26),
      getVGap: () => 10,
      getHGap: () => 40
    }
  })

  // 通向注入节点的连线同步标红，形成完整的"攻击路径"视觉
  graph.edge((edge) => {
    const target = graph.findById(edge.target)
    const injected = target?.getModel?.().injected
    return {
      style: {
        stroke: injected ? '#FB7185' : '#B8BEC9',
        lineWidth: injected ? 1.8 : 1.1,
        endArrow: {
          path: G6.Arrow.triangle(4, 5, 0),
          fill: injected ? '#FB7185' : '#B8BEC9',
          d: 0
        }
      }
    }
  })

  graph.data(data)
  graph.render()

  // 布局完成后再适配视图。使用较大的内边距保证节点不贴边，
  // 并限制缩放上下限：过大会使少量节点占满画布显得空洞，
  // 过小则文字不可读。
  requestAnimationFrame(() => {
    if (!graph || graph.destroyed) return
    graph.fitView([32, 56, 32, 56])
    const zoom = graph.getZoom()
    const center = {
      x: graph.get('width') / 2,
      y: graph.get('height') / 2
    }
    if (zoom > 1.05) {
      graph.zoomTo(1.05, center)
    } else if (zoom < 0.32) {
      // 树过大时保底缩放，配合滚轮与拖拽供用户细看
      graph.zoomTo(0.32, center)
    }
  })

  // 节点悬停时显示完整标签（长文本被截断的情况）
  graph.on('node:mouseenter', (evt) => {
    const model = evt.item.getModel()
    if (model.rawLabel && model.rawLabel !== model.label) {
      container.value.setAttribute('title', model.rawLabel)
    }
  })
  graph.on('node:mouseleave', () => {
    container.value?.removeAttribute('title')
  })
}

/** 容器尺寸变化时同步调整画布。 */
let observer = null
let resizeTimer = null

onMounted(async () => {
  await nextTick()
  render()
  observer = new ResizeObserver(() => {
    // 防抖：侧栏折叠等连续变化会高频触发，避免重复重排
    if (resizeTimer) clearTimeout(resizeTimer)
    resizeTimer = setTimeout(() => {
      if (!graph || graph.destroyed || !container.value) return
      const rect = container.value.getBoundingClientRect()
      if (rect.width < 40 || rect.height < 40) return
      graph.changeSize(Math.round(rect.width), Math.round(rect.height))
      graph.fitView([32, 56, 32, 56])
      const center = {
        x: graph.get('width') / 2,
        y: graph.get('height') / 2
      }
      if (graph.getZoom() > 1.05) {
        graph.zoomTo(1.05, center)
      }
    }, 160)
  })
  if (container.value) observer.observe(container.value)
})

watch(() => props.tree, async () => {
  await nextTick()
  render()
}, { deep: true })

onUnmounted(() => {
  if (resizeTimer) clearTimeout(resizeTimer)
  observer?.disconnect()
  destroyGraph()
})

defineExpose({
  refit: () => graph?.fitView([24, 40, 24, 40])
})
</script>

<template>
  <div class="ast-graph" :style="{ height }">
    <div ref="container" class="ast-graph__canvas" />

    <!-- 图例 -->
    <div class="ast-graph__legend">
      <div class="legend-item">
        <span class="legend-dot legend-dot--normal" />
        <span>合法结构</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot legend-dot--injected" />
        <span>注入变异</span>
      </div>
      <div class="legend-hint">滚轮缩放 · 拖拽平移</div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.ast-graph {
  position: relative;
  width: 100%;
  border-radius: $r-md;
  background:
    radial-gradient(circle at 20% 20%, rgba(99,102,241,0.04) 0%, transparent 55%),
    linear-gradient(180deg, #FCFDFF 0%, #F7FAFF 100%);
  border: 1px solid $border-subtle;
  overflow: hidden;

  &__canvas {
    width: 100%;
    height: 100%;
  }

  &__legend {
    position: absolute;
    left: $sp-4;
    bottom: $sp-3;
    display: flex;
    align-items: center;
    gap: $sp-4;
    padding: $sp-2 $sp-3;
    background: rgba(224, 229, 236, 0.92);
    backdrop-filter: blur(8px);
    border: 1px solid $border-subtle;
    border-radius: $r-full;
    box-shadow: $shadow-xs;
  }
}

.legend-item {
  display: flex;
  align-items: center;
  gap: $sp-2;
  font-size: $fs-micro;
  color: $text-secondary;
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  flex-shrink: 0;

  &--normal   { background: #F0F6FF; border: 1.4px solid #93C5FD; }
  &--injected { background: #FFF1F2; border: 1.4px solid #F43F5E; }
}

.legend-hint {
  font-size: 10px;
  color: $text-tertiary;
  padding-left: $sp-3;
  border-left: 1px solid $border-default;
}
</style>
