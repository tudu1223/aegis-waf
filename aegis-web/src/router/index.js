import { createRouter, createWebHashHistory } from 'vue-router'

/**
 * 路由表。
 *
 * 使用 hash 模式，保证构建产物可直接以静态文件方式部署，
 * 无需服务端配置 history fallback。
 */
const routes = [
  { path: '/', redirect: '/overview' },
  {
    path: '/overview',
    name: 'overview',
    component: () => import('@/views/OverviewView.vue'),
    meta: { title: '态势总览', subtitle: 'SITUATION OVERVIEW', icon: '◎' }
  },
  {
    path: '/events',
    name: 'events',
    component: () => import('@/views/EventsView.vue'),
    meta: { title: '威胁事件', subtitle: 'THREAT EVENTS', icon: '◈' }
  },
  {
    path: '/analysis/:eventId?',
    name: 'analysis',
    component: () => import('@/views/AnalysisView.vue'),
    meta: { title: '语义分析', subtitle: 'AST ANALYSIS', icon: '⌘' }
  },
  {
    path: '/baseline',
    name: 'baseline',
    component: () => import('@/views/BaselineView.vue'),
    meta: { title: '基线管理', subtitle: 'SQL BASELINE', icon: '⊞' }
  },
  {
    path: '/range',
    name: 'range',
    component: () => import('@/views/RangeView.vue'),
    meta: { title: '攻防演练', subtitle: 'CYBER RANGE', icon: '◉' }
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { title: '系统设置', subtitle: 'SETTINGS', icon: '⚙' }
  }
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 })
})
