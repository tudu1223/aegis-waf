<script setup>
import { onMounted, onUnmounted, computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useSituationStore } from '@/stores/situation'

const route = useRoute()
const router = useRouter()
const store = useSituationStore()

const collapsed = ref(false)

/** 导航项直接从路由表派生，避免菜单与路由不同步。 */
const navItems = computed(() =>
  router.getRoutes()
    .filter((r) => r.meta?.title && r.name !== 'analysis')
    .map((r) => ({
      name: r.name,
      path: r.path,
      title: r.meta.title,
      subtitle: r.meta.subtitle,
      icon: r.meta.icon
    }))
)

const currentTitle = computed(() => route.meta?.title || 'AEGIS')
const currentSubtitle = computed(() => route.meta?.subtitle || '')

const modes = [
  { value: 'OFF', label: '关闭', cls: 'is-off', hint: '不做任何防护，用于演示漏洞真实危害' },
  { value: 'MONITOR', label: '监控', cls: 'is-monitor', hint: '检出并记录，但不阻断请求' },
  { value: 'BLOCK', label: '拦截', cls: 'is-block', hint: '检出即阻断，完整防护' }
]

async function switchMode(mode) {
  if (store.policy.mode === mode) return
  await store.changeMode(mode)
}

let refreshTimer = null

onMounted(async () => {
  await store.loadAll()
  await store.loadRecentEvents()
  store.connect()
  // WebSocket 之外的兜底轮询，保证连接异常时数据仍会更新
  refreshTimer = setInterval(() => store.loadAll(), 12000)
})

onUnmounted(() => {
  store.disconnect()
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<template>
  <div class="app-canvas app-shell" :class="{ 'is-collapsed': collapsed }">
    <!-- ==================== 侧栏 ==================== -->
    <aside class="sidebar">
      <div class="sidebar__brand">
        <div class="brand-mark">
          <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M16 2L4 7v9c0 7.2 5.1 13.9 12 15.5C22.9 29.9 28 23.2 28 16V7L16 2z"
                  fill="url(#shield)" />
            <path d="M11 16.2l3.4 3.4L21.5 12.5" stroke="#fff" stroke-width="2.4"
                  stroke-linecap="round" stroke-linejoin="round" />
            <defs>
              <linearGradient id="shield" x1="4" y1="2" x2="28" y2="31" gradientUnits="userSpaceOnUse">
                <stop stop-color="#3B82F6" />
                <stop offset="1" stop-color="#6366F1" />
              </linearGradient>
            </defs>
          </svg>
        </div>
        <div class="brand-text" v-show="!collapsed">
          <div class="brand-text__name">AEGIS</div>
          <div class="brand-text__desc">语义化攻击检测</div>
        </div>
      </div>

      <nav class="sidebar__nav">
        <RouterLink
          v-for="item in navItems"
          :key="item.name"
          :to="item.path"
          class="nav-item"
          :class="{ 'is-active': route.name === item.name }"
        >
          <span class="nav-item__indicator" />
          <span class="nav-item__icon">{{ item.icon }}</span>
          <span class="nav-item__label" v-show="!collapsed">
            <span class="nav-item__title">{{ item.title }}</span>
            <span class="nav-item__subtitle">{{ item.subtitle }}</span>
          </span>
        </RouterLink>
      </nav>

      <div class="sidebar__footer">
        <button class="collapse-btn" @click="collapsed = !collapsed"
                :title="collapsed ? '展开侧栏' : '收起侧栏'">
          <span :class="{ 'is-flipped': collapsed }">‹</span>
        </button>
      </div>
    </aside>

    <!-- ==================== 主区 ==================== -->
    <div class="main">
      <header class="topbar">
        <div class="topbar__left">
          <h1 class="topbar__title">{{ currentTitle }}</h1>
          <span class="topbar__subtitle">{{ currentSubtitle }}</span>
        </div>

        <div class="topbar__right">
          <!-- 防护模式切换：演示流程的核心开关 -->
          <div class="mode-switch">
            <span class="mode-switch__label">防护模式</span>
            <div class="segmented">
              <button
                v-for="m in modes"
                :key="m.value"
                class="segmented__item"
                :class="[{ 'is-active': store.policy.mode === m.value }, m.cls]"
                :title="m.hint"
                @click="switchMode(m.value)"
              >{{ m.label }}</button>
            </div>
          </div>

          <div class="conn-status" :title="store.connected ? '实时通道已连接' : '实时通道断开，正在重连'">
            <span class="status-dot" :class="store.connected ? 'status-dot--live' : 'status-dot--idle'" />
            <span class="conn-status__text">{{ store.connected ? '实时' : '离线' }}</span>
          </div>
        </div>
      </header>

      <main class="content">
        <RouterView v-slot="{ Component }">
          <Transition name="page" mode="out-in">
            <component :is="Component" />
          </Transition>
        </RouterView>
      </main>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.app-shell {
  display: flex;
  min-height: 100vh;
}

// ==================== 侧栏 ====================
.sidebar {
  position: relative;
  z-index: 10;
  display: flex;
  flex-direction: column;
  width: $sidebar-width;
  flex-shrink: 0;
  background: rgba(255, 255, 255, 0.86);
  backdrop-filter: blur(16px) saturate(1.4);
  border-right: 1px solid $border-subtle;
  transition: width $dur-normal $ease-out;

  .is-collapsed & { width: $sidebar-width-collapsed; }

  &__brand {
    display: flex;
    align-items: center;
    gap: $sp-3;
    height: $topbar-height;
    padding: 0 $sp-4;
    border-bottom: 1px solid $border-subtle;
    overflow: hidden;
  }

  &__nav {
    flex: 1;
    padding: $sp-4 $sp-3;
    display: flex;
    flex-direction: column;
    gap: 2px;
    overflow-y: auto;
  }

  &__footer {
    padding: $sp-3;
    border-top: 1px solid $border-subtle;
    display: flex;
    justify-content: flex-end;
  }
}

.brand-mark {
  width: 32px;
  height: 32px;
  flex-shrink: 0;
  svg { width: 100%; height: 100%; display: block; }
}

.brand-text {
  min-width: 0;
  &__name {
    font-size: 17px;
    font-weight: $fw-bold;
    letter-spacing: 0.08em;
    color: $text-primary;
    line-height: 1.2;
  }
  &__desc {
    font-size: $fs-micro;
    color: $text-tertiary;
    white-space: nowrap;
  }
}

.nav-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding: $sp-2 $sp-3;
  border-radius: $r-md;
  color: $text-secondary;
  transition: all $dur-fast $ease-out;
  overflow: hidden;

  &:hover:not(.is-active) {
    background: $bg-hover;
    color: $text-primary;
  }

  &.is-active {
    background: $primary-50;
    color: $primary-600;
    .nav-item__indicator { transform: scaleY(1); }
    .nav-item__icon { color: $primary-600; }
  }

  // 左侧激活指示条：从中心展开的动效
  &__indicator {
    position: absolute;
    left: 0;
    top: 50%;
    width: 3px;
    height: 20px;
    margin-top: -10px;
    border-radius: 0 $r-full $r-full 0;
    background: $grad-primary;
    transform: scaleY(0);
    transform-origin: center;
    transition: transform $dur-normal $ease-spring;
  }

  &__icon {
    width: 22px;
    text-align: center;
    font-size: 15px;
    color: $text-tertiary;
    flex-shrink: 0;
    transition: color $dur-fast;
  }

  &__label {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.25;
  }

  &__title {
    font-size: $fs-small;
    font-weight: $fw-medium;
    white-space: nowrap;
  }

  &__subtitle {
    font-size: 9px;
    letter-spacing: 0.08em;
    color: $text-tertiary;
    white-space: nowrap;
  }
}

.collapse-btn {
  width: 28px;
  height: 28px;
  border-radius: $r-sm;
  color: $text-tertiary;
  font-size: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all $dur-fast $ease-out;

  &:hover { background: $bg-hover; color: $text-primary; }

  span {
    display: block;
    transition: transform $dur-normal $ease-spring;
    &.is-flipped { transform: rotate(180deg); }
  }
}

// ==================== 主区 ====================
.main {
  position: relative;
  z-index: 1;
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: $sp-4;
  height: $topbar-height;
  padding: 0 $sp-6;
  background: rgba(255, 255, 255, 0.78);
  backdrop-filter: blur(16px) saturate(1.4);
  border-bottom: 1px solid $border-subtle;
  position: sticky;
  top: 0;
  z-index: 20;

  &__left {
    display: flex;
    align-items: baseline;
    gap: $sp-3;
    min-width: 0;
  }

  &__title {
    font-size: $fs-h2;
    font-weight: $fw-semibold;
    letter-spacing: -0.02em;
  }

  &__subtitle {
    font-size: $fs-micro;
    font-weight: $fw-medium;
    color: $text-tertiary;
    letter-spacing: 0.12em;
  }

  &__right {
    display: flex;
    align-items: center;
    gap: $sp-5;
  }
}

.mode-switch {
  display: flex;
  align-items: center;
  gap: $sp-3;

  &__label {
    font-size: $fs-micro;
    font-weight: $fw-medium;
    color: $text-tertiary;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }
}

.conn-status {
  display: flex;
  align-items: center;
  gap: $sp-2;
  padding: $sp-1 $sp-3;
  border-radius: $r-full;
  background: $bg-subtle;
  border: 1px solid $border-subtle;

  &__text {
    font-size: $fs-micro;
    font-weight: $fw-medium;
    color: $text-secondary;
  }
}

.content {
  flex: 1;
  padding: $sp-6;
  max-width: $content-max-width;
  width: 100%;
  margin: 0 auto;
}

@media (max-width: 1280px) {
  .content { padding: $sp-4; }
}
</style>
