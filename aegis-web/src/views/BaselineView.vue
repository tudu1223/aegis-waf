<script setup>
import { ref, computed, onMounted } from 'vue'
import * as api from '@/api'
import { useSituationStore } from '@/stores/situation'
import AstGraph from '@/components/AstGraph.vue'

/**
 * SQL 基线管理页。
 *
 * 基线是结构差分检测的参照系。学习到的基线默认为待审核状态，
 * 需人工确认后才参与检测判定——这是为了防止学习期内混入的
 * 攻击流量污染基线，导致同类攻击被误认为合法结构。
 */
const store = useSituationStore()

const baselines = ref([])
const loading = ref(false)
const selected = ref(null)
const newEndpoint = ref('')
const newSql = ref('')
const adding = ref(false)

async function load() {
  loading.value = true
  try {
    const result = await api.fetchBaselines()
    baselines.value = result?.data || []
    if (!selected.value && baselines.value.length) {
      selected.value = baselines.value[0]
    }
  } finally {
    loading.value = false
  }
}

async function toggleLearning() {
  await store.changeLearningMode(!store.policy.learningMode)
}

async function confirmOne(item) {
  await api.confirmBaseline(item.id)
  await load()
}

async function disableOne(item) {
  await api.disableBaseline(item.id)
  await load()
}

async function removeOne(item) {
  if (!confirm(`确定删除该基线？\n${item.endpoint}`)) return
  await api.deleteBaseline(item.id)
  if (selected.value?.id === item.id) selected.value = null
  await load()
}

async function clearAll() {
  if (!confirm('确定清空全部基线？清空后系统将退回冷启动状态，仅依赖风险特征判定。')) return
  await api.clearBaselines()
  selected.value = null
  await load()
}

async function addBaseline() {
  if (!newEndpoint.value.trim() || !newSql.value.trim()) return
  adding.value = true
  try {
    await api.addBaseline(newEndpoint.value.trim(), newSql.value.trim())
    newEndpoint.value = ''
    newSql.value = ''
    await load()
  } finally {
    adding.value = false
  }
}

onMounted(load)

const statusMeta = {
  CONFIRMED: { cls: 'safe', label: '已确认' },
  LEARNING: { cls: 'medium', label: '待审核' },
  DISABLED: { cls: 'neutral', label: '已禁用' }
}

const stats = computed(() => ({
  total: baselines.value.length,
  confirmed: baselines.value.filter((b) => b.status === 'CONFIRMED').length,
  learning: baselines.value.filter((b) => b.status === 'LEARNING').length
}))

/** 选中基线的 AST 结构，用于右侧可视化。 */
const selectedTree = computed(() => {
  const ast = selected.value?.ast
  return ast && ast.id ? ast : null
})

function formatTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('zh-CN', { hour12: false })
}
</script>

<template>
  <div class="baseline">
    <!-- 说明与控制 -->
    <div class="panel intro-bar">
      <div class="intro-bar__text">
        <b>基线是结构差分检测的参照系。</b>
        开启学习模式后，系统会记录各接口实际执行的 SQL 结构指纹；
        经人工审核确认后，这些结构将作为合法基准，任何偏离都会被判定为异常。
      </div>
      <div class="intro-bar__actions">
        <div class="learn-switch">
          <span class="learn-switch__label">学习模式</span>
          <button class="toggle" :class="{ 'is-on': store.policy.learningMode }"
                  @click="toggleLearning">
            <span class="toggle__thumb" />
          </button>
        </div>
        <button class="btn btn--ghost btn--sm" @click="clearAll">清空基线</button>
      </div>
    </div>

    <!-- 统计 -->
    <div class="stat-row">
      <div class="stat-chip">
        <span class="stat-chip__key">基线总数</span>
        <span class="stat-chip__val mono-num">{{ stats.total }}</span>
      </div>
      <div class="stat-chip is-safe">
        <span class="stat-chip__key">已确认</span>
        <span class="stat-chip__val mono-num">{{ stats.confirmed }}</span>
      </div>
      <div class="stat-chip is-medium">
        <span class="stat-chip__key">待审核</span>
        <span class="stat-chip__val mono-num">{{ stats.learning }}</span>
      </div>
    </div>

    <div class="baseline-grid">
      <!-- 基线列表 -->
      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">基线清单</span>
            <span class="panel__subtitle">Baseline List</span>
          </div>
        </div>

        <div class="panel__body panel__body--flush">
          <div v-if="loading" style="padding:16px">
            <div v-for="i in 4" :key="i" class="skeleton"
                 style="height:48px;margin-bottom:8px" />
          </div>

          <div v-else-if="baselines.length" class="baseline-list">
            <div v-for="item in baselines" :key="item.id"
                 class="baseline-item"
                 :class="{ 'is-selected': selected?.id === item.id }"
                 @click="selected = item">
              <div class="baseline-item__main">
                <div class="baseline-item__head">
                  <span class="badge"
                        :class="`badge--${(statusMeta[item.status] || {}).cls || 'neutral'}`">
                    {{ (statusMeta[item.status] || {}).label || item.status }}
                  </span>
                  <span class="baseline-item__endpoint mono-num">{{ item.endpoint }}</span>
                </div>
                <div class="baseline-item__sql mono-num">{{ item.sampleSql }}</div>
                <div class="baseline-item__meta mono-num">
                  指纹 {{ String(item.fingerprint).slice(0, 16) }} ·
                  命中 {{ item.hitCount || 0 }} 次 ·
                  {{ formatTime(item.lastSeen) }}
                </div>
              </div>
              <div class="baseline-item__actions" @click.stop>
                <button v-if="item.status !== 'CONFIRMED'"
                        class="btn btn--secondary btn--sm" @click="confirmOne(item)">
                  确认
                </button>
                <button v-else class="btn btn--ghost btn--sm" @click="disableOne(item)">
                  禁用
                </button>
                <button class="btn btn--ghost btn--sm" @click="removeOne(item)">删除</button>
              </div>
            </div>
          </div>

          <div v-else class="empty-state">
            <div class="empty-state__icon">⊞</div>
            <div class="empty-state__title">暂无基线</div>
            <div class="empty-state__desc">
              开启学习模式并访问业务接口，系统将自动学习合法的 SQL 结构。
              也可在下方手工添加。
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧：结构预览 + 手工添加 -->
      <div class="side">
        <div class="panel">
          <div class="panel__header">
            <div class="panel__title-group">
              <span class="panel__accent" />
              <span class="panel__title">结构预览</span>
              <span class="panel__subtitle">AST Preview</span>
            </div>
          </div>
          <div class="panel__body">
            <AstGraph v-if="selectedTree" :tree="selectedTree" height="300px"
                      :animate="false" />
            <div v-else class="empty-state" style="padding:44px 16px">
              <div class="empty-state__title">选择一条基线查看其语法树结构</div>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel__header">
            <div class="panel__title-group">
              <span class="panel__accent" />
              <span class="panel__title">手工添加基线</span>
              <span class="panel__subtitle">Add Baseline</span>
            </div>
          </div>
          <div class="panel__body">
            <div class="form-field">
              <label class="form-field__label">接口标识</label>
              <input v-model="newEndpoint" class="input-full"
                     placeholder="例如 GET:/api/notes/search" />
            </div>
            <div class="form-field">
              <label class="form-field__label">合法 SQL 样本</label>
              <textarea v-model="newSql" class="textarea" rows="4"
                        placeholder="SELECT id, title FROM notes WHERE owner_id = 1" />
            </div>
            <button class="btn btn--primary" style="width:100%"
                    :disabled="adding || !newEndpoint || !newSql"
                    @click="addBaseline">
              {{ adding ? '添加中…' : '添加并确认' }}
            </button>
            <div class="form-hint">
              手工添加的基线默认为已确认状态，将立即参与检测判定。
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.baseline {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

.intro-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: $sp-5;
  padding: $sp-4 $sp-5;
  flex-wrap: wrap;

  &__text {
    flex: 1;
    min-width: 280px;
    font-size: $fs-caption;
    line-height: 1.65;
    color: $text-secondary;
    b { color: $text-primary; font-weight: $fw-semibold; }
  }

  &__actions {
    display: flex;
    align-items: center;
    gap: $sp-4;
  }
}

.learn-switch {
  display: flex;
  align-items: center;
  gap: $sp-2;

  &__label {
    font-size: $fs-micro;
    color: $text-tertiary;
    white-space: nowrap;
  }
}

.toggle {
  position: relative;
  width: 42px;
  height: 23px;
  border-radius: $r-full;
  background: $border-strong;
  transition: background $dur-normal $ease-out;

  &.is-on {
    background: $primary-500;
    .toggle__thumb { transform: translateX(19px); }
  }

  &__thumb {
    position: absolute;
    top: 2.5px;
    left: 2.5px;
    width: 18px;
    height: 18px;
    border-radius: $r-full;
    background: #fff;
    box-shadow: $shadow-xs;
    transition: transform $dur-normal $ease-spring;
  }
}

.stat-row {
  display: flex;
  gap: $sp-3;
}

.stat-chip {
  display: flex;
  align-items: center;
  gap: $sp-2;
  padding: $sp-2 $sp-4;
  background: $bg-surface;
  border: 1px solid $border-subtle;
  border-radius: $r-md;
  box-shadow: $shadow-xs;

  &__key { font-size: $fs-micro; color: $text-tertiary; }
  &__val {
    font-size: $fs-h3;
    font-weight: $fw-semibold;
    color: $text-primary;
  }

  &.is-safe   .stat-chip__val { color: $safe; }
  &.is-medium .stat-chip__val { color: $medium; }
}

.baseline-grid {
  display: grid;
  grid-template-columns: 1fr 420px;
  gap: $sp-4;
  align-items: start;
}

.side {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

.baseline-list {
  max-height: 620px;
  overflow-y: auto;
}

.baseline-item {
  display: flex;
  align-items: flex-start;
  gap: $sp-3;
  padding: $sp-3 $sp-5;
  border-bottom: 1px solid $border-subtle;
  border-left: 3px solid transparent;
  cursor: pointer;
  transition: all $dur-fast $ease-out;

  &:last-child { border-bottom: none; }
  &:hover { background: $bg-hover; }

  &.is-selected {
    background: $primary-50;
    border-left-color: $primary-500;
  }

  &__main { flex: 1; min-width: 0; }

  &__head {
    display: flex;
    align-items: center;
    gap: $sp-2;
    margin-bottom: 3px;
  }

  &__endpoint {
    font-size: $fs-caption;
    font-weight: $fw-medium;
    color: $text-primary;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  &__sql {
    font-size: 11px;
    color: $text-secondary;
    line-height: 1.5;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    margin-bottom: 3px;
  }

  &__meta {
    font-size: 10px;
    color: $text-tertiary;
  }

  &__actions {
    display: flex;
    gap: $sp-1;
    flex-shrink: 0;
  }
}

.form-field {
  margin-bottom: $sp-3;

  &__label {
    display: block;
    font-size: $fs-micro;
    font-weight: $fw-medium;
    color: $text-secondary;
    margin-bottom: $sp-1;
  }
}

.input-full,
.textarea {
  width: 100%;
  padding: $sp-2 $sp-3;
  font-family: $font-mono;
  font-size: $fs-caption;
  color: $text-primary;
  background: $bg-surface;
  border: 1px solid $border-default;
  border-radius: $r-sm;
  outline: none;
  transition: all $dur-fast $ease-out;
  resize: vertical;

  &:focus {
    border-color: $primary-400;
    box-shadow: 0 0 0 3px $primary-glow;
  }
}

.form-hint {
  margin-top: $sp-2;
  font-size: 10.5px;
  color: $text-tertiary;
  line-height: 1.55;
}

@media (max-width: 1400px) {
  .baseline-grid { grid-template-columns: 1fr; }
}
</style>
