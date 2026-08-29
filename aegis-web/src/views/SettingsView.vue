<script setup>
import { ref, onMounted } from 'vue'
import * as api from '@/api'
import { useSituationStore } from '@/stores/situation'

/**
 * 系统设置页。
 *
 * 集中管理防护参数与靶场漏洞开关。漏洞开关用于"三轮测试法"
 * 的第三轮——验证代码层面的修复确实有效。
 */
const store = useSituationStore()

const form = ref({
  blockThreshold: 70,
  rateLimitCapacity: 100,
  rateLimitRefillPerSecond: 20,
  slidingWindowThreshold: 600
})

const saving = ref(false)
const saved = ref(false)
const vulns = ref([])
const loadingVulns = ref(false)

async function loadPolicy() {
  const result = await api.fetchPolicy()
  if (result?.data) {
    form.value = {
      blockThreshold: result.data.blockThreshold,
      rateLimitCapacity: result.data.rateLimitCapacity,
      rateLimitRefillPerSecond: result.data.rateLimitRefillPerSecond,
      slidingWindowThreshold: result.data.slidingWindowThreshold
    }
  }
}

async function savePolicy() {
  saving.value = true
  saved.value = false
  try {
    await api.updatePolicy(form.value)
    saved.value = true
    setTimeout(() => { saved.value = false }, 2600)
  } finally {
    saving.value = false
  }
}

async function loadVulns() {
  loadingVulns.value = true
  try {
    const result = await api.fetchVulnStatus()
    const map = result?.vulnerabilities || {}
    vulns.value = Object.values(map)
  } catch (e) {
    vulns.value = []
  } finally {
    loadingVulns.value = false
  }
}

async function toggleVuln(item) {
  await api.toggleVuln(item.id, !item.patched)
  await loadVulns()
}

async function toggleAll(patched) {
  await api.toggleAllVuln(patched)
  await loadVulns()
}

onMounted(async () => {
  await loadPolicy()
  await loadVulns()
})

const severityCls = (severity) => ({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
}[severity] || 'neutral')
</script>

<template>
  <div class="settings">
    <div class="settings-grid">
      <!-- 检测参数 -->
      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">检测参数</span>
            <span class="panel__subtitle">Detection Tuning</span>
          </div>
        </div>
        <div class="panel__body">
          <div class="field">
            <div class="field__head">
              <label class="field__label">拦截阈值</label>
              <span class="field__value mono-num">{{ form.blockThreshold }}</span>
            </div>
            <input type="range" min="30" max="100" step="5"
                   v-model.number="form.blockThreshold" class="slider" />
            <div class="field__hint">
              综合风险评分达到此值即判定为攻击并拦截。降低可提高检出率，
              但可能增加误报；提高则相反。
            </div>
          </div>

          <div class="field">
            <div class="field__head">
              <label class="field__label">令牌桶容量</label>
              <span class="field__value mono-num">{{ form.rateLimitCapacity }}</span>
            </div>
            <input type="range" min="10" max="500" step="10"
                   v-model.number="form.rateLimitCapacity" class="slider" />
            <div class="field__hint">
              允许的突发请求数上限。业务存在正常峰值时应适当调高。
            </div>
          </div>

          <div class="field">
            <div class="field__head">
              <label class="field__label">令牌填充速率</label>
              <span class="field__value mono-num">{{ form.rateLimitRefillPerSecond }} /秒</span>
            </div>
            <input type="range" min="1" max="200" step="1"
                   v-model.number="form.rateLimitRefillPerSecond" class="slider" />
            <div class="field__hint">
              长期平均请求速率上限，决定持续流量的承载能力。
            </div>
          </div>

          <div class="field">
            <div class="field__head">
              <label class="field__label">滑动窗口阈值</label>
              <span class="field__value mono-num">{{ form.slidingWindowThreshold }} /分钟</span>
            </div>
            <input type="range" min="60" max="3000" step="60"
                   v-model.number="form.slidingWindowThreshold" class="slider" />
            <div class="field__hint">
              60 秒窗口内允许的请求总数，用于抑制持续性的暴力破解。
            </div>
          </div>

          <div class="save-row">
            <button class="btn btn--primary" :disabled="saving" @click="savePolicy">
              {{ saving ? '保存中…' : '保存配置' }}
            </button>
            <span v-if="saved" class="save-row__ok">✓ 已生效</span>
          </div>
        </div>
      </div>

      <!-- 靶场漏洞开关 -->
      <div class="panel">
        <div class="panel__header">
          <div class="panel__title-group">
            <span class="panel__accent" />
            <span class="panel__title">靶场漏洞开关</span>
            <span class="panel__subtitle">Vulnerability Toggle</span>
          </div>
          <div class="flex-center" style="gap:6px">
            <button class="btn btn--ghost btn--sm" @click="toggleAll(false)">全部脆弱</button>
            <button class="btn btn--secondary btn--sm" @click="toggleAll(true)">全部修复</button>
          </div>
        </div>

        <div class="panel__body panel__body--flush">
          <div class="vuln-intro">
            每个漏洞均提供「脆弱实现」与「安全实现」两份代码。
            切换开关即可对比修复前后的行为差异，用于验证修复的有效性。
          </div>

          <div v-if="loadingVulns" style="padding:16px">
            <div v-for="i in 5" :key="i" class="skeleton"
                 style="height:44px;margin-bottom:8px" />
          </div>

          <div v-else class="vuln-list">
            <div v-for="item in vulns" :key="item.id" class="vuln-item">
              <div class="vuln-item__main">
                <div class="vuln-item__head">
                  <span class="vuln-item__id mono-num">{{ item.id }}</span>
                  <span class="vuln-item__name">{{ item.name }}</span>
                  <span class="badge" :class="`badge--${severityCls(item.severity)}`">
                    CVSS {{ item.cvss }}
                  </span>
                  <span class="vuln-item__owasp">{{ item.owasp }}</span>
                </div>
                <div class="vuln-item__desc">
                  <span class="vuln-item__label">脆弱：</span>{{ item.vulnerableImpl }}
                </div>
                <div class="vuln-item__desc">
                  <span class="vuln-item__label is-fix">修复：</span>{{ item.secureImpl }}
                </div>
              </div>
              <div class="vuln-item__toggle">
                <span class="vuln-item__state" :class="item.patched ? 'is-fixed' : 'is-vuln'">
                  {{ item.patched ? '已修复' : '脆弱' }}
                </span>
                <button class="toggle" :class="{ 'is-on': item.patched }"
                        @click="toggleVuln(item)">
                  <span class="toggle__thumb" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 合规声明 -->
    <div class="panel compliance">
      <div class="compliance__title">⚖ 合规与伦理声明</div>
      <div class="compliance__text">
        本项目所有攻击测试均在本地隔离环境中针对自建靶场执行，未对任何第三方系统进行未授权测试。
        靶场中的漏洞代码为教学目的主动构造，集中隔离于 <code>vuln</code> 包并全部加注警示注释，
        不会随生产构建发布。反序列化类测试用例采用无害化载荷，不包含任何具备实际破坏能力的
        gadget 链。本项目严格遵守《中华人民共和国网络安全法》《数据安全法》及相关法律法规，
        所有技术成果仅用于安全防护研究与教学实践。
      </div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
@use '@/styles/tokens' as *;

.settings {
  display: flex;
  flex-direction: column;
  gap: $sp-4;
}

.settings-grid {
  display: grid;
  grid-template-columns: 420px 1fr;
  gap: $sp-4;
  align-items: start;
}

// ---------- 参数字段 ----------
.field {
  margin-bottom: $sp-5;

  &__head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: $sp-2;
  }

  &__label {
    font-size: $fs-small;
    font-weight: $fw-medium;
    color: $text-primary;
  }

  &__value {
    font-size: $fs-small;
    font-weight: $fw-semibold;
    color: $primary-600;
  }

  &__hint {
    margin-top: $sp-2;
    font-size: 10.5px;
    line-height: 1.6;
    color: $text-tertiary;
  }
}

.slider {
  width: 100%;
  height: 5px;
  border-radius: $r-full;
  background: $bg-muted;
  outline: none;
  appearance: none;
  cursor: pointer;

  &::-webkit-slider-thumb {
    appearance: none;
    width: 17px;
    height: 17px;
    border-radius: $r-full;
    background: #fff;
    border: 2px solid $primary-500;
    box-shadow: $shadow-sm;
    cursor: pointer;
    transition: transform $dur-fast $ease-spring;
  }

  &::-webkit-slider-thumb:hover { transform: scale(1.16); }

  &::-moz-range-thumb {
    width: 17px;
    height: 17px;
    border-radius: $r-full;
    background: #fff;
    border: 2px solid $primary-500;
    box-shadow: $shadow-sm;
    cursor: pointer;
  }
}

.save-row {
  display: flex;
  align-items: center;
  gap: $sp-3;
  padding-top: $sp-2;

  &__ok {
    font-size: $fs-small;
    font-weight: $fw-medium;
    color: $safe;
    animation: fade-in $dur-normal $ease-out;
  }
}

@keyframes fade-in {
  from { opacity: 0; transform: translateX(-6px); }
  to   { opacity: 1; transform: translateX(0); }
}

// ---------- 漏洞列表 ----------
.vuln-intro {
  padding: $sp-3 $sp-5;
  font-size: $fs-caption;
  line-height: 1.65;
  color: $text-secondary;
  background: $primary-50;
  border-bottom: 1px solid $border-subtle;
}

.vuln-list {
  max-height: 560px;
  overflow-y: auto;
}

.vuln-item {
  display: flex;
  align-items: center;
  gap: $sp-4;
  padding: $sp-3 $sp-5;
  border-bottom: 1px solid $border-subtle;
  transition: background $dur-instant;

  &:last-child { border-bottom: none; }
  &:hover { background: $bg-hover; }

  &__main { flex: 1; min-width: 0; }

  &__head {
    display: flex;
    align-items: center;
    gap: $sp-2;
    margin-bottom: 4px;
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

  &__owasp {
    font-size: 10px;
    color: $text-tertiary;
  }

  &__desc {
    font-size: 11px;
    line-height: 1.55;
    color: $text-tertiary;
  }

  &__label {
    color: $critical;
    font-weight: $fw-medium;
    &.is-fix { color: $safe; }
  }

  &__toggle {
    display: flex;
    align-items: center;
    gap: $sp-2;
    flex-shrink: 0;
  }

  &__state {
    font-size: $fs-micro;
    font-weight: $fw-medium;
    width: 40px;
    text-align: right;
    &.is-fixed { color: $safe; }
    &.is-vuln  { color: $critical; }
  }
}

.toggle {
  position: relative;
  width: 40px;
  height: 22px;
  border-radius: $r-full;
  background: $critical;
  transition: background $dur-normal $ease-out;
  flex-shrink: 0;

  &.is-on {
    background: $safe;
    .toggle__thumb { transform: translateX(18px); }
  }

  &__thumb {
    position: absolute;
    top: 2.5px;
    left: 2.5px;
    width: 17px;
    height: 17px;
    border-radius: $r-full;
    background: #fff;
    box-shadow: $shadow-xs;
    transition: transform $dur-normal $ease-spring;
  }
}

// ---------- 合规声明 ----------
.compliance {
  padding: $sp-4 $sp-5;

  &__title {
    font-size: $fs-small;
    font-weight: $fw-semibold;
    color: $text-primary;
    margin-bottom: $sp-2;
  }

  &__text {
    font-size: $fs-caption;
    line-height: 1.75;
    color: $text-secondary;

    code {
      padding: 1px 5px;
      font-size: 11px;
      background: $bg-subtle;
      border: 1px solid $border-subtle;
      border-radius: $r-xs;
      color: $primary-600;
    }
  }
}

@media (max-width: 1400px) {
  .settings-grid { grid-template-columns: 1fr; }
}
</style>
