<template>
  <div class="h-full w-full mx-auto max-w-screen-2xl px-5 flex flex-col gap-5 overflow-hidden">
    <a-card title="代码仓库管理" :bordered="false" class="rounded-lg flex flex-col w-full h-full flex-shrink-0">
      <template #extra>
        <a-space>
          <a-popconfirm
            content="将删除选中的仓库及其扫描任务和漏洞记录，确认继续吗？"
            @ok="handleBatchDelete"
          >
            <a-button status="danger" :disabled="selectedRowKeys.length === 0">
              批量删除
            </a-button>
          </a-popconfirm>
          <a-button type="primary" @click="handleOpenAdd">
            <template #icon><icon-plus /></template>
            添加仓库
          </a-button>
        </a-space>
      </template>

      <div class="flex-1 overflow-hidden h-full">
        <a-table
          row-key="id"
          :columns="columns"
          :data="data"
          :row-selection="rowSelection"
          :scroll="{ x: '100%', y: '100%' }"
          size="small"
          :loading="loading"
          :pagination="pagination"
          @page-change="handlePageChange"
          class="h-full w-full"
        >
          <template #language="{ record }">
            <a-tag :color="record.language === 'go' ? 'blue' : 'green'">
              {{ record.language }}
            </a-tag>
          </template>

          <template #actions="{ record }">
            <a-space class="repo-actions" :size="10">
              <a-button type="text" size="small" @click="handleScan(record)">开始扫描</a-button>
              <a-button type="text" status="warning" size="small" @click="handleOpenEdit(record)">更新</a-button>
              <a-popconfirm content="确定要删除这个仓库吗？" @ok="handleDelete(record.id)">
                <a-button type="text" status="danger" size="small">删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </a-table>
      </div>
    </a-card>

    <a-modal
      :visible="visible"
      @update:visible="(v) => (visible = v)"
      :title="editingId ? '更新仓库' : '新增仓库'"
      @ok="handleConfirm"
      @cancel="handleCancel"
    >
      <a-form :model="form" auto-label-width>
        <a-form-item field="name" label="仓库名称">
          <a-input v-model="form.name" :max-length="128" placeholder="例如：my-go-project" />
        </a-form-item>
        <a-form-item field="url" label="Git 地址">
          <a-input v-model="form.url" :max-length="300" placeholder="https://github.com/user/repo.git" />
        </a-form-item>
        <a-form-item field="language" label="主要语言">
          <a-select v-model="form.language" placeholder="请选择语言">
            <a-option value="go">Go</a-option>
            <a-option value="java">Java</a-option>
            <a-option value="javascript">JavaScript</a-option>
            <a-option value="python">Python</a-option>
          </a-select>
        </a-form-item>
        <a-form-item field="branch" label="扫描分支">
          <a-input v-model="form.branch" :max-length="128" placeholder="默认为 main" />
        </a-form-item>
        <a-form-item field="stars" label="Stars">
          <a-input-number v-model="form.stars" :min="0" />
        </a-form-item>
        <a-form-item field="auth_type" label="认证类型">
          <a-select v-model="form.auth_type" placeholder="请选择认证类型">
            <a-option value="none">无</a-option>
            <a-option value="token">Token</a-option>
            <a-option value="ssh_key">SSH Key</a-option>
          </a-select>
        </a-form-item>
        <a-form-item
          v-if="form.auth_type !== 'none'"
          field="auth_secret"
          :label="form.auth_type === 'token' ? 'Access Token' : 'SSH Key'"
          :rules="[{ required: true, message: '请输入凭证内容' }]"
        >
          <a-input-password
            v-model="form.auth_secret"
            :placeholder="form.auth_type === 'token' ? '请输入 Personal Access Token' : '请输入 SSH 私钥内容'"
          />
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal :visible="scanVisible" @update:visible="(v) => (scanVisible = v)" title="触发扫描" @ok="handleConfirmScan">
      <a-form :model="scanForm" auto-label-width>
        <a-form-item field="rule_profile" label="规则策略">
          <a-select v-model="scanForm.rule_profile" placeholder="baseline / cve_hot / zero_day_only">
            <a-option value="baseline">baseline</a-option>
            <a-option value="cve_hot">cve_hot</a-option>
            <a-option value="zero_day_only">zero_day_only</a-option>
          </a-select>
        </a-form-item>
        <a-form-item field="query_suite" label="额外规则">
          <a-input v-model="scanForm.query_suite" :max-length="512" placeholder="支持逗号分隔多个 .ql/.qls" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { Message } from '@arco-design/web-vue';
import { IconPlus } from '@arco-design/web-vue/es/icon';
import { addRepo, batchDeleteRepos, deleteRepo, getRepoList, triggerScan, updateRepo } from '../../api/repo';

type RepoLanguage = 'go' | 'java' | 'javascript' | 'python';
type AuthType = 'none' | 'token' | 'ssh_key';
type RuleProfile = 'baseline' | 'cve_hot' | 'zero_day_only';

interface RepoRecord {
  id: number;
  name: string;
  url: string;
  language: RepoLanguage;
  branch: string;
  stars?: number;
  auto_scan_enabled?: boolean;
  auth_type: AuthType;
}

interface RepoForm {
  name: string;
  url: string;
  language: RepoLanguage;
  branch: string;
  stars: number;
  auth_type: AuthType;
  auth_secret: string;
}

interface ScanForm {
  rule_profile: RuleProfile;
  query_suite: string;
}

const BRANCH_REGEX = /^[A-Za-z0-9._/-]{1,128}$/;
const QUERY_FILE_REGEX = /^[A-Za-z0-9._/-]+\.qls?$/;

const normalizeString = (value: string) => value.trim();

const isValidGitUrl = (url: string) => {
  const normalized = normalizeString(url);
  const httpGitRegex = /^https?:\/\/[\w.-]+\/[\w.-]+\/[\w.-]+(?:\.git)?$/;
  const sshGitRegex = /^git@[\w.-]+:[\w.-]+\/[\w.-]+(?:\.git)?$/;
  return httpGitRegex.test(normalized) || sshGitRegex.test(normalized);
};

const isValidBranch = (branch: string) => {
  const normalized = normalizeString(branch);
  return BRANCH_REGEX.test(normalized) && !normalized.includes('..') && !normalized.startsWith('/');
};

const normalizeQuerySuite = (querySuite: string) => {
  const files = querySuite
    .split(',')
    .map((item) => normalizeString(item))
    .filter(Boolean);

  if (files.length === 0) {
    return '';
  }

  const valid = files.every((file) => QUERY_FILE_REGEX.test(file) && !file.includes('..'));
  if (!valid) {
    return null;
  }

  return files.join(',');
};

const loading = ref(false);
const visible = ref(false);
const editingId = ref<number | null>(null);
const data = ref<RepoRecord[]>([]);
const selectedRowKeys = ref<number[]>([]);
const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
});

const initialForm: RepoForm = {
  name: '',
  url: '',
  language: 'go',
  branch: 'main',
  stars: 0,
  auth_type: 'none',
  auth_secret: '',
};

const form = reactive({ ...initialForm });

const columns = [
  { title: '名称', dataIndex: 'name', width: 180, ellipsis: true, tooltip: true },
  { title: 'Git 地址', dataIndex: 'url', width: 300, ellipsis: true, tooltip: true },
  { title: '语言', slotName: 'language', width: 90 },
  { title: 'Stars', dataIndex: 'stars', width: 90 },
  { title: '分支', dataIndex: 'branch', width: 100 },
  { title: '认证方式', dataIndex: 'auth_type', width: 110 },
  { title: '操作', slotName: 'actions', width: 210, fixed: 'right', align: 'center' as const },
];

const rowSelectionState = reactive({
  type: 'checkbox' as const,
  fixed: true,
  width: 48,
  showCheckedAll: true,
  selectedRowKeys: [] as (string | number)[],
  onChange: (keys: (string | number)[]) => {
    selectedRowKeys.value = keys.map((k) => Number(k));
  },
});

watch(
  () => selectedRowKeys.value,
  (v) => {
    rowSelectionState.selectedRowKeys = v;
  },
  { immediate: true }
);

const rowSelection = computed(() => rowSelectionState);

const scanVisible = ref(false);
const scanTarget = ref<RepoRecord | null>(null);
const scanForm = reactive<ScanForm>({
  rule_profile: 'baseline',
  query_suite: '',
});

const loadData = async () => {
  loading.value = true;
  try {
    const res = await getRepoList(pagination.current, pagination.pageSize);
    data.value = res.data.data.data;
    pagination.total = res.data.data.total;
  } catch {
    Message.error('获取列表失败');
  } finally {
    loading.value = false;
  }
};

const handleOpenAdd = () => {
  editingId.value = null;
  Object.assign(form, initialForm);
  visible.value = true;
};

const handleOpenEdit = (record: RepoRecord) => {
  editingId.value = record.id;
  Object.assign(form, {
    name: record.name,
    url: record.url,
    language: record.language,
    branch: record.branch,
    stars: record.stars ?? 0,
    auth_type: record.auth_type,
    auth_secret: '',
  });
  visible.value = true;
};

const validateRepoForm = () => {
  form.name = normalizeString(form.name);
  form.url = normalizeString(form.url);
  form.branch = normalizeString(form.branch) || 'main';
  form.auth_secret = form.auth_secret.trim();

  if (!form.name) {
    Message.error('仓库名称不能为空');
    return false;
  }
  if (!isValidGitUrl(form.url)) {
    Message.error('Git 地址格式非法，仅支持标准 HTTP(S)/SSH 仓库地址');
    return false;
  }
  if (!isValidBranch(form.branch)) {
    Message.error('分支名非法：仅允许字母、数字、._/-，且禁止路径穿越片段');
    return false;
  }
  if (form.auth_type !== 'none' && !form.auth_secret && !editingId.value) {
    Message.error('已选择认证类型，必须输入凭证');
    return false;
  }
  return true;
};

const handleConfirm = async () => {
  if (!validateRepoForm()) return;

  const payload = {
    name: form.name,
    url: form.url,
    language: form.language,
    branch: form.branch,
    stars: Number(form.stars) || 0,
    auth_type: form.auth_type,
    ...(form.auth_type !== 'none' && form.auth_secret ? { auth_secret: form.auth_secret } : {}),
  };

  try {
    if (editingId.value) {
      await updateRepo(editingId.value, payload);
      Message.success('更新成功');
    } else {
      await addRepo(payload);
      Message.success('添加成功');
    }
    visible.value = false;
    loadData();
  } catch {
    Message.error(editingId.value ? '更新失败' : '添加失败');
  }
};

const handleCancel = () => {
  visible.value = false;
};

const handleDelete = async (id: number) => {
  try {
    await deleteRepo(id);
    selectedRowKeys.value = selectedRowKeys.value.filter((v) => v !== id);
    Message.success('删除成功');
    loadData();
  } catch {
    Message.error('删除失败');
  }
};

const handleBatchDelete = async () => {
  if (selectedRowKeys.value.length === 0) return;
  try {
    await batchDeleteRepos(selectedRowKeys.value);
    Message.success(`批量删除成功：${selectedRowKeys.value.length} 个仓库`);
    selectedRowKeys.value = [];
    loadData();
  } catch {
    Message.error('批量删除失败');
  }
};

const handlePageChange = (current: number) => {
  pagination.current = current;
  loadData();
};

const handleScan = (record: RepoRecord) => {
  scanTarget.value = record;
  scanForm.query_suite = '';
  scanForm.rule_profile = 'baseline';
  scanVisible.value = true;
};

const handleConfirmScan = async () => {
  if (!scanTarget.value) return;

  const normalizedQuerySuite = normalizeQuerySuite(scanForm.query_suite);
  if (normalizedQuerySuite === null) {
    Message.error('额外规则格式非法，仅允许逗号分隔 .ql/.qls 且禁止路径穿越');
    return;
  }

  try {
    await triggerScan({
      repo_id: scanTarget.value.id,
      language: scanTarget.value.language,
      branch: scanTarget.value.branch,
      rule_profile: scanForm.rule_profile || undefined,
      query_suite: normalizedQuerySuite || undefined,
    });
    scanVisible.value = false;
    Message.success(`已触发扫描：${scanTarget.value.name}`);
  } catch {
    Message.error(`触发扫描失败：${scanTarget.value.name}`);
  }
};

onMounted(() => {
  loadData();
});
</script>

<style scoped>
:deep(.arco-card),
:deep(.arco-modal) {
  box-shadow: none !important;
}

:deep(.repo-actions) {
  white-space: nowrap;
}
</style>
