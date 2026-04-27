<template>
  <div class="scan-task-container">
    <a-card title="扫描任务" :bordered="false" class="premium-card">
      <template #extra>
        <a-space>
          <a-select v-model="statusFilter" style="width: 180px" allow-clear placeholder="按状态筛选" @change="loadTasks">
            <a-option value="pending">pending</a-option>
            <a-option value="running">running</a-option>
            <a-option value="success">success</a-option>
            <a-option value="failed">failed</a-option>
          </a-select>
          <a-button @click="loadTasks">刷新</a-button>
        </a-space>
      </template>

      <a-alert type="info" class="mb-12">
        选择任务后可查看 <b>执行日志</b>、<b>危险点列表</b> 与 <b>完整调用路径</b>。
      </a-alert>

      <a-table
        row-key="id"
        :columns="taskColumns"
        :data="taskData"
        size="small"
        :loading="taskLoading"
        :pagination="taskPagination"
        @page-change="onTaskPageChange"
      >
        <template #status="{ record }">
          <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
        </template>

        <template #repo="{ record }">
          {{ record.repository?.name || '-' }}
        </template>

        <template #actions="{ record }">
          <a-space :size="6">
            <a-button type="text" size="small" @click="viewVulnerabilities(record)">查看结果</a-button>
            <a-button type="text" size="small" @click="viewTaskLogs(record)">查看日志</a-button>
            <a-popconfirm content="确认删除该扫描任务及其漏洞记录吗？" @ok="handleDeleteTask(record)">
              <a-button type="text" status="danger" size="small">删除任务</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </a-table>
    </a-card>

    <a-card v-if="selectedTaskId" :title="`任务详情（#${selectedTaskId}）`" :bordered="false" class="premium-card mt-16">
      <a-tabs default-active-key="results">
        <a-tab-pane key="results" title="漏洞结果">
          <a-table
            row-key="id"
            :columns="vulnColumns"
            :data="vulnData"
            size="small"
            :loading="vulnLoading"
            :pagination="vulnPagination"
            @page-change="onVulnPageChange"
          >
            <template #severity="{ record }">
              <a-tag :color="severityColor(record.severity)">{{ record.severity }}</a-tag>
            </template>

            <template #status="{ record }">
              <a-tag>{{ record.status }}</a-tag>
            </template>

            <template #location="{ record }">
              <a-space direction="vertical" :size="2">
                <span>{{ record.file_path || '-' }}</span>
                <span class="hint-text">L{{ record.start_line || '-' }}</span>
              </a-space>
            </template>

            <template #repo_url="{ record }">
              <a-link
                v-if="record.repo_url"
                :href="record.repo_url"
                target="_blank"
                style="max-width: 180px; display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
              >
                {{ record.repo_url }}
              </a-link>
              <span v-else>-</span>
            </template>

            <template #actions="{ record }">
              <a-button type="text" size="small" @click="viewCallStack(record)">危险点/调用栈</a-button>
            </template>
          </a-table>
        </a-tab-pane>

        <a-tab-pane key="logs" title="任务日志">
          <div class="log-toolbar">
            <a-space>
              <a-switch v-model="autoRefreshLogs" type="round" size="small" />
              <span class="hint-text">自动刷新</span>
              <a-button size="small" @click="loadTaskLogs">刷新日志</a-button>
            </a-space>
          </div>
          <a-spin :loading="taskLogLoading" style="width: 100%">
            <div v-if="taskLogLines.length === 0" class="empty-log">
              暂无日志，任务可能尚未启动。
            </div>
            <div v-else class="log-panel compact-log">
              <div v-for="(line, idx) in taskLogLines" :key="`${idx}_${line}`" :class="['log-line', lineClass(line)]">
                {{ line }}
              </div>
            </div>
          </a-spin>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <a-drawer
      :visible="callStackVisible"
      @update:visible="(v) => (callStackVisible = v)"
      :title="drawerTitle"
      width="70%"
      unmount-on-close
    >
      <a-descriptions v-if="currentVuln" :column="2" layout="inline-horizontal" class="mb-12" bordered>
        <a-descriptions-item label="规则 ID">{{ currentVuln.rule_id || '-' }}</a-descriptions-item>
        <a-descriptions-item label="严重性">
          <a-tag :color="severityColor(currentVuln.severity)">{{ currentVuln.severity || '-' }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="危险文件">{{ currentVuln.file_path || '-' }}</a-descriptions-item>
        <a-descriptions-item label="起始行">{{ currentVuln.start_line || '-' }}</a-descriptions-item>
      </a-descriptions>

      <a-tabs default-active-key="danger-points">
        <a-tab-pane key="danger-points" title="危险点列表">
          <a-table :columns="dangerPointColumns" :data="dangerPoints" :pagination="false" row-key="key" size="small">
            <template #type="{ record }">
              <a-tag :color="record.point_type === 'source' ? 'green' : record.point_type === 'sink' ? 'red' : 'arcoblue'">
                {{ record.point_type }}
              </a-tag>
            </template>
            <template #location="{ record }">
              <a-space direction="vertical" :size="2">
                <span>{{ record.file_path || '-' }}</span>
                <a-link v-if="record.code_link" :href="record.code_link" target="_blank">定位到代码 (L{{ record.start_line }})</a-link>
                <span v-else class="hint-text">L{{ record.start_line || '-' }}</span>
              </a-space>
            </template>
          </a-table>
          <a-empty v-if="dangerPoints.length === 0" description="该漏洞没有可视化危险点数据" />
        </a-tab-pane>

        <a-tab-pane key="call-stack" title="调用路径可视化">
          <div v-if="currentCallStack.length === 0">
            <a-empty description="该漏洞没有调用栈数据或未提取" />
          </div>
          <a-tabs v-else default-active-key="1" type="capsule">
            <a-tab-pane v-for="(path, index) in currentCallStack" :key="String(index + 1)" :title="`路径 ${index + 1}`">
              <a-timeline>
                <a-timeline-item v-for="step in path" :key="step.key" :label="`Step ${step.step_index}`">
                  <div class="timeline-line">
                    <div class="timeline-title">{{ step.file_path || '-' }} : {{ step.start_line || '-' }}</div>
                    <div class="hint-text" v-if="step.message">{{ step.message }}</div>
                    <pre class="snippet" v-if="step.snippet">{{ step.snippet }}</pre>
                    <a-link v-if="step.code_link" :href="step.code_link" target="_blank">跳转代码位置</a-link>
                  </div>
                </a-timeline-item>
              </a-timeline>
            </a-tab-pane>
          </a-tabs>
        </a-tab-pane>
      </a-tabs>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue';
import { Message } from '@arco-design/web-vue';
import { deleteScanTask, getScanTaskLogs, getScanTasks, getScanVulnerabilities } from '../../api/repo';

interface ScanTaskRecord {
  id: number;
  status: string;
  branch: string;
  language: string;
  repository?: { name?: string };
}

interface DangerPoint {
  key: string;
  path_index: number;
  step_index: number;
  point_type: 'source' | 'flow' | 'sink';
  file_path: string;
  start_line: number;
  end_line?: number;
  snippet?: string;
  message?: string;
  code_link?: string;
}

const statusFilter = ref('');

const taskLoading = ref(false);
const taskData = ref<ScanTaskRecord[]>([]);
const taskPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
});

const selectedTaskId = ref<number | null>(null);
const selectedTask = ref<ScanTaskRecord | null>(null);

const vulnLoading = ref(false);
const vulnData = ref<any[]>([]);
const vulnPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
});

const taskLogLoading = ref(false);
const taskLogLines = ref<string[]>([]);
const autoRefreshLogs = ref(true);
let logTimer: number | null = null;

const callStackVisible = ref(false);
const currentCallStack = ref<any[]>([]);
const currentVuln = ref<any | null>(null);
const dangerPoints = ref<DangerPoint[]>([]);

const taskColumns = [
  { title: '任务ID', dataIndex: 'id' },
  { title: '仓库', slotName: 'repo' },
  { title: '分支', dataIndex: 'branch' },
  { title: '语言', dataIndex: 'language' },
  { title: '规则策略', dataIndex: 'rule_profile', width: 110 },
  { title: '状态', slotName: 'status' },
  { title: '漏洞数', dataIndex: 'vuln_count' },
  { title: '错误信息', dataIndex: 'error_msg', ellipsis: true, tooltip: true },
  { title: '创建时间', dataIndex: 'created_at' },
  { title: '操作', slotName: 'actions', width: 180 },
];

const vulnColumns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '规则', dataIndex: 'rule_id', width: 180, ellipsis: true, tooltip: true },
  { title: '严重性', slotName: 'severity', width: 90 },
  { title: '状态', slotName: 'status', width: 90 },
  { title: '仓库地址', slotName: 'repo_url', width: 190, ellipsis: true, tooltip: true },
  { title: '危险位置', slotName: 'location', width: 260, ellipsis: true, tooltip: true },
  { title: '风险描述', dataIndex: 'message', ellipsis: true, tooltip: true },
  { title: '操作', slotName: 'actions', width: 130 },
];

const dangerPointColumns = [
  { title: '路径', dataIndex: 'path_index', width: 70 },
  { title: '步骤', dataIndex: 'step_index', width: 70 },
  { title: '类型', slotName: 'type', width: 90 },
  { title: '代码位置', slotName: 'location' },
  { title: '上下文', dataIndex: 'snippet', ellipsis: true, tooltip: true },
  { title: '说明', dataIndex: 'message', ellipsis: true, tooltip: true },
];

const drawerTitle = computed(() => {
  if (!currentVuln.value) return '漏洞详情';
  return `漏洞详情：${currentVuln.value.rule_id || '-'} @ ${currentVuln.value.file_path || '-'}`;
});

const statusColor = (status: string) => {
  const map: Record<string, string> = {
    pending: 'gray',
    running: 'arcoblue',
    success: 'green',
    failed: 'red',
  };
  return map[status] || 'gray';
};

const severityColor = (severity: string) => {
  const map: Record<string, string> = {
    critical: 'red',
    high: 'orangered',
    medium: 'orange',
    low: 'gold',
    info: 'blue',
  };
  return map[severity] || 'gray';
};

const normalizeRepoUrl = (url: string) => url.replace(/\.git$/i, '').trim();

const buildCodeLink = (repoUrl?: string, filePath?: string, line?: number) => {
  if (!repoUrl || !filePath || !line || !selectedTask.value?.branch) return '';
  const normalized = normalizeRepoUrl(repoUrl);
  if (!normalized.includes('github.com')) return '';
  const cleanFilePath = String(filePath).replace(/^\/+/, '');
  return `${normalized}/blob/${selectedTask.value.branch}/${cleanFilePath}#L${line}`;
};

const parseDataFlow = (dataFlowRaw: unknown) => {
  let parsed = dataFlowRaw;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      parsed = [];
    }
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.map((path: any[], pathIndex: number) => {
    if (!Array.isArray(path)) return [];
    return path.map((step, index) => ({
      ...step,
      key: `path_${pathIndex}_step_${index}`,
      step_index: index + 1,
      path_index: pathIndex + 1,
    }));
  });
};

const buildDangerPoints = (record: any, callstack: any[][]): DangerPoint[] => {
  const points: DangerPoint[] = [];
  callstack.forEach((path, pathIndex) => {
    path.forEach((step: any, stepIndex: number) => {
      const isFirst = stepIndex === 0;
      const isLast = stepIndex === path.length - 1;
      const pointType: DangerPoint['point_type'] = isFirst ? 'source' : isLast ? 'sink' : 'flow';
      points.push({
        key: `dp_${pathIndex}_${stepIndex}`,
        path_index: pathIndex + 1,
        step_index: stepIndex + 1,
        point_type: pointType,
        file_path: step.file_path || record.file_path || '',
        start_line: Number(step.start_line || record.start_line || 0),
        end_line: Number(step.end_line || 0) || undefined,
        snippet: step.snippet || '',
        message: step.message || record.message || '',
        code_link: buildCodeLink(record.repo_url, step.file_path || record.file_path, Number(step.start_line || record.start_line || 0)),
      });
    });
  });

  if (points.length === 0) {
    points.push({
      key: `dp_main_${record.id}`,
      path_index: 1,
      step_index: 1,
      point_type: 'sink',
      file_path: record.file_path || '',
      start_line: Number(record.start_line || 0),
      end_line: Number(record.end_line || 0) || undefined,
      snippet: record.code_snippet || '',
      message: record.message || '',
      code_link: buildCodeLink(record.repo_url, record.file_path, Number(record.start_line || 0)),
    });
  }

  return points;
};

const lineClass = (line: string) => {
  const lower = line.toLowerCase();
  if (lower.includes('error') || lower.includes('失败')) return 'log-error';
  if (lower.includes('完成') || lower.includes('success')) return 'log-success';
  return 'log-default';
};

const loadTasks = async () => {
  taskLoading.value = true;
  try {
    const res = await getScanTasks(taskPagination.current, taskPagination.pageSize, undefined, statusFilter.value || undefined);
    taskData.value = res.data.data.data;
    taskPagination.total = res.data.data.total;
  } catch {
    Message.error('获取扫描任务失败');
  } finally {
    taskLoading.value = false;
  }
};

const loadVulnerabilities = async () => {
  if (!selectedTaskId.value) return;
  vulnLoading.value = true;
  try {
    const res = await getScanVulnerabilities(selectedTaskId.value, vulnPagination.current, vulnPagination.pageSize);
    vulnData.value = res.data.data.data;
    vulnPagination.total = res.data.data.total;
  } catch {
    Message.error('获取漏洞结果失败');
  } finally {
    vulnLoading.value = false;
  }
};

const loadTaskLogs = async () => {
  if (!selectedTaskId.value) return;
  taskLogLoading.value = true;
  try {
    const res = await getScanTaskLogs(selectedTaskId.value);
    taskLogLines.value = Array.isArray(res.data?.data?.logs) ? res.data.data.logs : [];
  } catch {
    Message.error('获取任务日志失败');
  } finally {
    taskLogLoading.value = false;
  }
};

const ensureSelectedTask = (task: ScanTaskRecord) => {
  selectedTaskId.value = task.id;
  selectedTask.value = task;
};

const viewVulnerabilities = (task: ScanTaskRecord) => {
  ensureSelectedTask(task);
  vulnPagination.current = 1;
  loadVulnerabilities();
  loadTaskLogs();
};

const viewTaskLogs = (task: ScanTaskRecord) => {
  ensureSelectedTask(task);
  loadTaskLogs();
};

const handleDeleteTask = async (task: ScanTaskRecord) => {
  try {
    await deleteScanTask(task.id);
    Message.success(`任务 #${task.id} 删除成功`);

    if (selectedTaskId.value === task.id) {
      selectedTaskId.value = null;
      selectedTask.value = null;
      vulnData.value = [];
      taskLogLines.value = [];
    }

    loadTasks();
  } catch {
    Message.error(`任务 #${task.id} 删除失败`);
  }
};

const viewCallStack = (record: any) => {
  currentVuln.value = record;
  const parsed = parseDataFlow(record.data_flow);
  currentCallStack.value = parsed.map((path) =>
    path.map((step: any) => ({
      ...step,
      code_link: buildCodeLink(record.repo_url, step.file_path, Number(step.start_line || 0)),
    }))
  );
  dangerPoints.value = buildDangerPoints(record, currentCallStack.value);
  callStackVisible.value = true;
};

const startLogPolling = () => {
  if (logTimer) {
    window.clearInterval(logTimer);
    logTimer = null;
  }
  logTimer = window.setInterval(() => {
    if (!autoRefreshLogs.value || !selectedTask.value) return;
    if (selectedTask.value.status === 'running' || selectedTask.value.status === 'pending') {
      loadTaskLogs();
    }
  }, 5000);
};

const onTaskPageChange = (current: number) => {
  taskPagination.current = current;
  loadTasks();
};

const onVulnPageChange = (current: number) => {
  vulnPagination.current = current;
  loadVulnerabilities();
};

watch(
  () => taskData.value,
  (tasks) => {
    if (!selectedTaskId.value) return;
    const latest = tasks.find((item) => item.id === selectedTaskId.value);
    if (latest) {
      selectedTask.value = latest;
    }
  }
);

onMounted(() => {
  loadTasks();
  startLogPolling();
});

onUnmounted(() => {
  if (logTimer) {
    window.clearInterval(logTimer);
    logTimer = null;
  }
});
</script>

<style scoped>
.scan-task-container {
  max-width: 1080px;
  margin: 0 auto;
}

.premium-card {
  border-radius: 8px;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
}

.mt-16 {
  margin-top: 16px;
}

.mb-12 {
  margin-bottom: 12px;
}

.hint-text {
  color: var(--color-text-3);
  font-size: 12px;
}

.empty-log {
  padding: 12px;
  border: 1px dashed var(--color-border-2);
  border-radius: 6px;
  color: var(--color-text-3);
}

.log-panel {
  max-height: 260px;
  overflow: auto;
  border: 1px solid var(--color-border-2);
  border-radius: 8px;
  background: #0f172a;
  padding: 10px 12px;
}

.compact-log {
	max-height: 320px;
}

.log-toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 8px;
}

.log-line {
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  word-break: break-all;
}

.log-default {
  color: #cbd5e1;
}

.log-success {
  color: #22c55e;
}

.log-error {
  color: #ef4444;
}

.timeline-line {
  width: 100%;
}

.timeline-title {
  font-weight: 600;
  margin-bottom: 4px;
}

.snippet {
  margin: 8px 0;
  padding: 8px;
  border-radius: 6px;
  background: var(--color-fill-2);
  max-height: 180px;
  overflow: auto;
  white-space: pre-wrap;
}
</style>
