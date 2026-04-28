<template>
  <div class="h-full w-full mx-auto max-w-screen-2xl px-5 flex flex-col gap-5 overflow-hidden">
    <div class="flex flex-col gap-4 flex-1 overflow-hidden h-full">
      <a-card title="扫描任务" :bordered="false" class="rounded-lg flex flex-col w-full h-[45%] flex-shrink-0">
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

        <div class="mb-3 grid grid-cols-[repeat(auto-fit,minmax(100px,1fr))] gap-3">
          <div class="min-w-[100px] flex-1 rounded-lg bg-[var(--color-fill-2)] px-4 py-3">
            <div class="text-lg font-semibold text-[var(--color-text-1)]">{{ taskPagination.total }}</div>
            <div class="text-xs text-[var(--color-text-3)]">任务总数</div>
          </div>
          <div class="min-w-[100px] flex-1 rounded-lg bg-[var(--color-fill-2)] px-4 py-3">
            <div class="text-lg font-semibold text-[var(--color-text-1)]">{{ pendingCount }}</div>
            <div class="text-xs text-[var(--color-text-3)]">待执行</div>
          </div>
          <div class="min-w-[100px] flex-1 rounded-lg bg-[var(--color-fill-2)] px-4 py-3">
            <div class="text-lg font-semibold text-[var(--color-text-1)]">{{ runningCount }}</div>
            <div class="text-xs text-[var(--color-text-3)]">执行中</div>
          </div>
          <div class="min-w-[100px] flex-1 rounded-lg bg-[var(--color-fill-2)] px-4 py-3">
            <div class="text-lg font-semibold text-[var(--color-text-1)]">{{ successCount }}</div>
            <div class="text-xs text-[var(--color-text-3)]">已完成</div>
          </div>
          <div class="min-w-[100px] flex-1 rounded-lg bg-[var(--color-fill-2)] px-4 py-3">
            <div class="text-lg font-semibold text-[var(--color-text-1)]">{{ failedCount }}</div>
            <div class="text-xs text-[var(--color-text-3)]">失败</div>
          </div>
        </div>

        <div class="mb-3 text-xs text-[var(--color-text-3)]">选择任务后可查看执行日志、危险点列表与完整调用路径。</div>

        <div class="flex-1 overflow-hidden h-full">
          <a-table
            row-key="id"
            :columns="taskColumns"
            :data="taskData"
            size="small"
            :loading="taskLoading"
            :pagination="taskPagination"
            @page-change="onTaskPageChange"
            :scroll="{x: '100%', y: '100%'}"
            class="h-full w-full"
          >
            <template #created_at="{ record }">
              {{ new Date(record.created_at).toLocaleString() }}
            </template>

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
        </div>
      </a-card>

      <a-card :bordered="false" class="rounded-lg flex-1 flex flex-col overflow-hidden w-full" :title="detailTitle">
        <template #extra>
          <a-space v-if="selectedTask">
            <a-tag :color="statusColor(selectedTask.status)">{{ selectedTask.status }}</a-tag>
            <span class="text-xs text-[var(--color-text-3)]">{{ selectedTask.repository?.name || '-' }}</span>
          </a-space>
        </template>

        <a-empty v-if="!selectedTaskId" description="请选择左侧任务查看详情" />

        <a-tabs v-else default-active-key="results" class="flex-1 flex flex-col overflow-hidden">
          <a-tab-pane key="results" title="漏洞结果" class="h-full w-full flex flex-col overflow-hidden">
            <div class="flex-1 overflow-hidden h-full w-full pt-2">
              <a-table
                row-key="id"
                :columns="vulnColumns"
                :data="vulnData"
                size="small"
                :loading="vulnLoading"
                :pagination="vulnPagination"
                @page-change="onVulnPageChange"
                :scroll="{x: '100%', y: '100%'}"
                class="h-full w-full"
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
                    <span class="text-xs text-[var(--color-text-3)]">L{{ record.start_line || '-' }}</span>
                  </a-space>
                </template>

                <template #repo_url="{ record }">
                  <a-link
                    v-if="record.repo_url"
                    :href="record.repo_url"
                    target="_blank"
                    class="max-w-[200px] truncate"
                  >
                    {{ record.repo_url }}
                  </a-link>
                  <span v-else>-</span>
                </template>

                <template #actions="{ record }">
                  <a-button type="text" size="small" @click="viewCallStack(record)">危险点/调用栈</a-button>
                </template>
              </a-table>
            </div>
          </a-tab-pane>

          <a-tab-pane key="logs" title="任务日志" class="h-full flex flex-col overflow-hidden">
            <div class="mb-2 flex justify-end">
              <a-space>
                <a-switch v-model="autoRefreshLogs" type="round" size="small" />
                <span class="text-xs text-[var(--color-text-3)]">自动刷新</span>
                <a-button size="small" @click="loadTaskLogs">刷新日志</a-button>
              </a-space>
            </div>
            <a-spin :loading="taskLogLoading" class="flex-1 overflow-hidden w-full h-full">
              <div v-if="taskLogLines.length === 0" class="rounded-md border border-dashed border-[var(--color-border-2)] px-3 py-3 text-xs text-[var(--color-text-3)]">
                暂无日志，任务可能尚未启动。
              </div>
              <div v-else class="h-full overflow-auto rounded-lg border border-[var(--color-border-2)] bg-slate-900 px-3 py-2">
                <div v-for="(line, idx) in taskLogLines" :key="`${idx}_${line}`" :class="['font-mono text-xs leading-6 break-all', lineClass(line)]">
                  {{ line }}
                </div>
              </div>
            </a-spin>
          </a-tab-pane>
        </a-tabs>
      </a-card>
    </div>

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
          <a-table
            :columns="dangerPointColumns"
            :data="dangerPoints"
            :pagination="false"
            row-key="key"
            size="small"
            table-layout="auto"
          >
            <template #source="{ record }">
              <div class="source-cell">
                <div class="source-meta">
                  <a-tag :color="record.point_type === 'source' ? 'green' : record.point_type === 'sink' ? 'red' : 'arcoblue'">
                    {{ record.point_type }}
                  </a-tag>
                  <span class="text-xs text-[var(--color-text-2)]">{{ record.file_path || '-' }}</span>
                  <a-link v-if="record.code_link" :href="record.code_link" target="_blank">L{{ record.start_line }}</a-link>
                  <span v-else class="text-xs text-[var(--color-text-3)]">L{{ record.start_line || '-' }}</span>
                </div>
                <pre v-if="record.snippet" class="max-h-36 overflow-auto rounded-md bg-[var(--color-fill-2)] px-2 py-2 text-xs leading-5 whitespace-pre-wrap">{{ record.snippet }}</pre>
                <span v-else class="text-xs text-[var(--color-text-3)]">暂无源码</span>
              </div>
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
                    <div>
                    <div class="mb-1 font-semibold">{{ step.file_path || '-' }} : {{ step.start_line || '-' }}</div>
                    <div class="text-xs text-[var(--color-text-3)]" v-if="step.message">{{ step.message }}</div>
                    <pre class="my-2 max-h-44 overflow-auto rounded-md bg-[var(--color-fill-2)] px-3 py-2 text-xs leading-5 whitespace-pre-wrap" v-if="step.snippet">{{ step.snippet }}</pre>
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
  { title: '仓库', slotName: 'repo', ellipsis: true, tooltip: true },
  { title: '分支', dataIndex: 'branch', ellipsis: true },
  { title: '语言', dataIndex: 'language' },
  { title: '规则策略', dataIndex: 'rule_profile', ellipsis: true },
  { title: '状态', slotName: 'status' },
  { title: '漏洞数', dataIndex: 'vuln_count' },
  { title: '错误信息', dataIndex: 'error_msg', ellipsis: true, tooltip: true },
  { title: '创建时间', slotName: 'created_at' },
  { title: '操作', slotName: 'actions' },
];

const pendingCount = computed(() => taskData.value.filter((item) => item.status === 'pending').length);
const runningCount = computed(() => taskData.value.filter((item) => item.status === 'running').length);
const successCount = computed(() => taskData.value.filter((item) => item.status === 'success').length);
const failedCount = computed(() => taskData.value.filter((item) => item.status === 'failed').length);

const detailTitle = computed(() => {
  if (!selectedTaskId.value) return '任务详情';
  return `任务详情（#${selectedTaskId.value}）`;
});

const vulnColumns = [
  { title: 'ID', dataIndex: 'id' },
  { title: '规则', dataIndex: 'rule_id', ellipsis: true, tooltip: true },
  { title: '严重性', slotName: 'severity' },
  { title: '状态', slotName: 'status' },
  { title: '仓库地址', slotName: 'repo_url', ellipsis: true, tooltip: true },
  { title: '危险位置', slotName: 'location', ellipsis: true, tooltip: true },
  { title: '风险描述', dataIndex: 'message', ellipsis: true, tooltip: true },
  { title: '操作', slotName: 'actions' },
];

const dangerPointColumns = [{ title: '源码', slotName: 'source' }];

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
  snippet: step.snippet || record.code_snippet || '',
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
