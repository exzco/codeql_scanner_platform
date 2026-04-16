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
        CodeQL 分析完成后，任务状态会变成 <b>success</b>，点击“查看结果”可查看漏洞。
      </a-alert>

      <a-table
        row-key="id"
        :columns="taskColumns"
        :data="taskData"
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
          <a-button type="text" size="small" @click="viewVulnerabilities(record)">查看结果</a-button>
        </template>
      </a-table>
    </a-card>

    <a-card
      v-if="selectedTaskId"
      :title="`漏洞结果（任务 #${selectedTaskId}）`"
      :bordered="false"
      class="premium-card mt-16"
    >
      <a-table
        row-key="id"
        :columns="vulnColumns"
        :data="vulnData"
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

        <template #actions="{ record }">
          <a-button type="text" size="small" @click="viewCallStack(record)">查看调用栈</a-button>
        </template>
      </a-table>
    </a-card>

    <!-- 调用栈溯源抽屉 -->
    <a-drawer
      v-model:visible="callStackVisible"
      title="漏洞调用栈溯源"
      width="60%"
      unmount-on-close
    >
      <div v-if="!currentCallStack || currentCallStack.length === 0">
        <a-empty description="该漏洞没有调用栈数据或未提取" />
      </div>
      <div v-else>
        <a-tabs default-active-key="1">
          <a-tab-pane v-for="(path, index) in currentCallStack" :key="String(index + 1)" :title="`调用路径 ${index + 1}`">
            <a-table
              :columns="callStackColumns"
              :data="path"
              :pagination="false"
              row-key="key"
            >
              <template #file_path="{ record }">
                <a-tag color="arcoblue">{{ record.file_path }}</a-tag> 
                <span style="margin-left: 8px;">行: {{ record.start_line }} <span v-if="record.end_line && record.end_line !== record.start_line">- {{ record.end_line }}</span></span>
              </template>
            </a-table>
          </a-tab-pane>
        </a-tabs>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { getScanTasks, getScanVulnerabilities } from '../../api/repo';

const statusFilter = ref('');

const taskLoading = ref(false);
const taskData = ref<any[]>([]);
const taskPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
});

const selectedTaskId = ref<number | null>(null);
const vulnLoading = ref(false);
const vulnData = ref<any[]>([]);
const vulnPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
});

const callStackVisible = ref(false);
const currentCallStack = ref<any[]>([]);

const taskColumns = [
  { title: '任务ID', dataIndex: 'id' },
  { title: '仓库', slotName: 'repo' },
  { title: '分支', dataIndex: 'branch' },
  { title: '语言', dataIndex: 'language' },
  { title: '状态', slotName: 'status' },
  { title: '漏洞数', dataIndex: 'vuln_count' },
  { title: '错误信息', dataIndex: 'error_msg', ellipsis: true, tooltip: true },
  { title: '创建时间', dataIndex: 'created_at' },
  { title: '操作', slotName: 'actions' },
];

const vulnColumns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '规则', dataIndex: 'rule_id' },
  { title: '严重性', slotName: 'severity', width: 90 },
  { title: '状态', slotName: 'status', width: 90 },
  { title: '文件', dataIndex: 'file_path', ellipsis: true, tooltip: true },
  { title: '行号', dataIndex: 'start_line', width: 80 },
  { title: '描述', dataIndex: 'message', ellipsis: true, tooltip: true },
  { title: '操作', slotName: 'actions', width: 100 },
];

const callStackColumns = [
  { title: '环节', dataIndex: 'step_index', width: 70 },
  { title: '文件位置', slotName: 'file_path' },
  { title: '代码片段', dataIndex: 'snippet', ellipsis: true, tooltip: true },
  { title: '额外说明', dataIndex: 'message', ellipsis: true, tooltip: true },
];

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

const loadTasks = async () => {
  taskLoading.value = true;
  try {
    const res = await getScanTasks(taskPagination.current, taskPagination.pageSize, undefined, statusFilter.value || undefined);
    taskData.value = res.data.data.data;
    taskPagination.total = res.data.data.total;
  } catch (err) {
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
  } catch (err) {
    Message.error('获取漏洞结果失败');
  } finally {
    vulnLoading.value = false;
  }
};

const viewVulnerabilities = (task: any) => {
  selectedTaskId.value = task.id;
  vulnPagination.current = 1;
  loadVulnerabilities();
};

const viewCallStack = (record: any) => {
  let df = record.data_flow;
  if (typeof df === 'string') {
    try {
      df = JSON.parse(df);
    } catch(e) {
      df = [];
    }
  }
  
  if (Array.isArray(df)) {
    currentCallStack.value = df.map((path: any[]) => {
      if (!Array.isArray(path)) return [];
      return path.map((step, idx) => ({
        ...step,
        key: `step_${idx}`,
        step_index: idx + 1,
      }));
    });
  } else {
    currentCallStack.value = [];
  }
  callStackVisible.value = true;
};

const onTaskPageChange = (current: number) => {
  taskPagination.current = current;
  loadTasks();
};

const onVulnPageChange = (current: number) => {
  vulnPagination.current = current;
  loadVulnerabilities();
};

onMounted(() => {
  loadTasks();
});
</script>

<style scoped>
.scan-task-container {
  max-width: 1200px;
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
</style>
