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
      </a-table>
    </a-card>
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
  { title: 'ID', dataIndex: 'id' },
  { title: '规则', dataIndex: 'rule_id' },
  { title: '严重性', slotName: 'severity' },
  { title: '状态', slotName: 'status' },
  { title: '文件', dataIndex: 'file_path', ellipsis: true, tooltip: true },
  { title: '行号', dataIndex: 'start_line' },
  { title: '描述', dataIndex: 'message', ellipsis: true, tooltip: true },
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
