<template>
  <div class="repo-container">
    <a-card title="代码仓库管理" :bordered="false" class="premium-card">
      <template #extra>
        <a-button type="primary" @click="handleOpenAdd">
          <template #icon><icon-plus /></template>
          添加仓库
        </a-button>
      </template>

      <!-- 仓库表格 -->
      <a-table 
        :columns="columns" 
        :data="data" 
        :loading="loading"
        :pagination="pagination"
        @page-change="handlePageChange"
      >
        <template #language="{ record }">
          <a-tag :color="record.language === 'go' ? 'blue' : 'green'">
            {{ record.language }}
          </a-tag>
        </template>
        
        <template #actions="{ record }">
          <a-space>
            <a-button type="text" size="small" @click="handleScan(record)">开始扫描</a-button>
            <a-button type="text" status="warning" size="small" @click="handleOpenEdit(record)">更新</a-button>
            <a-popconfirm content="确定要删除这个仓库吗？" @ok="handleDelete(record.id)">
              <a-button type="text" status="danger" size="small">删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </a-table>
    </a-card>

    <!-- 统一的增/改对话框 -->
    <a-modal 
      v-model:visible="visible" 
      :title="editingId ? '更新仓库' : '新增仓库'" 
      @ok="handleConfirm" 
      @cancel="handleCancel"
    >
      <a-form :model="form" auto-label-width>
        <a-form-item field="name" label="仓库名称">
          <a-input v-model="form.name" placeholder="例如：my-go-project" />
        </a-form-item>
        <a-form-item field="url" label="Git 地址">
          <a-input v-model="form.url" placeholder="https://github.com/user/repo.git" />
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
          <a-input v-model="form.branch" placeholder="默认为 main" />
        </a-form-item>
        <a-form-item field="auth_type" label="认证类型">
          <a-select v-model="form.auth_type" placeholder="请选择认证类型">
            <a-option value="none">无</a-option>
            <a-option value="token">Token</a-option>
            <a-option value="ssh_key">SSH Key</a-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { IconPlus } from '@arco-design/web-vue/es/icon';
import { getRepoList, addRepo, deleteRepo, updateRepo, triggerScan } from '../../api/repo';

const loading = ref(false);
const visible = ref(false);
const editingId = ref<number | null>(null); // 💡 正在编辑的记录 ID
const data = ref([]);
const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0
});

// 💡 提取初始表单状态以便重置
const initialForm = {
  name: '',
  url: '',
  language: 'go',
  branch: 'main',
  auth_type: 'none',
};

const form = reactive({ ...initialForm });

const columns = [
  { title: '名称', dataIndex: 'name' },
  { title: 'Git 地址', dataIndex: 'url' },
  { title: '语言', slotName: 'language' },
  { title: '分支', dataIndex: 'branch' },
  { title: '认证方式', dataIndex: 'auth_type' },
  { title: '操作', slotName: 'actions' },
];

const loadData = async () => {
  loading.value = true;
  try {
    const res = await getRepoList(pagination.current, pagination.pageSize);
    data.value = res.data.data.data;
    pagination.total = res.data.data.total;
  } catch (err) {
    Message.error('获取列表失败');
  } finally {
    loading.value = false;
  }
};

const handleOpenAdd = () => {
  editingId.value = null;
  Object.assign(form, initialForm); // 重置表单为空
  visible.value = true;
};

const handleOpenEdit = (record: any) => {
  editingId.value = record.id;

  Object.assign(form, {
    name: record.name,
    url: record.url,
    language: record.language,
    branch: record.branch,
    auth_type: record.auth_type,
  });
  visible.value = true;
};


const handleConfirm = async () => {
  try {
    if (editingId.value) {
      await updateRepo(editingId.value, form);
      Message.success('更新成功');
    } else {
      await addRepo(form);
      Message.success('添加成功');
    }
    visible.value = false;
    loadData();
  } catch (err) {
    Message.error(editingId.value ? '更新失败' : '添加失败');
  }
};

const handleCancel = () => {
  visible.value = false;
};

const handleDelete = async (id: number) => {
  try {
    await deleteRepo(id);
    Message.success('删除成功');
    loadData();
  } catch (err) {
    Message.error('删除失败');
  }
};

const handlePageChange = (current: number) => {
  pagination.current = current;
  loadData();
};

const handleScan = async (record: any) => {
  try {
    await triggerScan(record.id, record.language, record.branch);
    Message.success(`已触发扫描：${record.name}，请到“扫描任务”查看分析进度与结果`);
  } catch (e) {
    Message.error(`触发扫描失败：${record.name}`);
  }
};


onMounted(() => {
  loadData();
});
</script>

<style scoped>
.repo-container {
  max-width: 1200px;
  margin: 0 auto;
}
.premium-card {
  border-radius: 8px;
  box-shadow: 0 4px 10px rgba(0,0,0,0.05);
}
</style>
