<template>
  <div class="repo-container">
    <a-card title="代码仓库管理" :bordered="false" class="premium-card">
      <template #extra>
        <a-button type="primary" @click="handleOpenAdd">
          <template #icon><icon-plus /></template>
          添加仓库
        </a-button>
      </template>

      <!-- 仓库搜索/过滤 -->
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
            <a-popconfirm content="确定要删除这个仓库吗？" @ok="handleDelete(record.id)">
              <a-button type="text" status="danger" size="small">删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </a-table>
    </a-card>

    <!-- 添加仓库对话框 -->
    <a-modal v-model:visible="visible" title="新增仓库" @ok="handleAdd" @cancel="handleCancel">
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
          </a-select>
        </a-form-item>
        <a-form-item field="branch" label="扫描分支">
          <a-input v-model="form.branch" placeholder="默认为 main" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { IconPlus } from '@arco-design/web-vue/es/icon';
import { getRepoList, addRepo, deleteRepo } from '../../api/repo';

const loading = ref(false);
const visible = ref(false);
const data = ref([]);
const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0
});

const form = reactive({
  name: '',
  url: '',
  language: 'go',
  branch: 'main',
  auth_type: 'none',
});

const columns = [
  { title: '名称', dataIndex: 'name' },
  { title: 'Git 地址', dataIndex: 'url' },
  { title: '语言', slotName: 'language' },
  { title: '分支', dataIndex: 'branch' },
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
  visible.value = true;
};

const handleAdd = async () => {
  try {
    await addRepo(form);
    Message.success('添加成功');
    visible.value = false;
    loadData();
  } catch (err) {
    Message.error('添加失败');
  }
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

const handleScan = (record: any) => {
    Message.info(`即将开始扫描 ${record.name}，下一步将对接异步任务队列`);
}

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
