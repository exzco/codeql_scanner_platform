<template>
  <a-layout class="layout-container">
    <!-- 侧边栏 -->
    <a-layout-sider
      breakpoint="lg"
      :width="220"
      collapsible
      class="sider-bar"
    >
      <div class="logo">
        <img src="https://p1-arco.byteimg.com/tos-cn-i-uwbnlip3yd/a8c8cdb109cb05116f409152c0a42bc0.png~tplv-uwbnlip3yd-webp.webp" />
        <span v-if="!collapsed">CodeQL Platform</span>
      </div>
      <a-menu
        :default-selected-keys="['RepoList']"
        @menu-item-click="handleMenuClick"
      >
        <a-menu-item key="Dashboard">
          <template #icon><icon-dashboard /></template>
          概览
        </a-menu-item>
        <a-menu-item key="RepoList">
          <template #icon><icon-list /></template>
          仓库管理
        </a-menu-item>
        <a-menu-item key="ScanTasks">
          <template #icon><icon-command /></template>
          扫描任务
        </a-menu-item>
      </a-menu>
    </a-layout-sider>

    <!-- 主主体区 -->
    <a-layout>
      <!-- 顶栏 -->
      <a-layout-header class="header-bar">
        <div class="header-left">
          <a-breadcrumb>
            <a-breadcrumb-item>首页</a-breadcrumb-item>
            <a-breadcrumb-item>{{ $route.name }}</a-breadcrumb-item>
          </a-breadcrumb>
        </div>
        <div class="header-right">
          <a-space size="large">
            <a-button shape="circle"><icon-notification /></a-button>
            <a-avatar :size="32">Admin</a-avatar>
          </a-space>
        </div>
      </a-layout-header>

      <!-- 内容区 -->
      <a-layout-content class="content-body">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router';
import { IconDashboard, IconList, IconCommand, IconNotification } from '@arco-design/web-vue/es/icon';

const router = useRouter();

const handleMenuClick = (key: string) => {
  router.push({ name: key });
};
</script>

<style scoped>
.layout-container {
  height: 100vh;
}
.logo {
  height: 64px;
  display: flex;
  align-items: center;
  padding: 0 20px;
  color: #fff;
  font-weight: bold;
  font-size: 18px;
  background: var(--color-bg-3);
  border-bottom: 1px solid var(--color-border);
}
.logo img {
  width: 32px;
  margin-right: 10px;
}
.header-bar {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  background: var(--color-bg-3);
  border-bottom: 1px solid var(--color-border);
}
.content-body {
  padding: 24px;
  background: var(--color-fill-2);
  overflow-y: auto;
}
</style>
