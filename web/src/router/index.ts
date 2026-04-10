import { createRouter, createWebHistory } from 'vue-router';
import MainLayout from '../layout/MainLayout.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: MainLayout,
      redirect: '/repos',
      children: [
        {
          path: '/dashboard',
          name: 'Dashboard',
          component: () => import('../views/dashboard/index.vue'),
        },
        {
          path: '/repos',
          name: 'RepoList',
          component: () => import('../views/repo/RepoList.vue'),
        },
        {
          path: '/scan-tasks',
          name: 'ScanTasks',
          component: () => import('../views/scan/ScanTasks.vue'),
        },
      ],
    },
  ],
});

export default router;
