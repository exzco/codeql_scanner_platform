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
      ],
    },
  ],
});

export default router;
