<template>
  <div>
    <a-typography-title :heading="3">欢迎使用 CodeQL Platform</a-typography-title>
    <a-grid :cols="24" :colGap="16" :rowGap="16">
      <a-grid-item :span="8">
        <a-card title="扫描任务总数" :bordered="false">
          <a-statistic :value="128" show-group-separator />
        </a-card>
      </a-grid-item>
      <a-grid-item :span="8">
        <a-card title="发现漏洞数" :bordered="false">
          <a-statistic :value="42" color="#f53f3f" show-group-separator />
        </a-card>
      </a-grid-item>
      <a-grid-item :span="8">
        <a-card title="已接入仓库" :bordered="false">
          <a-statistic :value="12" color="#00b42a" show-group-separator />
        </a-card>
      </a-grid-item>
    </a-grid>
  </div>
</template>
