---
name: go-backend-developer
description: |
  Go backend development expertise covering framework routing, database modeling, and handler-driven service derivation.
  Use when: defining backend architecture, building RESTful APIs with Gin, mapping databases with GORM, writing HTTP handlers, and deriving models/services/configs from business requirements.
license: MIT
metadata:
  author: processing-engine
  version: "1.0.0"
---

# Go Backend Developer

专家级 Go 后端开发协议，专注于高清晰度架构解析与自顶向下的代码生成逻辑。

## 触发条件 (When to Apply)

当执行以下结构化构建任务时调用此协议：
- 确定 Go 后端技术栈与基础设施配置。
- 设计关系型数据库表结构与 ORM 映射模型。
- 定义 RESTful 或 RPC 路由拓扑树。
- 编写 HTTP Handler 处理器。
- 由控制层逻辑反向推导所需的 Service 接口与核心业务实现。

## 技术栈规范 (Technology Stack)

### 核心框架层
- **语言** - Go (Golang)
- **路由与 HTTP 框架** - Gin (高性能、中间件支持)
- **数据绑定与校验** - go-playground/validator

### 数据与持久化层
- **关系型数据库** - MySQL / PostgreSQL
- **ORM 组件** - GORM
- **缓存引擎** - Redis (go-redis)

### 基础设施层
- **配置解析** - Viper (支持 YAML, TOML, ENV)

    

## 架构推导流 (Architecture Derivation Pattern)

基于“技术栈 -> 路由/数据库 -> Handler -> Service/Model -> Config”的逻辑链
