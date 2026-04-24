# 管理 API

QD 提供了一组基于 Bearer Token 的外部管理 API，可用于令牌管理、任务管理、模板管理、用户管理和站点配置。

实现位置：`web/handlers/api.py`

## 基本信息

- 基础路径：`/api/v1`
- 数据格式：`application/json`
- 成功响应：

```json
{
  "ok": true,
  "data": {}
}
```

- 失败响应：

```json
{
  "ok": false,
  "error": {
    "code": "unauthorized",
    "message": "missing bearer token"
  }
}
```

## 认证方式

除了 `POST /api/v1/bootstrap/token` 之外，其他接口都需要在请求头中携带：

```http
Authorization: Bearer <token>
```

令牌会在请求前校验以下条件：

- 必须存在且未被撤销
- 如设置了 `expires_at`，则必须未过期
- 令牌所属用户必须存在
- 非管理员用户必须为启用状态
- 当站点启用了邮箱验证时，用户必须已验证邮箱

### 引导创建 Token

`POST /api/v1/bootstrap/token` 用于在**已有 Web 登录会话**的前提下生成 API Token。

也就是说：

- 这个接口不要求 Bearer Token
- 但要求当前浏览器 / 会话已经登录 QD

请求体示例：

```json
{
  "name": "automation",
  "scopes": "task:read task:write task:run log:read",
  "expires_at": 1777000000
}
```

返回结果中会包含仅返回一次的明文 `token`。

## 权限模型

API 同时使用“用户角色”和“令牌 scope”做权限控制。

常见 scope：

- `admin`
- `token:read`
- `token:write`
- `task:read`
- `task:write`
- `task:run`
- `log:read`
- `log:write`
- `template:read`
- `template:write`
- `template:run`
- `user:read`
- `user:write`
- `site:read`
- `site:write`

### 管理员接口的判定

管理员操作通常要求同时满足：

1. 当前用户 `role == admin`
2. 当前 token 包含 `admin` scope

## 快速示例

### 1. 通过已登录会话创建 Token

```bash
curl -X POST "http://127.0.0.1:8923/api/v1/bootstrap/token" \
  -H "Content-Type: application/json" \
  -H "Cookie: <你的登录会话 Cookie>" \
  -d '{
    "name": "automation",
    "scopes": "task:read task:write task:run log:read",
    "expires_at": 1777000000
  }'
```

### 2. 使用 Token 查询当前身份

```bash
curl "http://127.0.0.1:8923/api/v1/me" \
  -H "Authorization: Bearer <token>"
```

### 3. 列出任务

```bash
curl "http://127.0.0.1:8923/api/v1/tasks" \
  -H "Authorization: Bearer <token>"
```

### 4. 立即执行任务

```bash
curl -X POST "http://127.0.0.1:8923/api/v1/tasks/123/run" \
  -H "Authorization: Bearer <token>"
```

## 接口列表

## 认证与令牌

### POST `/api/v1/bootstrap/token`

使用当前已登录的 Web 会话创建 API Token。

请求体字段：

- `name`: 令牌名称
- `scopes`: scope 字符串，可用空格或逗号分隔
- `expires_at`: 过期时间戳，可选

### GET `/api/v1/me`

返回当前认证用户、当前 token 元信息和已解析的 scopes。

### GET `/api/v1/tokens`

列出当前用户的 API Token。

需要 scope：`token:read`

查询参数：

- `userid`: 管理员可指定其他用户 ID

### POST `/api/v1/tokens`

创建 API Token。

需要 scope：`token:write`

请求体字段：

- `name`
- `scopes`
- `expires_at`
- `userid`: 管理员可为其他用户创建

### GET `/api/v1/tokens/{token_id}`

获取指定 Token 的元信息。

需要 scope：`token:read`

### PATCH `/api/v1/tokens/{token_id}`

更新 Token。

需要 scope：`token:write`

可更新字段：

- `name`
- `scopes`
- `expires_at`
- `revoked`

### DELETE `/api/v1/tokens/{token_id}`

撤销指定 Token。

需要 scope：`token:write`

## 任务管理

### GET `/api/v1/tasks`

列出任务。

需要 scope：`task:read`

查询参数：

- `userid`: 管理员可查看其他用户任务

### POST `/api/v1/tasks`

根据模板创建任务。

需要 scope：`task:write`

请求体字段：

- `tplid`: 模板 ID，必填
- `note`: 备注
- `proxy`: 代理地址
- `retry_count`: 重试次数
- `retry_interval`: 重试间隔
- `variables`: 初始变量对象
- `group`: 分组

### GET `/api/v1/tasks/{task_id}`

获取任务详情。

需要 scope：`task:read`

查询参数：

- `include_env=true`: 返回解密后的 `init_env`，同时还需要 `task:write`

### PATCH `/api/v1/tasks/{task_id}`

更新任务。

需要 scope：`task:write`

可更新字段：

- `note`
- `disabled`
- `retry_count`
- `retry_interval`
- `_groups`
- `next`
- `variables`
- `proxy`

### DELETE `/api/v1/tasks/{task_id}`

删除任务及其日志。

需要 scope：`task:write`

### POST `/api/v1/tasks/{task_id}/enable`

启用任务。

需要 scope：`task:write`

### POST `/api/v1/tasks/{task_id}/disable`

禁用任务。

需要 scope：`task:write`

### PATCH `/api/v1/tasks/{task_id}/schedule`

更新任务计划。

需要 scope：`task:write`

请求体为计划对象，常用字段包括：

- `sw`
- `mode`
- `time`
- `date`
- `cron_val`
- `randsw`
- `tz1`
- `tz2`
- `cron_sec`

### PATCH `/api/v1/tasks/{task_id}/group`

修改任务分组。

需要 scope：`task:write`

请求体字段：

- `group`

### POST `/api/v1/tasks/{task_id}/run`

立即执行任务。

需要 scope：`task:run`

返回字段示例：

- `task_id`
- `tpl_id`
- `success`
- `log`
- `next`
- `duration`

### GET `/api/v1/tasks/{task_id}/logs`

获取任务日志。

需要 scope：`log:read`

### DELETE `/api/v1/tasks/{task_id}/logs`

删除任务日志。

需要 scope：`log:write`

请求体字段：

- `older_than_days`: 删除多少天前的日志
- `success`: 按成功 / 失败筛选

### POST `/api/v1/tasks/batch`

批量操作任务。

需要 scope：`task:write`

请求体字段：

- `action`: `delete` / `enable` / `disable` / `set_group`
- `task_ids`: 任务 ID 数组
- `group`: 当 `action=set_group` 时使用

## 聚合日志

### GET `/api/v1/logs`

获取当前用户任务的聚合日志。

需要 scope：`log:read`

查询参数：

- `userid`: 管理员查看其他用户
- `days`: 默认 `365`

## 模板管理

### GET `/api/v1/templates`

列出模板。

需要 scope：`template:read`

查询参数：

- `scope=mine`: 我的模板
- `scope=public`: 公共模板
- `scope=all`: 所有模板，仅管理员

### POST `/api/v1/templates`

创建模板。

需要 scope：`template:write`

请求体字段：

- `tpl`: 模板内容，必填
- `har`: HAR 内容
- `init_env`
- `siteurl`
- `sitename`
- `banner`
- `note`
- `interval`
- `public`
- `group`

### GET `/api/v1/templates/{tpl_id}`

获取模板详情。

需要 scope：`template:read`

查询参数：

- `include_content=true`: 同时返回解密后的 `har`、`tpl`、`init_env`，并额外需要 `template:write`

### PATCH `/api/v1/templates/{tpl_id}`

更新模板。

需要 scope：`template:write`

可更新字段：

- `siteurl`
- `sitename`
- `banner`
- `note`
- `interval`
- `public`
- `disabled`
- `_groups`
- `group`
- `tpl`
- `har`
- `init_env`

### DELETE `/api/v1/templates/{tpl_id}`

删除模板及其关联任务和日志。

需要 scope：`template:write`

### GET `/api/v1/templates/{tpl_id}/variables`

获取模板变量定义与初始环境。

需要 scope：`template:read`

### POST `/api/v1/templates/{tpl_id}/run`

直接执行模板。

需要 scope：`template:run`

请求体字段：

- `variables`
- `session`

## 用户管理

### GET `/api/v1/users`

列出所有用户。

需要 scope：`user:read`

同时要求管理员角色和 `admin` scope。

查询参数：

- `include_sensitive=true`: 返回更多敏感字段

### POST `/api/v1/users`

创建用户。

需要 scope：`user:write`

同时要求管理员角色和 `admin` scope。

请求体字段：

- `email`
- `password`
- `nickname`
- `role`
- `status`
- `email_verified`

### GET `/api/v1/users/{user_id}`

获取用户详情。

需要 scope：`user:read`

用户可读取自己；读取他人时需要管理员权限。

### PATCH `/api/v1/users/{user_id}`

更新用户信息。

需要 scope：`user:write`

用户可修改自己；修改他人时需要管理员权限。

常见字段：

- `nickname`
- `role`
- `status`
- `email_verified`
- `noticeflg`
- `logtime`
- `push_batch`
- `diypusher`
- `skey`
- `barkurl`
- `wxpusher`
- `qywx_token`
- `qywx_webhook`
- `tg_token`
- `dingding_token`

### DELETE `/api/v1/users/{user_id}`

删除用户及其关联任务、模板、日志、便签。

需要 scope：`user:write`

同时要求管理员角色和 `admin` scope。

### POST `/api/v1/users/{user_id}/password`

修改用户密码。

需要 scope：`user:write`

### PATCH `/api/v1/users/{user_id}/push`

更新用户推送配置。

需要 scope：`user:write`

请求体可包含：

- `skey`
- `barkurl`
- `wxpusher`
- `qywx_token`
- `qywx_webhook`
- `tg_token`
- `dingding_token`
- `noticeflg`
- `logtime`
- `push_batch`
- `diypusher`

## 站点配置

### GET `/api/v1/site/config`

获取站点配置。

需要 scope：`site:read`

同时要求管理员角色和 `admin` scope。

### PATCH `/api/v1/site/config`

更新站点配置。

需要 scope：`site:write`

同时要求管理员角色和 `admin` scope。

可更新字段：

- `regEn`
- `MustVerifyEmailEn`
- `logDay`
- `repos`

当 `MustVerifyEmailEn=1` 时，要求服务端已配置 `config.domain`。

## 常见错误

### 401 Unauthorized

- `missing bearer token`
- `invalid token`
- `token expired`
- `login required`

### 403 Forbidden

- `insufficient scope`
- `admin required`
- `admin scope required`
- `user disabled`
- `email not verified`

### 404 Not Found

- `token not found`
- `template not found`
- `user not found`

### 409 Conflict

- `email already exists`
