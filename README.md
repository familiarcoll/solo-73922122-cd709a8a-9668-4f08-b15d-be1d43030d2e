# 刷新令牌安全续期与盗用即撤销 API（FastAPI + SQLite + cryptography）

一个可实际启动的双进程令牌服务：密码登录后签发**访问令牌（60 秒）**与**刷新令牌（10 分钟）**；
刷新令牌一次性轮换，并在检测到盗用时**永久撤销整条令牌家族**。两个 API 进程共享同一个
SQLite 数据库，所有安全状态变更都在单个数据库事务内原子提交，并发与重启后行为保持一致。

## 安全模型一览

| 需求 | 实现方式 |
| --- | --- |
| 令牌随机且不可猜测 | `secrets` 级 CSPRNG（`os.urandom(32)`）生成不透明令牌 |
| 令牌索引仅存哈希 | 数据库只保存 SHA-256 哈希，原始令牌仅出现在 HTTPS 响应体 |
| 旧刷新令牌只能换一次 | 首次使用即置 `consumed=1` 并在**同一家族**内签发新对 |
| 30 秒内同请求 ID 重试 | `(旧令牌哈希, request_id)` 唯一约束，命中即返回**完全相同**的令牌对 |
| 重试响应加密保存 | 完整令牌对用启动配置提供的 **Fernet 密钥**加密后落库 |
| 复用已消费令牌 = 盗用 | 任何非幂等重试都把**整个家族**置为永久撤销并先提交再返回 401 |
| 家族隔离 | 只撤销被盗家族，其他登录家族的刷新与身份查询不受影响 |
| 撤销不可恢复 | 已撤销家族的刷新、身份查询、幂等重试一律 `family_revoked` |
| 原子性 / 无半份轮换 | 轮换、回执、撤销均在一个 `BEGIN IMMEDIATE` 事务中提交或回滚 |
| 多进程 / 重启一致 | WAL + `busy_timeout`，共享数据卷；状态全部在 SQLite 中 |
| 秘密不写日志 | 不记录请求体，并对令牌/密码形态的日志文本做脱敏过滤 |

令牌家族（family）在**登录时创建**；之后每次轮换产生的新令牌都挂在同一家族下，
因此一次撤销即可让该登录会话的整条令牌链同时失效。

## 目录结构

```
.
├── app/
│   ├── config.py      # 环境变量配置、Fernet 密钥装配
│   ├── security.py    # 随机令牌、SHA-256 哈希、PBKDF2 密码哈希、Fernet 加解密
│   ├── db.py          # SQLite 连接、WAL、事务上下文、建表、演示账户、清理任务
│   ├── models.py      # 请求/响应 Pydantic 模型
│   ├── services.py    # 登录、原子轮换、幂等重试、盗用撤销、访问令牌鉴权
│   └── main.py        # FastAPI 路由、错误映射、日志脱敏
├── scripts/
│   ├── demo.sh            # curl 全流程演示
│   ├── test_services.py   # 服务层正确性测试
│   ├── test_http.py       # 双进程 HTTP 端到端 + 并发测试
│   ├── test_restart.py    # 重启持久性测试
│   └── test_atomicity.py  # 崩溃原子性与落库秘密检查
├── Dockerfile
├── docker-compose.yml # api-a + api-b 两进程 + Nginx 负载均衡
├── nginx.conf
├── .env.example       # 复制为 .env；生产环境务必更换全部秘密
└── requirements.txt
```

## 一键启动（Docker Compose）

```bash
cp .env.example .env          # 已附带可直接演示的值；生产请重新生成密钥
# 生成新的 Fernet 密钥：
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
docker compose up --build
```

启动后：

| 地址 | 用途 |
| --- | --- |
| http://localhost:8080/docs | **交互式文档**（Nginx 轮询到两个 API 进程） |
| http://localhost:8080/health | 健康检查（响应中的 `pid` 会随轮询变化） |
| http://localhost:8001 | 直达 API 进程 A 的 `/docs` |
| http://localhost:8002 | 直达 API 进程 B 的 `/docs` |

演示账户：`demo` / `demo-pass-123`（可通过环境变量覆盖）。

## API

### `POST /api/auth/login`
```json
{ "username": "demo", "password": "demo-pass-123" }
```
返回 `access_token`（60s）、`refresh_token`（600s）、`family_id`。

### `POST /api/auth/refresh`
```json
{ "refresh_token": "<上一次拿到的刷新令牌>", "request_id": "<客户端随机ID>" }
```
- 首次提交：旧令牌消费，返回新令牌对。
- 30 秒内以**相同 request_id** 重试：返回字节级完全相同的令牌对（解密自加密回执）。
- 用已消费令牌搭配**不同 request_id**，或超过幂等窗口再试：返回
  `401 token_reuse_revoked`，并永久撤销整个家族。

### `GET /api/auth/me`
`Authorization: Bearer <access_token>` —— 返回身份信息；家族被撤销后返回
`401 family_revoked`，访问令牌过期返回 `401 token_expired`。

错误响应统一为：
```json
{ "error": { "code": "token_reuse_revoked", "message": "..." } }
```

## 命令行演示

```bash
./scripts/demo.sh                 # 默认走 :8080 负载均衡
BASE=http://localhost:8001 ./scripts/demo.sh
```

脚本依次演示：登录 → 查身份 → 轮换 → 幂等重试返回同对 → 盗用触发整族撤销 →
新令牌与身份查询全部被拒 → 重试无法恢复 → 另一家族不受影响。

## 本地运行（无 Docker）

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export FERNET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export AUTH_DB_PATH=./data/auth.db
uvicorn app.main:app --port 8001   # 终端 1
uvicorn app.main:app --port 8002   # 终端 2，AUTH_DB_PATH 指向同一文件
```

## 测试

```bash
FERNET_KEY=<key> AUTH_DB_PATH=/tmp/t.db python scripts/test_services.py
FERNET_KEY=<key> AUTH_DB_PATH=/tmp/t.db python scripts/test_atomicity.py
# 双进程 HTTP 与重启测试见脚本头部注释
python scripts/test_http.py  http://127.0.0.1:8001 http://127.0.0.1:8002
```

已覆盖：单次轮换、幂等重试返回同对、并发首次轮换恰好一次成功、盗用整族撤销、
家族隔离、撤销后重试不可恢复、跨进程共享状态、进程重启后撤销与回执保持、
崩溃回滚不留半份轮换、库内仅哈希与密文、日志无秘密。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `FERNET_KEY` | （必填） | 加密幂等回执的 Fernet 密钥，由启动配置提供 |
| `AUTH_DB_PATH` | `/data/auth.db` | 两个进程共享的 SQLite 文件路径 |
| `DEMO_USERNAME` / `DEMO_USER_PASSWORD` | `demo` / `demo-pass-123` | 预置演示账户 |
| `ACCESS_TOKEN_TTL` | `60` | 访问令牌有效期（秒） |
| `REFRESH_TOKEN_TTL` | `600` | 刷新令牌有效期（秒） |
| `IDEMPOTENCY_TTL` | `30` | 重试回执有效期（秒） |

> 生产部署提示：本示例面向演示，未启用 TLS（应由前置网关终止 HTTPS）、
> 未做速率限制；`.env` 中的密钥与演示密码必须替换，并通过密钥管理系统注入。
