# InterGate 安全审计与缺陷修复报告

| 项目 | 内容 |
|---|---|
| 项目 | InterGate · AI API 智能中转网关(Python 版) |
| 审计版本 | v1.1.2 → **v1.1.3** |
| 审计日期 | 2026-10-31 |
| 审计范围 | 44 个 Python 文件(约 8200 行)+ `web/index.html`(3240 行) |
| 方法 | 全量代码走查 + 逐项构造复现脚本 + 修复后回归验证 |
| 结论 | 确认 **15 个缺陷**(4 个 P0、6 个 P1、5 个 P2), 全部已修复 |
| 回归结果 | pytest 79 → **96 项通过**; 冒烟 36 + 62 项通过; 新增 17 项回归用例 |

---

## 一、风险概览

| # | 级别 | 缺陷 | 影响 | 位置 |
|---|---|---|---|---|
| 1 | **P0** | 租户鉴权引用未定义变量 | 限定提供商的租户请求 100% 500 | `gateway.py:162` |
| 2 | **P0** | 响应缓存跨租户串数据 | 读到其他租户的对话内容 | `gateway.py:187` |
| 3 | **P0** | 管理接口网络内匿名可读 | 匿名枚举 Key 配置与运行数据 | `gateway.py:346` |
| 4 | **P0** | 流式超时误判为流结束 | 长思考模型返回空流 | `gateway.py:513` |
| 5 | P1 | 一条非法日志丢弃整批写库 | 用量统计与 Key 状态丢失 | `db/database.py:423` |
| 6 | P1 | 附加网关密钥保存一次即清空 | 点一次开关即失效全部附加密钥 | `webapp.py:471` |
| 7 | P1 | 开关操作导致密钥明文落盘 | 破坏「明文不落盘」安全模型 | `webapp.py:432` |
| 8 | P1 | 在途请求覆盖管理动作 | 额度耗尽/手动停用被复活 | `services/key_manager.py:169` |
| 9 | P1 | 自适应 TPM 单位不一致 | 限流实际失效(20 万 token 未拦) | `services/rate_limiter.py:166` |
| 10 | P1 | 租户 Token 越权读管理端点 | 下游可见上游 Key 清单 | `gateway.py:118-130` |
| 11 | P2 | `/api/settings` 明文回传敏感字段 | 明文进入响应体/浏览器缓存 | `webapp.py:373` |
| 12 | P2 | 配置导出/导入不对称 | 换机后 Key 全废、旧 Token 仍有效 | `webapp.py:743,750` |
| 13 | P2 | 转发丢失查询串 | `alt=sse`、`api-version` 被丢弃 | `gateway.py:91-96` |
| 14 | P2 | Anthropic 鉴权头错误 | Claude 上游一律 401 | `gateway.py:475` |
| 15 | P2 | 额度耗尽告警风暴 | 每请求一条告警 + 一次推送 | `services/quota.py:150` |

> 行号为修复前位置。

---

## 二、P0 缺陷详情

### 1. 租户鉴权引用未定义变量

**症状** — 为租户设置了 `provider` 限定后, 该租户的每个请求都返回 500。

```python
# gateway.py:162 (修复前)
if tenant.provider and provider != tenant.provider:   # provider 尚未赋值
    ...
header_provider = request.headers.get(C.PROVIDER_HEADER)
provider = entry["provider"] if entry else detect_provider(...)   # 168 行才赋值
```

AST 确认 `provider` 的 STORE 在第 168 行, LOAD 在第 162 行。

**复现**

```
租户(不限定提供商) -> 200
租户(限定 openai)   -> UnboundLocalError: cannot access local variable 'provider'
```

`provider == ""` 的租户因 `and` 短路逃过一劫, 掩盖了问题。

**修复** — 将提供商解析前移至租户检查之前 (`gateway.py:144-148`)。

---

### 2. 响应缓存跨租户串数据

**症状** — 缓存键仅 `sha256(method, path, body)`, 不含请求者身份。

```python
cache_key = self.cache.make_key(request.method, path, body)   # 修复前
```

**复现**

```
租户A: {"result":"A的私有数据"} | x-relay-cache: MISS
租户B: {"result":"A的私有数据"} | x-relay-cache: HIT     ← 未调用上游, 直接读到 A 的数据
```

单租户自用场景下这是「省钱」, 一旦开启 `tokens_enabled` 即构成越权读取。

**修复** — `make_key()` 新增 `scope` 参数, 由调用方传入 `租户 id | 凭证名 | provider`:
- `services/cache.py:38` — 内存 LRU 缓存
- `services/shared_state.py:131` — 多 Worker 共享的 SQLite 缓存(同步修改, 否则多进程下漏洞依旧)

---

### 3. 管理接口网络内匿名可读

**症状** — `gateway_key` 为空时 `_authorize()` 对未带凭证的请求返回 full 权限, 而默认监听 `0.0.0.0`。

**复现**

```
默认 host=0.0.0.0  gateway_key=''  gateway_key_enabled=True
无凭证 GET /relay/stats  -> 200
无凭证 GET /relay/report -> 200   ← 含全部 Key 名称 / base_url / 状态 / 用量
无凭证 GET /relay/metrics -> 200
```

**修复** — 匿名放行时返回 `anonymous: True` 标记, 管理端点在鉴权后二次校验并拒绝。
代理路径 `/v1/*` 保持开放 —— 该产品的主要用法是手机热点共享给其它设备, 强制鉴权会破坏现有客户端。

**行为变更** — 依赖匿名抓取 `/relay/metrics` 的监控脚本需补配网关 Key。

---

### 4. 流式响应被误判为流结束

**症状** — 长思考模型(首 token 前推理 > 15 秒)返回空流。

```python
# gateway.py:525-537 (修复前)
try:
    chunk = await asyncio.wait_for(gen.__anext__(), timeout=15.0)
    ...
except asyncio.TimeoutError:
    yield b": keepalive\n\n"        # 以为只是跳过一次读取
except StopAsyncIteration:
    break                            # 实际下一轮就会到这里
```

`wait_for` 超时会**取消** `__anext__`, 异步生成器收到 `CancelledError` 后关闭,
下一次 `__anext__` 抛 `StopAsyncIteration` → `break` → 流结束。

**复现**(真实 httpx 客户端对接「先静默、后输出」的 SSE 服务端)

```
[网关] 15s 无数据 -> yield ': keepalive'
[网关] StopAsyncIteration -> break, 流提前结束
客户端实际收到: []
```

更严重的是 `finally` 中仍执行 `record_success()` 并以 200 记日志, 故障被完全掩盖。

**修复** — 上游读取放入独立任务, 主循环只在「队列空闲」上等待超时, 心跳不再触碰上游迭代器
(`gateway.py:531-580`)。

**验证** — 心跳阈值缩至 50ms 后, 3 个延迟分片 + 结尾 `[DONE]` 全部送达。

---

## 三、P1 缺陷详情

### 5. 一条非法日志丢弃整批写库

`_write_flush()` 用单个 `try` 包住三类 `executemany`, 且 `request_logs.model` 为 `NOT NULL`
而无 model 的请求(`/v1/models`)写入 `None`:

```
批量落库失败, 丢弃 4 条: NOT NULL constraint failed: request_logs.model
合法请求日志落库: 0
日统计落库: 0
Key 写回落库: False
```

**即一次 `/v1/models` 请求就能连带丢掉落库的用量统计和 Key 状态。**

**修复** — 三类写独立提交; 整批失败时降级逐条重试, 只丢弃真正非法的单条
(`db/database.py:411-450`); 同时 `_log_row()` 把 `None` 规整为 `""` (`db/database.py:927`)。

---

### 6. 附加网关密钥保存一次即被清空

后端 GET 只返回 `key_masked` 并 `pop("key")`; 前端把整个对象回传 PUT, 后端 `encrypt_field("")`
得空串后被过滤:

```
PUT#1 {'ok': True, 'count': 1}
GET   [{..., "key_masked": "sk-e••••0111"}]        ← 无 key 字段
PUT#2 {'ok': True, 'count': 0}                     ← 全删了
auth with sk-extra-000111 -> None
```

用户仅点击「启用/停用」开关即导致所有附加密钥失效。

**修复** — GET 返回稳定 `id`; PUT 时按 `id` 或 `key_masked` 复用库中旧密文,
既无新明文也找不到旧密文则跳过而非写入空值 (`webapp.py:475-520`)。

---

### 7. 开关操作导致密钥明文落盘

```python
# webapp.py:432 (修复前)
self.db.set_setting("user_settings", self.settings.to_dict())   # 内存中是明文
```

```
保存设置后         : gateway_key = enc$oDIBH5DAwsbmBB/...
点一次暂停/开启开关 : gateway_key = sk-SECRET-GW            ← 明文
```

**修复** — 改用 `to_persist_dict()`。同类写入点 `webapp.py:414`、`main.py:43` 本就正确,
属单点漏改。

---

### 8. 在途请求成功覆盖管理动作

`record_success()` 无条件 `k.status = ACTIVE`:

```
quota 失败后 : exhausted -> 在途请求成功后: active     (额度耗尽自动解锁)
手动停用     : inactive  -> 在途成功后:   active       (手动停用被覆盖)
```

与 `list_active()` 注释「EXHAUSTED 必须手动处理」直接矛盾。

**修复** — 仅 `ERROR`(运行时冷却)可被成功请求解除; `INACTIVE` / `EXHAUSTED` 保持原状
(`services/key_manager.py:148-166`)。

---

### 9. 自适应 TPM 单位不一致

```python
used = w.count()                                    # 单位: token
...
w.add(max(1, tokens // max(1, int(limit // 60))))   # 单位: 「秒当量」
```

两边量纲不同, 比较恒不成立:

```
TPM 上限: 100000
累计发送 200000 token 后, 被拦次数: 0
窗口记账值: 200
```

**修复** — 统一按 token 记账 (`services/rate_limiter.py:178`)。

**连带发现** — 单位修正后限流真正生效, 立刻暴露 AIMD **按请求数**降档:
窗口一旦饱和, 后续每个请求都触发一次乘性下调, 35 次即把上限从 10 万压到 339(下限),
反过来会把 Key 限死。已为降档加入 60 秒冷却, 使其按「拥塞事件」触发
(`services/rate_limiter.py:52-90`)。

---

### 10. 租户 Token 越权读管理端点

租户 Token 被签发为 `permission: full`, 与主网关 Key 同等权限:

```
租户访问 /relay/report  -> 200 (看到 1 条上游 Key: 名称/base_url/状态/密文)
租户访问 /relay/metrics -> 200
```

下游租户不应知道网关内有多少上游 Key。

**修复** — 租户 Token 签发 `permission: proxy`, 配合缺陷 3 的管理端点校验一并生效
(`gateway.py:390-397`)。

---

## 四、P2 缺陷详情

### 11. `/api/settings` 明文回传敏感字段

```
gateway_key        = 'sk-MASTER-PLAINTEXT'   明文
jwt_secret         = 'jwt-SECRET'            明文
webhook_secret     = 'wh-SECRET'             明文
telegram_bot_token = '123:SECRET'            明文
web_password       = '$pbkdf2$...'           已哈希
```

虽需管理员登录, 但明文会进入响应体、浏览器缓存与调试工具。

**修复**
- GET 统一脱敏: 保留首尾各 4 字符; **长度 ≤12 整体打码**(否则 `jwt-SECRET` 会露出 8/10)
- 新增 `GET /api/settings/secret/{field}` 按需取单个明文(仪表盘「复制网关 Key」使用)
- PUT 丢弃掩码值, 避免前端整体回传把 `sk-M••••TEXT` 写成真实密钥
- 前端配套: `GW_KEY` 改为按需拉取、`fullSettingsBody()` 跳过掩码、`saveField()` 拦截掩码

---

### 12. 配置导出/导入不对称

Key: 导出 `encrypted_key`, 导入要求明文 `key`:

```
导入后: k1 decrypt -> 'sk-REAL-PLAINTEXT'   (原 Key, 因为没被覆盖)
        k1 decrypt -> ''                    (新导入的空 Key)
```

Token: 导出密文, 导入当明文再加密一层:

```
导入后 plaintext = 'u+q6uhBKPjoIi9YnvSevixQGLYr4jhmDQ111yMHlHUH1kVc='  == 导出时的密文
用导出文件里的密文字符串直接鉴权: True
```

净效果: **换机后上游 Key 全废, 而旧租户 Token 依然有效且可预测。**

**修复**
- 导出改为明文(AES 密文依赖本机 `data/.master_key`, 换机不可解密), 标注 `format: intergate-config/2`,
  响应头加 `Cache-Control: no-store`
- 导入按 `format` 判定: 新格式直接用明文; 旧格式密文只做解密, 解不开则跳过并计入 `skipped`,
  绝不把密文当明文写入
- 补齐附加密钥 / 模型开关 / 价格覆盖的还原

---

### 13. 转发丢失查询串

路由只取 `path`, `request.url.query` 从未参与拼接。`_join_base_and_path()` 中的 query
处理逻辑因入参永远无 query 而成为死代码。

```
GET  /v1/models?limit=5&after=abc  -> https://.../v1/models
POST /v1/embeddings?trace=1        -> https://.../v1/embeddings
```

影响 Google 的 `?alt=sse`、Azure 的 `?api-version=` 等。

**修复** — `_handle()` 入口拼接查询串 (`gateway.py:98-101`)。

---

### 14. Anthropic 鉴权头错误

```
转发给 anthropic 的头部: {'anthropic-version': '2023-06-01',
                          'Authorization': 'Bearer sk-ant-REAL'}   ← Anthropic 要求 x-api-key
```

除非 Key 的 `base_url` 指向自行做转换的中转, 否则 Claude 一律 401。

**修复** — 按提供商写入鉴权头: `anthropic` 补 `x-api-key` 与缺省 `anthropic-version`;
同时不再把 `anthropic-version` 透传给其它上游, 并过滤 `x-forwarded-*` / `via` / `forwarded`
等链路头 (`gateway.py:495-515`, 常量 `config/constants.py:71`)。

---

### 15. 额度耗尽告警风暴

`high_error_rate` 分支有去重判断, `quota_exhausted` 分支没有:

```
额度耗尽后 30 次请求 -> 29 条告警入库 + 29 次 webhook 推送
```

**修复** — 按 `(告警类型, Key)` 每自然日只告警一次 (`services/quota.py:190-199`),
两个分支共用同一节流器。

---

## 五、其他观察(未列为缺陷, 建议后续处理)

| 项 | 说明 | 位置 |
|---|---|---|
| 未使用的设置项 | `web_enabled` 全项目 0 处引用; `burst_multiplier`、`token_rate_limit_per_minute`、`max_concurrent` 仅出现在校验白名单, 设置页对它们的改动是空操作 | `config/settings.py:77` |
| 运行时改缓存参数不生效 | `cache_enabled` / `cache_ttl_seconds` 在构造时快照进 `ResponseCache`, 需重启; 但不在 `RESTART_FIELDS` 中, 前端不会提示 | `gateway.py:59-69` |
| JWT 无 `exp` 即永不过期 | `if payload.get("exp")` 为假则跳过校验, 签发方漏带 `exp` 时令牌永不失效 | `services/jwt.py:56` |
| `/api/status` 公开且含子进程调用 | 未鉴权即可触发 `_detect_ips()` 内的 `subprocess.run(["ip", ...])`; 实测 20 次 0.19s, 不严重但应加缓存 | `webapp.py:914` |
| 项目无版本控制 | 无 `.git`, 无法追溯变更; 根目录另有疑似误产物文件 `-H` | — |

---

## 六、验证记录

### 回归测试有效性

将新增的 `tests/test_regressions.py` 在**修复前的快照**上执行:

```
16 failed, 1 passed
```

唯一通过的是 `test_tpm_aimd_does_not_collapse` —— 旧代码 TPM 限流本就未生效, AIMD 无从未触发,
属预期。修复后:

```
17 passed
```

### 全量回归

| 套件 | 修复前 | 修复后 |
|---|---|---|
| `pytest tests/` | 79 passed | **96 passed** |
| `tests/gateway_smoke.py` | 36 项断言 | 36 项断言 |
| `tests/unit_smoke.py` | 62 项断言 | 62 项断言 |

### 真实服务验证

以临时数据目录启动 `main.py`, curl 实测:

```
健康检查(公开)            : 200
/relay/version 匿名       : 401
/relay/stats   匿名       : 401
/relay/report  匿名       : 401
/relay/stats   带网关 Key : 200
GET /api/settings 敏感字段: 'sk-l••••efgh' / '••••' / '••••'   (已脱敏)
落盘 gateway_key          : 加密
切两次网关开关后落盘       : 仍加密
```

---

## 七、升级须知

### 行为变更(可能影响现有部署)

1. **管理接口由匿名可读改为 401** — 未配置网关 Key 时, `/relay/*` 全部拒绝。
   代理接口 `/v1/*` 与健康检查不受影响。依赖匿名抓取 `/relay/metrics` 的监控需补配网关 Key。
2. **`/api/settings` 敏感字段改为脱敏** — 直接读该接口取明文的外部脚本需改用
   `/api/settings/secret/{field}`。
3. **旧版导出文件** — 仍可导入, 但跨机不可解密的 Key/Token 会被跳过并计入 `skipped`。

### 必须执行的凭据轮换

`InterGate.zip`(9 月 28 日归档)中包含 `data/.master_key`、`intergate.db` 与 4MB WAL。
**其中的上游 API Key 应视为已泄露。** 本次修复只阻断新的泄露路径, 不回收已外流的凭据:

- 轮换全部上游服务商 API Key
- 轮换网关 Key 与附加网关密钥
- 轮换租户 Token
- 若曾对外分享该归档, 一并检查账单异常

---

## 八、改动文件清单

| 文件 | 改动要点 |
|---|---|
| `gateway.py` | 提供商解析前移; 缓存 scope; 管理端点鉴权; 流式读取重构; 查询串透传; 上游头白名单与 provider 鉴权头 |
| `webapp.py` | 设置脱敏与 reveal 端点; 掩码回传保护; 附加密钥保留旧密文; 开关写入加密; 导出/导入对称化 |
| `db/database.py` | 批量写分组隔离与逐条降级; `model` 空值规整 |
| `services/cache.py` | `make_key` 新增 `scope` |
| `services/shared_state.py` | `make_key` 新增 `scope`(与内存版一致) |
| `services/key_manager.py` | `record_success` 状态保护 |
| `services/rate_limiter.py` | TPM 单位统一; AIMD 降档冷却 |
| `services/quota.py` | 告警节流 |
| `config/constants.py` | 版本 1.1.3; 新增 `ANTHROPIC_VERSION` |
| `web/index.html` | 网关 Key 按需拉取; 掩码输入保护; `fullSettingsBody` 跳过掩码 |
| `tests/test_regressions.py` | **新增** 17 项回归用例 |
| `tests/gateway_smoke.py` | 适配管理端点鉴权变更 |

### 保留的补丁前快照

`/data/data/com.termux/files/home/工作目录/InterGate.backup-20261031-182324.tgz` (286K)

> 建议尽快 `git init` 并将本次改动拆分为独立提交, 便于后续逐项回退。
