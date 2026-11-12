# 安全加固说明（2026-11 事件复盘）

> 现象：图床被当成任意文件存储用，出现 `.php` / `.html` / `.svg` 之类的"马"，并伴随大量异常上传。
> 结论：**上传侧和读取侧同时缺少约束，且完全没有限流**。本文记录根因、改动、部署方式和存量清理步骤。

---

## 一、根因分析

| # | 位置 | 问题 | 后果 |
|---|------|------|------|
| 1 | `functions/upload.js` | 只校验 `uploadFile.type.startsWith('image/')`，而 MIME 来自 multipart 头，攻击者随便填 | 任意文件都能"冒充"图片 |
| 2 | `functions/upload.js` `sendToTelegram()` | `sendPhoto` 失败后**自动降级 `sendDocument`**，而 document 通道接受任何文件 | 上传必成功，等于开放了通用网盘 |
| 3 | `functions/upload.js` | 扩展名直接取 `fileName.split('.').pop()`，原样拼进 KV key 和返回 URL | 可生成 `/file/<id>.php`、`.html`、`.svg` 等危险路径 |
| 4 | `functions/file/[id].js` | 不校验扩展名，且把上游 `Content-Type` 原样回传 | 上传的 HTML/SVG/JS 用**本站同源**打开 → 存储型 XSS、钓鱼页、木马分发 |
| 5 | `functions/file/[id].js` | 把用户的全部请求头（含 `Authorization` / `Cookie`）转发给 Telegram | 后台 Basic 凭据外泄给上游 |
| 6 | `admin-imgtc.html` | `v-html` 直接渲染攻击者可控的 `fileName` | 恶意文件名 → 后台 XSS → 管理员会话被利用 |
| 7 | 全站 | 零限流 | 可无限刷上传、当免费 CDN、爆破后台密码 |

> 说明：本项目是 Cloudflare Pages Functions，**运行环境里没有 PHP 解析器**，所以 `.php` 不会真的执行。
> 真正的危害是"用你域名的信誉托管任意 HTML/JS/可执行文件"：存储型 XSS、钓鱼页、恶意软件分发、
> 搜索引擎/安全厂商拉黑域名。所以修复重点是"只允许图片 + 非图片一律不服务"。

---

## 二、本次改动

### 新增

| 文件 | 作用 |
|------|------|
| `functions/utils/security.js` | 图片魔数识别、扩展名白名单、文件名清洗、key 校验、定长比较、统一 JSON 响应 |
| `functions/utils/rate-limit.js` | 限流器（内存窗口 + 可选 KV 跨 isolate 计数），上传/登录/读图三套规则 |
| `functions/api/manage/scan.js` | 存量清理接口：扫描 KV 中扩展名非图片的记录，报告/拉黑/删除 |
| `test/security.test.js` | 19 个安全回归测试（伪装 PHP、HTML、SVG、超限、限流、头注入） |
| `_headers` | 静态资源安全响应头；后台页面 `no-store`；`/file/*` 加 `X-Robots-Tag: noindex` |
| `SECURITY.md` | 本文 |

### 修改

- **`functions/upload.js`**：限流前置 → Content-Length 预检 → 实测大小 → **魔数识别**（只认 JPG/PNG/GIF/WebP/BMP/AVIF）→ 服务端重建文件对象（文件名、MIME 均由服务端决定）→ 只走 `sendPhoto`，仅在图片被 Telegram 拒收时才用 `sendDocument` 保留原图 → 加 15s 超时。
- **`functions/file/[id].js`**：key 形状校验 → **非图片扩展名直接 404**（历史马全部失效）→ 黑白名单先判后回源 → 只转发 `accept/range/if-none-match/if-modified-since` → 强制 `Content-Type` + `nosniff` + `CSP: default-src 'none'; sandbox` → **只在元数据变化时写 KV**（旧版每次请求都写，会烧穿每日 1000 次额度）。
- **`functions/api/manage/_middleware.js`**：凭据比较改为 SHA-256 定长比较；认证失败按 IP 限流；异常不再回吐堆栈；新增 `ADMIN_REQUIRE_AUTH` 强制鉴权开关。
- **`functions/api/manage/editName/[id].js`**：改为读取真实的 `?newName=`（旧代码读 `params.name`，一直是坏的），并清洗长度与字符。
- **`functions/utils/middleware.js`**：异常统一兜底，堆栈只进日志。
- **`admin-imgtc.html`**：`formattedFileDetails` 全字段 HTML 转义（修复存储型 XSS）。
- **`index.html`**：前端允许列表去掉 `svg/ico/tiff`，增加 10MB 大小预检，`accept` 改为精确类型。
- **`.github/workflows/sync.yml`**：**停用每日自动同步上游**。自动 merge 会把安全补丁覆盖回不安全版本，改为手动 `workflow_dispatch` 并逐项 review。

---

## 三、部署

1. 合并本次改动到 `main`，Cloudflare Pages 会自动构建（必须重新部署，环境变量变更同理）。
2. 确认 KV 绑定 `img_url` 仍在（黑白名单依赖它，非必需）。
3. 按需设置环境变量（下表），**不设置也能用默认值**。
4. 打开后台 `/admin`，在"图片管理"里逐一确认没有可疑记录。

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MAX_UPLOAD_SIZE` | `10485760` | 单文件字节上限，硬顶 20MB |
| `UPLOAD_RATE_LIMIT` | `10` | 每 IP 每窗口上传次数 |
| `UPLOAD_RATE_WINDOW` | `60` | 上传限流窗口（秒） |
| `UPLOAD_DAILY_LIMIT` | `300` | 每 IP 每日上传次数 |
| `UPLOAD_GLOBAL_RATE_LIMIT` | `300` | 全站每分钟上传上限（单 isolate 维度） |
| `UPLOAD_TIMEOUT_MS` | `15000` | Telegram 上传超时（3000–25000） |
| `FILE_RATE_LIMIT` | `0`（关闭） | 每 IP 每窗口读图次数，防被当免费 CDN 刷 |
| `FILE_RATE_WINDOW` | `60` | 读图限流窗口（秒） |
| `LOGIN_RATE_LIMIT` | `10` | 后台密码错误次数上限 |
| `LOGIN_RATE_WINDOW` | `300` | 后台登录限流窗口（秒） |
| `BING_RATE_LIMIT` | `30` | 壁纸接口每 IP 每分钟上限 |
| `RATE_LIMIT_ENABLED` | `true` | 总开关，`false` 关闭全部代码层限流 |
| `ADMIN_REQUIRE_AUTH` | `false` | `true` 时若未配置 `BASIC_USER/BASIC_PASS`，后台直接拒绝（不再裸奔） |

### 跨 isolate 限流（可选）

代码层内存计数只在单个 isolate 内有效，量级小时够用；需要更严格时：

1. 新建一个**独立的** KV namespace（不要复用 `img_url`，否则限流计数会吃掉每天的写额度）；
2. 在 Pages 设置里绑定为 `RATE_LIMIT_KV`。

代价：KV 写有最终一致性，计数会略有偏差，但足以打掉脚本刷量。

---

## 四、必须做的两件"代码之外"的事

代码只能保证"以后不再收脏文件"，已经传进来的东西要另外处理。

### 1. Cloudflare WAF 限流（真正的兜底）

代码层限流受 isolate 影响，**务必**在 `Security → WAF → Rate limiting rules` 加一条：

- 表达式：`(http.request.uri.path eq "/upload" and http.request.method eq "POST")`
- 速率：`20` 次 / `1` 分钟，按 `IP`
- 动作：`Block`，持续 `10` 分钟

再加一条 WAF 自定义规则，把历史危险路径彻底掐死（部署新代码后其实已 404，这条是双保险）：

- 表达式：`(http.request.uri.path matches "^/file/.*\.(php|phtml|php[0-9]|pht|asp|aspx|jsp|jspx|html?|js|svg|exe|sh)$")`
- 动作：`Block`

站点被刷流量的话，顺带打开 `Security → Bots → Bot Fight Mode`。

### 2. 存量清理

```bash
# ① 先看清单，不改数据
curl -u 用户名:密码 "https://你的域名/api/manage/scan"

# ② 确认无误后拉黑（推荐，保留记录便于追溯）
curl -u 用户名:密码 "https://你的域名/api/manage/scan?action=block&limit=100"

# ③ 或直接删除 KV 记录（需显式确认；KV 免费额度 1000 次/天，分批跑）
curl -u 用户名:密码 "https://你的域名/api/manage/scan?action=delete&confirm=yes&limit=100"
```

注意：

- `scan` 默认只扫 1000 条，`&max=5000` 可放大；返回里的 `nextCursor` 用于翻页（当前实现每轮独立扫描，量大时建议多跑几次 `block`）。
- **删除 KV 记录 ≠ 删除文件**：原始文件在 Telegram 频道里，需要手动按时间翻找删除；或者干脆重建频道、换 `TG_Chat_ID`。
- 如果怀疑 `TG_Bot_Token` 泄露，去 [@BotFather](https://t.me/BotFather) `/revoke` 换新 token，并同步更新环境变量。
- 检查 Cloudflare 后台是否被动过：环境变量、KV 绑定、Access 策略、API Token 列表；顺手开 2FA。

---

## 五、残余风险（如实说明）

1. **多态文件**：给一张合法 GIF/JPEG 尾部追加 `<?php ... ?>`，魔数校验仍会放行。但本站不解析 PHP，且强制 `Content-Type: image/*` + `nosniff` + `CSP sandbox`，浏览器不会把它当网页/脚本执行，实际不可利用。
2. **代码层限流不跨 isolate**：攻击者换节点就能绕过一部分，**WAF 才是硬约束**。
3. **图片内容本身**：`ModerateContentApiKey` 只做色情识别，不做恶意内容检测；被用来托管违规图片的风险始终存在，建议定期抽查。
4. **后台裸奔风险**：不配置 `BASIC_USER/BASIC_PASS` 时后台仍按原设计开放。生产环境建议开启 `ADMIN_REQUIRE_AUTH=true`，或前置 Cloudflare Access 保护 `/admin*` 与 `/api/manage/*`。
5. **不再自动同步上游**：后续上游的功能更新需要手动 cherry-pick，合并时务必保留本文件的加固点。

---

## 六、回归测试

```bash
npm test                    # 32 个用例：安全 + 后台接口 + 壁纸降级
npm run test:security       # 只跑安全与后台接口相关
```

覆盖的关键断言：

- `shell.php` + `Content-Type: image/png` → **415**
- HTML / SVG 马 → **415**
- 真 PNG 改名 `.php` → 存储为 `.png`（扩展名由内容决定）
- `/file/xxx.php`、`/file/xxx.html`、`/file/xxx.svg` → **404**，且不回源
- 上游谎报 `text/html` → 仍输出 `image/png`
- 请求头里的 `Authorization` / `Cookie` 不会转发给上游
- 连续上传超阈值 → **429 + Retry-After**
- 跨站 `Origin` / `Sec-Fetch-Site: cross-site` 打后台 → **403**，同源与 curl 放行
- 后台非法 key → **400**，记录不存在 → **404**（不再是 500）
- Bing 接口上游失败 → **200 + 空数组**（不白屏、不 500）

---

## 七、第二轮全量审计（2026-11-13）

第一轮修的是"上传/读取"链路，这一轮把剩余文件全部过了一遍，新发现并修复：

| 严重度 | 位置 | 问题 | 处理 |
|---|---|---|---|
| 高 | `manage/block` `manage/white` `manage/delete` | `console.log(env)` 把整个环境变量打到日志，含 `TG_Bot_Token` 与 `BASIC_PASS` | 全部移除，日志只留必要上下文 |
| 高 | `api/manage/*` | 后台用 Basic 认证，浏览器自动附带凭据；第三方页面用 `<img src=".../delete/KEY">` 即可借管理员身份删记录（CSRF） | 中间件最前面加跨站校验（`Sec-Fetch-Site` / `Origin` / `Referer`），同源与 CLI 放行 |
| 中 | `manage/delete/[id]` | 直接用 `params.id` 调 KV delete，可删任意 key | 强制 `parseFileKey` 校验 |
| 中 | `manage/block` `white` `toggleLike` | metadata 为空时抛异常 → 500 | 先判存在性，返回 404 |
| 中 | `api/bing/wallpaper` | 无缓存/无超时/无限流，每个访客都回源 Bing，可被当免费代理 | 边缘缓存 1h + 8s 超时 + 30 次/分/IP + 失败降级空数组 |
| 中 | `file/[id]` | 每次出图都要多打一次 `getFile` 子请求 | `getFile` 边缘缓存 1h；图片本体缓存 1 天（带 Range 的跳过） |
| 低 | `admin.html` | 拉黑/白名单后把 JSON 字符串直接赋给 `metadata`，列表显示错乱 | 改为 `response.json()` 并校验 `error` |
| 低 | `admin-imgtc.html` | 上传失败只提示"上传失败"，读不到服务端 415 文案；且每次上传都额外 GET 一次图片"校验"，流量翻倍 | 兼容 `{error}` / `[{src}]` 两种响应；去掉多余的预览请求 |
| 低 | `_headers` | `/*.html` 与 `admin.html` 的 `no-store` 合并成 `public, max-age=0, must-revalidate, no-store` | 移除冗余规则，交给 Pages 默认策略 |
| 低 | 仓库 | `node_modules/` 被提交进库（**1282 个文件**），`_nuxt/`（1.3MB，8 个文件）是废弃构建产物，均无任何代码引用 | 一并删除，`.gitignore` 补齐；仓库从 1342 个文件降到 56 个 |

同时补充：`robots.txt`（屏蔽后台与 API）、`.gitattributes`（强制 LF，避免 Windows 下补丁校验不一致）、`package.json` 补 `name/private/engines`。

### 仍然建议但未自动执行

1. **删掉 `node_modules` 历史**：本轮删的是当前树；如果想彻底瘦身，可再跑 `git filter-repo --path node_modules --invert-paths`（会重写历史，需强推，自己评估）。
2. **删掉 `package-lock.json` 里的历史依赖**：本轮未改 lock 文件，`npm ci` 仍可复现。
3. **给后台加 Cloudflare Access**：比 Basic 认证更可靠（支持邮箱验证码/SSO），并天然免疫 CSRF。
4. **KV 用量监控**：`scan` 与后台列表都会消耗 KV 读；量大时建议接 Workers Analytics。

