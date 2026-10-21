---
demandId: OPC-INTEGRATION-001
repositoryId: code-opc
document: review
status: draft
---

# code-opc 独立审查记录

reviewer 路径：当前 Agent 的隔离只读 subagent（用户 2026-10-21 选择）。

## 第一轮（2026-10-21，指纹：HEAD=2f247cc9…、porcelain 清单哈希 66a3c912…、tracked diff c593356b…、未跟踪聚合 3e8627a0…）

结论：**CHANGES_REQUIRED**。

阻断/高：
- C-1 企业登录 begin/exchange 注册在 Auth 保护组内，真实路由 401，登录主链路端到端不可达（测试经 testutil 绕过路由未暴露）。
- C-2 企业任务不可领取：daemon 不声明 enterprise-protocol-v1 能力、不携带租约；CreateGrant/RenewGrant 无调用方（租约签发未接线）；叠加 C05 企业不写 daemon PAT，永久 claim-403-requeue 死循环。
- C-3 BND-161 被攻破：daemon 装配无条件把本机 MCP 合回（runtime_mcp.go），企业任务带整机个人 MCP 启动；managed_mcp_status 字段在 daemon Task 丢失。
- C-4 撤权到不了 code 后端：InvalidateEnterpriseVersion 无调用方；DB 版本只在 exchange 写；PAT 分支不比版本；已建 WS 连接撤权不关。
中：M-5 技能 resolve 无 claim 发放交集校验（confused deputy，用服务身份下载）；M-6 exchange 镜像空间一律 owner（平台角色未投影）。
轻：m-7 发起人门禁在落库后执行；codex 注释失真；PKCE verifier 生成后未用（平台 code-exchange 未校验 verifier）。

已验证通过：迁移/sqlc、伪造头剥离、续期重锚、租约验签与绑定、resolver 五元组与 pin、三 CLI 矩阵、桌面 vault/回环/teardown 等（详表见审查输出）。

处置：platform 补 code-exchange verifier 校验与 Space 角色投影；code 修 C-1~C-4、M-5/M-6、m-7。修复后重验并重审。

## 第二轮（2026-10-21，差异重审，新指纹 7705b2c0…）

结论：**CHANGES_REQUIRED**。C-1/C-3/M-6 修复到位；**N-1 阻断**：internal/platform 测试编译失败（CodeExchange 三参签名未适配 client_test.go——修复后轮该包从未跑过）；**N-2 高**：daemon 侧租约续期循环零实现（RenewEnterpriseLease 无调用方，BND-102/BND-110 T+45s 未交付）；**M-5 未修复**（声称的交集校验代码中不存在）；**N-3 中**：claim 技能清单失去租户收窄（读 claim 请求头租约恒空 → 全租户发放）；N-4 版本写入无单调守卫（旧版本重放可复活会话）；N-5 DaemonAuth PAT 不盖版本 + enterprise_revoked 帧客户端无处理。
处置：修复代理处理 N-1~N-5 与 M-5，完成后重审差异。

## 第三轮（2026-10-21，差异重审，指纹 f1325471…）

结论：**READY_FOR_HUMAN_REVIEW**。N-1~N-5/M-5 逐条核对修复到位（租约生命周期与 BND-110 code 段端到端闭环）；reviewer 独立复跑全绿。残余：R3-1 续期器零值过期角落 fail-open（主会话修）；R3-2 WS 的 PAT 连接未穿版本快照（纵深缺口，记 backlog，不阻断）。
