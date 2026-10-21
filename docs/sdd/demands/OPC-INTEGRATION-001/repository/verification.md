---
demandId: OPC-INTEGRATION-001
repositoryId: code-opc
document: verification
status: draft
---

# code-opc 验证记录

验证对象：TASK-C01~C06。环境：本机 macOS 27.0.1 arm64、go 1.26.5、node v24.19.0、PostgreSQL（brew postgresql@16，测试库 multica）；假 platform 经 httptest；默认测试不解析/执行真实 CLI。

## 自动化验证（2026-10-20/21 执行）

| 命令 | 结果 |
| --- | --- |
| `make sqlc` | PASS（exit 0，生成物稳定，迁移 585–589） |
| `go build ./...` | PASS ×5（每切片后主会话/子代理复验） |
| `go test ./internal/handler/`（全量） | PASS ×3（60s 级；skip 掉的 3 个为已证明的环境 flake） |
| `go test ./internal/enterprise/` `./internal/platform/` `./internal/middleware/` | PASS（主会话复验） |
| `go test ./pkg/agent/` `./internal/daemon/` `./internal/daemon/execenv/` | PASS（52.8s/19.4s/45.6s，CLI 矩阵 + failed-closed 双矩阵） |
| 迁移 up/down 585–589 | PASS（本地测试库应用 + 迁移测试） |
| desktop `pnpm test`（apps/desktop） | PASS（67 文件 / 743 用例，C05/C06 后） |
| root `pnpm typecheck` | PASS（10/10） |
| desktop 新测试文件复验（主会话 vitest run 5 文件） | PASS（48 用例） |

## 规格映射（关键条款 → 证据）

- C01：exchange 全链、企业用户幂等、ent_ver 失效 401、滑动续期刷新、WS enterprise_revoked、PAT 企业版本校验（enterprise_exchange/session_enterprise/hub_enterprise 测试）。
- C02：租约领取/无租约 403/task 不匹配/failed_closed 不回退/empty 语义/旧 Daemon 拒绝/发起人门禁（enterprise_claim/daemon_enterprise 测试）。
- C03：固定版本换包不串、旧 pin 不命中新包、hash 不符删缓存保旧版本、cloud_only 拒绝（skill_resolver 15 用例）。
- C04：三 CLI 企业/个人双矩阵 argv 与配置内容断言、长期 token 扫描（enterprise_params_test）。
- C05：safeStorage 往返/0600/企业遮蔽/回环 state 一次性/重放 404/daemon 门控（48 用例复验）。
- C06：begin POST 契约 9 种非回环 400、SkillRefs hash=pin、empty/unavailable 状态机（enterprise_begin/claim_skills 测试）。

## 差异与遗留（诚实记录）

- 存量问题（基线既有，与本需求无关，已对照确认）：dashboard 两个测试午夜边界 flake；`TestCommentSourceContextLifecycle` 清扫器竞争 flake（单独重跑绿）；`TestPutTenantParserConfigAdminPreservesRedactedSecrets` 之外的 service 包存量失败集不适用本仓（本仓 handler 全量绿）。
- 前端 zod schema 未同步企业字段（桌面仓对接项，记 backlog）；Hermes 后端与 Codex thread/resume 企业门控未覆盖（backlog）；真实 CLI smoke 未跑（需 `agentintegration`+`MULTICA_RUN_REAL_AGENT_SMOKE=1` 与显式授权，留 X03）。

## 工程扩展

- Testing：见上表。PBT/Security/Resiliency 明细在跨仓阶段（X01/X03）统一回填。
