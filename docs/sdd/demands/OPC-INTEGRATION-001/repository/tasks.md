---
demandId: OPC-INTEGRATION-001
repositoryId: code-opc
document: tasks
---

# code-opc 任务（总体 tasks.md 的本仓视图）

基线：main / `2f247cc92f0c5cbf604097e57012b572046d7a6f`；分支 `feature/261020_OPC-INTEGRATION-001_opc-integration`。验证：`make test`、pnpm typecheck/lint/test、Playwright；真实 CLI smoke 需 `agentintegration` + `MULTICA_RUN_REAL_AGENT_SMOKE=1` 与显式授权。

- TASK-C01 企业身份关联与会话纪元（迁移遵守 `CREATE INDEX CONCURRENTLY` 单语句规则）。
- TASK-C02 Daemon 受管任务与失败关闭。
- TASK-C03 企业技能 resolver 固定版本。
- TASK-C04 三 CLI 受管参数。
- TASK-C05 Electron 凭据与回环回调。
- TASK-C06 构建与测试。

前置：platform TASK-P04/P05 完成。
