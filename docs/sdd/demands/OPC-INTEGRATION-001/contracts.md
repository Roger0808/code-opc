# OPC-INTEGRATION-001 contracts（code-opc 只读投影）

> 本文件为主仓权威内容的只读投影，不得在参与仓独立修改。

# 跨仓契约（code-opc 视角）

- → platform：POST /integration/v1/auth/authorize（begin 代理，redirect_uri 回环）；code-exchange（code_verifier 必传）；POST /internal/grants 租约签发（响应 enterprise_lease）；renew 端点 X-Enterprise-Lease（键 task_id/runtime_id/tenant_id）；GET /internal/skills；POST /api/internal/enterprise/invalidate（撤权推送，服务 token）。
- → knowledge：经 platform 转发，不直连。
- 企业语义：ent_sid/ent_ver 纪元（JWT/PAT/WS）；企业任务 failed-closed MCP；三 CLI 受管参数；claim 发放技能集合交集校验（pin=skillbundle manifest hash + X-SHA256 字节交叉验）。
