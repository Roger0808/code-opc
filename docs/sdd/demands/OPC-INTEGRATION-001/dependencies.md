# OPC-INTEGRATION-001 dependencies（code-opc 只读投影）

> 本文件为主仓权威内容的只读投影，不得在参与仓独立修改。

# 依赖（code-opc）

- platform-opc：先于 code 部署（exchange/grants/skills/invalidate 端点 + 服务 token + 租约 HMAC 密钥配对 PLATFORM_LEASE_HMAC_SECRET）。
- knowledge-opc：经 platform 间接依赖。
- 桌面：desktop.json platformUrl；未配置企业入口不显示（fail-closed）。
