@/Users/nanfm/.codex/RTK.md

- 开发 macOS CLI 时保持 mihomo 可用：当前 agent 联网依赖它；不得停止、重启或覆写其配置，也不得接管默认路由或全局 DNS。
- mihomo 全局覆写的 `dns.fake-ip-filter` 保留 `'+.cczu.edu.cn'`（见 `config/mihomo-override.yaml`）；这仅排除 Fake IP，校内分流与 VPN 网关直连仍需单独处理。
- VPN 仅配置校内所需路由和 DNS；断开或失败时仅清理自身创建的配置。
