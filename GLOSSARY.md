# CCZU VPN

为常州大学用户提供校内资源访问的 VPN 客户端。

## Language

**macOS CLI 客户端**：
供用户或 agent 在 macOS 终端中控制 CCZU VPN 的工具，支持后台运行，是本仓库首阶段的交付形态。
_Avoid_: macOS 图形客户端

**校园账号**：
用于登录学校 WebVPN 的统一身份认证账号。
_Avoid_: 系统管理员账号、sudo 账号

**VPN 后台服务**：
独立于终端会话运行、接受 CLI 控制的本机服务；服务运行不代表 VPN 已连接。

**VPN 连接**：
客户端与学校 VPN 网关之间用于访问校内资源的活动隧道。
