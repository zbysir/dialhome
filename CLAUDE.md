# dialhome

云端中继：主机（herdr-web / gerdr）主动连上来，手机按 SNI 被原样转给主机。外加一个 passkey 登录的网页后台。
一个 Go 二进制，后台前端（`web/`，React + Vite + Tailwind v4，组件和配色照搬 gerdr 的界面）嵌在里面。

- 设计和「为什么」：[docs/DESIGN.md](docs/DESIGN.md)。**动 `relay/` 之前读 §1**：按「中继这台 VPS 已经被人拿下」设计，
  中继手里不许有任何能登录 / 解密主机的东西。
- `relay/` 是**公开包**，herdr-web 和 gerdr 都 import 它的主机那一半（HostConfig / Join / Start / CleanHost）。
  改它的导出 API 要顾着那两个仓库；**协议一个字节都不能改**（签名串前缀 `herdr-relay/1`、PEM 类型
  `HERDR RELAY KEY`、`/tunnel`、握手三句 JSON、子流头）—— 改了就是所有已注册的主机当场连不上。
- `internal/admin` 是后台的后端，`internal/admin/admin_test.go` 里有一个软件 passkey，整条 WebAuthn 注册 / 登录都在测。
- 环境变量前缀 `DIALHOME_`，老的 `HERDR_RELAY_` 照样认；数据目录老的 `~/.herdr-relay` 照样认。
- 改完跑 `make test`。发版 `make release V=vX.Y.Z`（镜像 `ghcr.io/zbysir/dialhome`）。
- 注释和文档写中文，说清为什么。
