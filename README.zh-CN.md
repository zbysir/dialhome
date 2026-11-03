# dialhome

[English](README.md) · 简体中文

**从哪儿都能连回你自己的机器** —— 一个只转发密文的云端中继。

你的电脑（跑着 [herdr-web](https://github.com/zbysir/herdr-web) 或 gerdr）主动连上一台 VPS 上的 dialhome；
手机打开 `https://mac.example.com`，dialhome 读一眼 TLS 握手里的主机名（SNI），把整条连接**原样**转给那台电脑。

- **中继看不到内容。** TLS 在你自己的机器上终止，页面也是你的机器发的。dialhome 手里没有证书私钥、
  没有你的登录凭据；VPS 整台被拿下，也只能断你的网。
- **加一台机器一条命令。** 后台出一个邀请码，在那台机器上 `herdr-web relay join …`（gerdr 在「设置 → 远程访问」里填，或者 `gerdr remote join`）。
- **每台机器自己的身份。** Ed25519 密钥对，中继只存公钥；没有共享 token。
- **网页后台**：管理员用 passkey 登录，出邀请码、看谁在线、删主机。

和 frp / ngrok / Cloudflare Tunnel 的区别：后两者默认在它们的服务器上解开 TLS；frp 的 https 透传和这里
是同一个形状，dialhome 多做的是按主机的身份、一条命令加入、和这个后台。为什么非这样不可，见
[docs/DESIGN.md](docs/DESIGN.md) §1。

## 部署（VPS 上）

```sh
docker run -d --name dialhome --restart unless-stopped \
  -p 443:443 -v dialhome-data:/data \
  -e DIALHOME_DOMAIN=relay.example.com \
  ghcr.io/zbysir/dialhome:latest
```

DNS：`relay.example.com`（后台 + 主机连进来的地方）和每台主机的名字（`mac.example.com`，或者一条
`*.h.example.com` 通配）都 A 记录指到这台 VPS。控制面的证书 dialhome 自己用 TLS-ALPN-01 签。

然后注册管理员 passkey：

```sh
docker exec dialhome dialhome admin init
# 在浏览器里打开它印出来的 https://relay.example.com/#setup=… ，按一下 Face ID / 指纹
```

之后就在 `https://relay.example.com/` 后台里邀请主机。命令行也能做同样的事：
`dialhome invite <主机名>` / `dialhome hosts` / `dialhome remove <主机名>`。

### 配置（环境变量）

| 变量 | 说明 |
|---|---|
| `DIALHOME_DOMAIN` | 中继自己的域名（后台 + 控制面），必填 |
| `DIALHOME_LISTEN` | 监听地址，默认 `:443` |
| `DIALHOME_DIR` | 数据目录，默认 `~/.dialhome`（镜像里是 `/data`） |
| `DIALHOME_TLS_CERT` / `DIALHOME_TLS_KEY` | 控制面的证书；不给就自己签 |
| `DIALHOME_ACME_EMAIL` | 自己签证书时的邮箱（可空） |
| `DIALHOME_CONTROL_LISTEN` | 前面已经有 Traefik / nginx 占着 443 时：控制面单独听一个明文口，由前面那层终止 TLS 再转进来 |
| `DIALHOME_PROXY_PROTOCOL` | `=1`：SNI 那个口上的连接必须带 PROXY 头（前面那层透传时加），不然按 IP 的限速全算到反代头上 |

改名之前的 `HERDR_RELAY_*` 照样认（两个都给时新的优先），老的 `~/.herdr-relay` 目录在、新的不在时沿用老的。

## 主机这一侧（给别的项目用）

主机侧是一个 Go 包，herdr-web 和 gerdr 都直接 import：

```go
import "github.com/zbysir/dialhome/relay"

relay.Join(ctx, relay.HostConfig{URL: "https://relay.example.com", Host: "mac.example.com", Dir: keyDir}, inviteCode)
tn, _ := relay.Start(relay.HostConfig{...}) // tn 是一个 net.Listener，Accept 出来的是手机连过来的 TLS 字节流
```

隧道出来的连接要当成**公网**的来处理（对端地址是中继说的，只能拿来限速），TLS 由你自己终止。

## 开发

```sh
make build   # 前端打包 + go build → ./dialhome
make test    # go vet + go test + 前端 typecheck
make dev     # 前端热更新（/api 转到 127.0.0.1:7900）
```

发版：`make release V=v0.1.0` 推 tag，GitHub Actions 出二进制和 `ghcr.io/zbysir/dialhome` 镜像。

## License

MIT
