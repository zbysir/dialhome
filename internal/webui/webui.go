// Package webui 把管理后台的前端产物嵌进二进制。dist 由 `make web` 从 web/dist 拷进来
// （入库的只有 .gitkeep —— 空目录上 go:embed 会报错，新 clone 连 go build 都过不了）。
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS 返回前端产物；还没 build 过（只有 .gitkeep）时返回 nil，后台只剩 /api/。
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
