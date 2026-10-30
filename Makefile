# dialhome：一个 Go 二进制，管理后台的前端（web/）打包后嵌在里面。
WEBDIST := internal/webui/dist

.PHONY: build web test dev clean release release-dry

build: web
	CGO_ENABLED=0 go build -o dialhome ./cmd/dialhome

# rm -rf 会把入库的 .gitkeep 一起删掉，而它是承重的（空目录上 go:embed 报错），所以拷完写回来
web:
	cd web && npm ci && npm run build
	rm -rf $(WEBDIST)
	cp -r web/dist $(WEBDIST)
	touch $(WEBDIST)/.gitkeep

test:
	go vet ./...
	go test ./...
	cd web && npm run typecheck

# 前端热更新：另开一个终端跑中继，控制面听本机明文口（vite 把 /api 转过去）
dev:
	cd web && npm run dev

clean:
	rm -rf dialhome dist $(WEBDIST)
	mkdir -p $(WEBDIST) && touch $(WEBDIST)/.gitkeep

release-dry:
	goreleaser release --snapshot --clean

# make release V=v0.1.0：打 tag 推到 GitHub，剩下的 Actions 干（二进制 + ghcr 镜像）
release:
	@test -n "$(V)" || (echo "用法：make release V=v0.1.0" && exit 1)
	@test -z "$$(git status --porcelain)" || (echo "工作区不干净" && exit 1)
	git tag $(V)
	git push origin $(V)
