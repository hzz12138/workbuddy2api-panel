package main

import (
	"strings"
	"testing"
)

// TestAppRepositoryPointsToOwnRepo 一键更新的 Release 来源必须指回本仓。
//
// 这条断言存在的理由不是「代码风格」：updater 下载的是 `appRepository` 那个仓库
// Release 里的 wb2api-panel-<ver>-<goos>-<goarch>.zip，并直接把**正在运行的二进制**
// 换掉（replaceBinaryWithRollback，回滚只留一个 .old，健康检查通过即删）。本仓带
// 独占改动（设备指纹按账号取样、头族按真机抓包对齐、模型锁池视图等），一旦指向上游，
// 一次误触或一次定时自动更新就会把这些改动全部覆盖、且不可逆。
//
// 判据刻意只挡「上游那个仓」而不是「必须等于本仓名字」：CI 用
// `-X main.appRepository=${GITHUB_REPOSITORY}` 注入，fork / 改名 / 私有部署都是
// 合法形态；本地构建回落常量时，唯一不可接受的值就是上游作者的仓库。
func TestAppRepositoryPointsToOwnRepo(t *testing.T) {
	if appRepository == "" {
		t.Fatal("appRepository 不能为空：updater 会回落到上游作者的仓库")
	}
	if strings.EqualFold(appRepository, upstreamRepo) {
		t.Fatalf("appRepository=%q 指向上游作者的仓库：一次一键更新（或定时自动更新）就会用上游构建覆盖本分支的独占改动。改成本仓，或由 CI 注入 GITHUB_REPOSITORY",
			appRepository)
	}
	// 形态：owner/repo，无前缀、无 .git 后缀、无 URL scheme。
	parts := strings.Split(appRepository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Fatalf("appRepository=%q 不是 owner/repo 形态", appRepository)
	}
	if strings.Contains(appRepository, "://") || strings.HasSuffix(appRepository, ".git") {
		t.Fatalf("appRepository=%q 应只写 owner/repo（shell-out 到 api.github.com 的路径参数）", appRepository)
	}
}

// TestAppVersionDefaultsToDev 本地构建不注入版本，面板显示 dev。
//
// 版本号只有 CI 打标签发版时才注入（AGENTS.md：形如 2026.9.26.711，不跟 1.x）。
// 本地若把 appVersion 手改成时间版本号，updater 会以「当前版本」去和 Release 列表
// 比较，本地跑的其实是未发布的改动、却以为自己在跑那个版本——排查时会误导。
func TestAppVersionDefaultsToDev(t *testing.T) {
	if appVersion != "dev" {
		t.Fatalf("appVersion=%q：源码里应保持 dev，版本号只由 CI 用 -X main.appVersion 注入", appVersion)
	}
}
