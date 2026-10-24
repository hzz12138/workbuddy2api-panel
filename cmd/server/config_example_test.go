package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConfigExampleIsValid 守卫仓库根目录的 config.example.json 是合法 JSON、
// 且能被 Config 结构解析（键名拼错/漏逗号都不会被编译期发现）。
//
// 来由：PR #55 加 features.sanitize_brand_scope 时漏了上一行的逗号，
// 文件变成非法 JSON 而 CI 全绿——因为它只在运行时被 `cp config.example.json
// config.json` 的人读到，报错现场离提交很远。这个测试把现场挪回 CI。
func TestConfigExampleIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 %s: %v", path, err)
	}
	if !json.Valid(raw) {
		t.Fatalf("%s 不是合法 JSON", path)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("%s 无法解析为 Config: %v", path, err)
	}
	// 新增的对外配置项必须在示例里可见，否则用户只能从 README 反推。
	if c.Features.SanitizeBrandScope != "all" {
		t.Errorf("features.sanitize_brand_scope 示例值应为 all，得到 %q", c.Features.SanitizeBrandScope)
	}
	if !c.Features.SanitizeBlacklistFingerprints {
		t.Error("features.sanitize_blacklist_fingerprints 示例值应为 true")
	}
	if c.Pool.ModelFallback == nil {
		t.Error("pool.model_fallback 示例应存在（空对象即可），否则用户不知道有这张表")
	}
}

// TestScheduleJitterDefaultsOn 时序抖动必须默认开启。
//
// 为什么钉住：jitter_minutes / account_spread_minutes 为 0 时，所有账号在同一秒
// 触发同一动作——上游不需要任何内容指纹，只看时间戳分布就能把整个部署聚成一批。
// 这两项长期是 0（见 docs/fingerprint-diversification.md 的 F1/F2），等于默认部署
// 就是「整点全池同秒」。默认值必须非 0，且示例文件与 Default() 必须一致，
// 否则 `cp config.example.json config.json` 的部署会退回整点。
func TestScheduleJitterDefaultsOn(t *testing.T) {
	d := Default()
	if d.Schedule.JitterMinutes <= 0 {
		t.Errorf("Default().Schedule.JitterMinutes = %d，必须 > 0（0 = 精确整点，全池同秒）", d.Schedule.JitterMinutes)
	}
	if d.Schedule.AccountSpreadMinutes <= 0 {
		t.Errorf("Default().Schedule.AccountSpreadMinutes = %d，必须 > 0（0 = 同一秒打全池）", d.Schedule.AccountSpreadMinutes)
	}
	if d.Schedule.AccountSpreadMinGapSeconds <= 0 {
		t.Errorf("Default().Schedule.AccountSpreadMinGapSeconds = %d，必须 > 0（0 = 只做随机，允许两号同秒）",
			d.Schedule.AccountSpreadMinGapSeconds)
	}
	// 抖动窗口必须小于最小触发间隔（checkin/travel 两档 12h = 720min），
	// 否则相邻两档的窗口会重叠，反而制造出新的固定形状。
	if d.Schedule.JitterMinutes >= 720 {
		t.Errorf("JitterMinutes = %d 不小于最小触发间隔 720min，会把相邻档次的窗口叠在一起",
			d.Schedule.JitterMinutes)
	}
	// 摊开窗口同理：账号数 × min_gap 超过窗口时尾部会被钳到同一秒
	// （spread.go 的已知 shortcut），故窗口必须留出足够余量。
	if d.Schedule.AccountSpreadMinutes >= 720 {
		t.Errorf("AccountSpreadMinutes = %d 不小于最小触发间隔 720min", d.Schedule.AccountSpreadMinutes)
	}
}

// TestConfigExampleScheduleMatchesDefault 示例文件的抖动取值必须与 Default() 一致。
// 两处口径漂移会让「用示例起步」和「空配置起步」的部署落在不同的时间形状上。
func TestConfigExampleScheduleMatchesDefault(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 %s: %v", path, err)
	}
	var ex Config
	if err := json.Unmarshal(raw, &ex); err != nil {
		t.Fatalf("%s 无法解析为 Config: %v", path, err)
	}
	d := Default()
	if ex.Schedule.JitterMinutes != d.Schedule.JitterMinutes {
		t.Errorf("config.example.json jitter_minutes = %d，Default() = %d，两处必须一致",
			ex.Schedule.JitterMinutes, d.Schedule.JitterMinutes)
	}
	if ex.Schedule.AccountSpreadMinutes != d.Schedule.AccountSpreadMinutes {
		t.Errorf("config.example.json account_spread_minutes = %d，Default() = %d，两处必须一致",
			ex.Schedule.AccountSpreadMinutes, d.Schedule.AccountSpreadMinutes)
	}
	if ex.Schedule.AccountSpreadMinGapSeconds != d.Schedule.AccountSpreadMinGapSeconds {
		t.Errorf("config.example.json account_spread_min_gap_seconds = %d，Default() = %d，两处必须一致",
			ex.Schedule.AccountSpreadMinGapSeconds, d.Schedule.AccountSpreadMinGapSeconds)
	}
}
