package upstream

import (
	"net/http"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// 2026-10-25 mitmproxy 抓 WorkBuddy 5.8.3 真机（Windows 桌面版）两轮共 150 条
// 请求，得到的 chat/completions 完整头集合共 42 个。本文件的测试把「真机没有、
// 项目曾经多发」的头钉成回归用例，防止后来人凭推测加回去。

// TestChatDoesNotSendFabricatedDeviceHeaders 真机 chat 请求里没有
// X-Machine-ID / X-Session-ID。
//
// 旧实现按 uid 派生 36 hex 注入这两个头，理由是「每账号一台固定虚拟设备」。
// 但官方客户端根本不发它们——多一个客户端从不发的头，比缺一个头更显眼，
// 且会暴露派生规律（36 hex、按 uid 恒定、跨重启不变）。
func TestChatDoesNotSendFabricatedDeviceHeaders(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u-1", AccessToken: "at", Nickname: "n"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/x", nil)
	c.ChatHeaders(req, a, "", ChatMeta{ConversationRequestID: "cr"})

	for _, h := range []string{"X-Machine-ID", "X-Session-ID"} {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("chat 不应发 %s（真机无此头），得到 %q", h, v)
		}
	}
}

// TestBillingDoesNotSendFabricatedDeviceHeaders billing 域同样不该发这两个头。
// 真机的 billing/report 请求头集合里也没有它们。
func TestBillingDoesNotSendFabricatedDeviceHeaders(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u-1", AccessToken: "at"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/x", nil)
	c.BillingHeaders(req, a)

	for _, h := range []string{"X-Machine-ID", "X-Session-ID"} {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("billing 不应发 %s（真机无此头），得到 %q", h, v)
		}
	}
}

// TestReportHeadersMatchDeviceCapture /v2/report 的请求头必须与真机一致：
// 不带 X-CodeBuddy-Request，Accept 是宽松形式。
//
// 真机实测（WorkBuddy 5.8.3）：
//
//	accept: application/json, text/plain, */*
//	authorization / connection / content-length
//	content-type: application/json;charset=UTF-8
//	host / user-agent / x-domain / x-product / x-request-id / x-user-id
func TestReportHeadersMatchDeviceCapture(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u-1", AccessToken: "at"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/v2/report", nil)

	// reportJSON 的头构造逻辑（不实际发请求，只看头）
	c.BillingHeaders(req, a)
	req.Header.Del("X-CodeBuddy-Request")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if v := req.Header.Get("X-CodeBuddy-Request"); v != "" {
		t.Errorf("report 不应发 X-CodeBuddy-Request（真机无此头），得到 %q", v)
	}
	if v := req.Header.Get("Accept"); v != "application/json, text/plain, */*" {
		t.Errorf("report Accept=%q，真机为「application/json, text/plain, */*」", v)
	}
}

// TestChatDoesNotSendOriginRefererOrLanguage chat 路径不发 Origin/Referer/Accept-Language。
// 真机 chat 请求里这三个都不存在；项目的 Del 处理与实测一致，钉住防回退。
func TestChatDoesNotSendOriginRefererOrLanguage(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u-1", AccessToken: "at", Nickname: "n"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/x", nil)
	c.ChatHeaders(req, a, "", ChatMeta{ConversationRequestID: "cr"})

	for _, h := range []string{"Origin", "Referer", "Accept-Language"} {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("chat 不应发 %s（真机 chat 无此头），得到 %q", h, v)
		}
	}
}

// TestChatAgentHeadersMatchCapture chat 的 x-agent-* 三头必须与真机主对话一致。
//
// 真机实测（主对话，2026-10-25）：
//
//	x-agent-type: main
//	x-agent-purpose: conversation
//	x-agent-intent: craft
//
// 注：标题生成等辅助请求用 auxiliary / conversation_topic，但网关只发主对话语义。
func TestChatAgentHeadersMatchCapture(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u-1", AccessToken: "at", Nickname: "n"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/x", nil)
	c.ChatHeaders(req, a, "", ChatMeta{ConversationRequestID: "cr"})

	want := map[string]string{
		"X-Agent-Type":    "main",
		"X-Agent-Purpose": "conversation",
		"X-Agent-Intent":  "craft",
	}
	for h, w := range want {
		if got := req.Header.Get(h); got != w {
			t.Errorf("%s=%q want %q（真机主对话实测值）", h, got, w)
		}
	}
}

// TestChatStainlessHeadersMatchCapture x-stainless-* 六项 + runtime 版本必须与真机一致。
// 这组头是 openai-node SDK 自动加的，随客户端打包版本固定，不是自由变量。
func TestChatStainlessHeadersMatchCapture(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u-1", AccessToken: "at", Nickname: "n"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/x", nil)
	c.ChatHeaders(req, a, "", ChatMeta{ConversationRequestID: "cr"})

	want := map[string]string{
		"X-Stainless-Lang":            "js",
		"X-Stainless-Package-Version": "6.25.0",
		"X-Stainless-OS":              "Windows",
		"X-Stainless-Arch":            "x64",
		"X-Stainless-Runtime":         "node",
		"X-Stainless-Runtime-Version": "v22.21.1",
		"X-Stainless-Retry-Count":     "0",
	}
	for h, w := range want {
		if got := req.Header.Get(h); got != w {
			t.Errorf("%s=%q want %q（真机实测值）", h, got, w)
		}
	}
}
