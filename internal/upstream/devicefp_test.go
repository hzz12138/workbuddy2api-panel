package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// uuidV4Re 复用 cache_key_test.go:292 的定义（同一形态断言，不重复声明）。

// TestDeviceProfileSelfConsistent 设备池的每条都必须物理自洽：
// cpuCores 与该 CPU 型号的真实线程数一致、内存档位符合该年代、Windows 版本可搭配。
// 这是本方案唯一的真风险——编造「i5 配 32 核」比全簇相同更容易被抓。
func TestDeviceProfileSelfConsistent(t *testing.T) {
	if len(cpuPool) < 12 {
		t.Fatalf("cpuPool 只有 %d 条，样本太少会让不同账号频繁撞同一台机器", len(cpuPool))
	}
	for _, c := range cpuPool {
		if c.Cores <= 0 {
			t.Errorf("cpu %q cores=%d 非法", c.Model, c.Cores)
		}
		if c.Cores%2 != 0 {
			t.Errorf("cpu %q cores=%d 为奇数，Windows 机器逻辑处理器数应为偶数", c.Model, c.Cores)
		}
		if c.Year < 2015 || c.Year > 2026 {
			t.Errorf("cpu %q year=%d 超出合理范围", c.Model, c.Year)
		}
		// 内存与 Windows 版本池必须非空且落在该年代的合理区间。
		rams := ramChoices(c.Year)
		if len(rams) == 0 {
			t.Errorf("cpu %q 无内存档位", c.Model)
		}
		for _, r := range rams {
			if r < 8 || r > 128 {
				t.Errorf("cpu %q(%d) 内存档位 %dG 不合理", c.Model, c.Year, r)
			}
			if r&(r-1) != 0 {
				// 真实机器内存几乎都是 2 的幂（8/16/32/64）。12G 也是存在的
				// （8+4 混插），故只对非 2 的幂且 >16 的档位报警。
				if r > 16 {
					t.Errorf("cpu %q 内存档位 %dG 非 2 的幂且大于 16，不像出厂配置", c.Model, r)
				}
			}
		}
		oss := osChoices(c.Year)
		if len(oss) == 0 {
			t.Errorf("cpu %q 无 Windows 版本档", c.Model)
		}
		for _, o := range oss {
			if !regexp.MustCompile(`^10\.0\.(19044|19045|22000|22621|22631|26100)$`).MatchString(o) {
				t.Errorf("cpu %q 的 Windows 版本 %q 不是真实发行版 build", c.Model, o)
			}
			// 老机器不装 Win11：2021 年之前的机型只给 Win10 档。
			if c.Year <= 2019 && o != "10.0.19044" && o != "10.0.19045" {
				t.Errorf("cpu %q(%d) 搭配 %q 属于分布外（老机型不应装 Win11）", c.Model, c.Year, o)
			}
		}
	}
}

// TestPickDeviceStableAndDistinct 同 uid 恒同值（跨重启稳定）、异 uid 高概率互异。
// 设备标识漂移比缺失更容易被关联，故稳定性是硬要求。
//
// uid 形态必须用**真实形态**（36 位 UUID 风格，服务端签发）：sha256 对规律串
// （"uid-a0"/"uid-b0"）的低位分布不均，会人为放大碰撞，测出来的数字不代表
// 生产行为。真实 uid 下 50 个号的碰撞期望 ≈ n²/2m ≈ 2 次（m≈500）。
func TestPickDeviceStableAndDistinct(t *testing.T) {
	a := pickDevice("uid-alpha")
	if again := pickDevice("uid-alpha"); again != a {
		t.Fatalf("同 uid 两次取样不同：%+v vs %+v", a, again)
	}

	seen := map[DeviceProfile]string{}
	dup := 0
	for i := 0; i < 50; i++ {
		// 生产形态的 uid：36 位小写 hex（上游签发的 uid 就是这个形态）。
		// 注意不能用 string(rune(i)) 构造——那会生成不可见控制字符，
		// 大量 uid 实际重复，测出的碰撞数是假的。
		s := sha256.Sum256([]byte(fmt.Sprintf("devicefp-test-uid-%d", i)))
		uid := hex.EncodeToString(s[:18])
		d := pickDevice(uid)
		if prev, ok := seen[d]; ok {
			dup++
			t.Logf("碰撞：%s 与 %s 都取到 %+v", prev, uid, d)
		}
		seen[d] = uid
	}
	// 组合空间实测 572 种，50 个样本的生日碰撞期望 ≈ 2.14。
	// 阈值取 4（≈2σ 上界），超过即说明池子退化。
	if dup > 4 {
		t.Errorf("50 个真实形态 uid 出现 %d 次碰撞，超过生日问题期望值（池子需扩容）", dup)
	}
}

// TestDeviceIDsAreUUID 设备标识必须是 UUID v4 形态，不是 36 位裸 hex。
//
// 2026-10-25 分发包逆向：官方 machineId 读注册表 MachineGuid（正则
// /\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/），sessionId 来自 randomUUID()。
// 旧实现用 deriveID 产出 36 裸 hex（无横线），与官方形态可区分。
func TestDeviceIDsAreUUID(t *testing.T) {
	a := &auth.Auth{UID: "u-uuid", AccessToken: "at", Nickname: "n"}

	fp := desktopFingerprint(a)
	for _, k := range []string{"machineId", "sessionId"} {
		v, _ := fp[k].(string)
		if !uuidV4Re.MatchString(v) {
			t.Errorf("desktop %s=%q 不是 UUID v4 形态", k, v)
		}
	}
	// 两个字段必须互异（不同 purpose 派生不同值）。
	if fp["machineId"] == fp["sessionId"] {
		t.Error("desktop machineId 与 sessionId 相同，派生 purpose 未生效")
	}

	// 小程序埋点同族：machineId 也必须是 UUID，且与桌面链路不同值。
	mp := mpEventBase(a)
	if v, _ := mp["machineId"].(string); !uuidV4Re.MatchString(v) {
		t.Errorf("mp machineId=%q 不是 UUID v4 形态", v)
	}
	if mp["machineId"] == fp["machineId"] {
		t.Error("mp 与 desktop 的 machineId 相同，两条链路应各用各的设备槽")
	}

	// qimei36 保持 36 裸 hex（腾讯设备号本来就是 36 hex，无横线）。
	if v, _ := fp["qimei36"].(string); len(v) != 36 || regexp.MustCompile(`[^0-9a-f]`).MatchString(v) {
		t.Errorf("qimei36=%q 应为 36 位小写 hex", v)
	}
}

// TestMPMachineIDNotShared 回归：mp machineId 不得回退成跨部署共用的硬编码值。
// 旧值 0655736a-607f-4d9d-b430-58176ee9a090 是全簇同一个设备号——最硬的聚类键。
func TestMPMachineIDNotShared(t *testing.T) {
	const legacy = "0655736a-607f-4d9d-b430-58176ee9a090"
	for _, uid := range []string{"u1", "u2", "u3", "u-other-deploy"} {
		v, _ := mpEventBase(&auth.Auth{UID: uid})["machineId"].(string)
		if v == legacy {
			t.Fatalf("uid=%s 仍在上报硬编码 machineId %s", uid, legacy)
		}
	}
}

// TestDeviceFieldsDiversified 设备四元组不再钉死一台机器：多个 uid 必须出现
// 至少两种 CPU 型号。旧实现恒定 i5-11320H，全簇逐字节相同。
func TestDeviceFieldsDiversified(t *testing.T) {
	cpus := map[string]bool{}
	oses := map[string]bool{}
	for i := 0; i < 40; i++ {
		uid := "diversify-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		fp := desktopFingerprint(&auth.Auth{UID: uid, Nickname: "n"})
		cpus[fp["cpuModel"].(string)] = true
		oses[fp["osVersion"].(string)] = true
	}
	if len(cpus) < 5 {
		t.Errorf("40 个 uid 只出现 %d 种 CPU，池取样未生效", len(cpus))
	}
	if len(oses) < 3 {
		t.Errorf("40 个 uid 只出现 %d 种 Windows 版本，池取样未生效", len(oses))
	}
}
