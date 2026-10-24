// devicefp.go 设备指纹取值池：把「全簇同一台机器」换成「官方分布里的一台真机」。
//
// 为什么需要池而不是常量：2026-10-25 对 WorkBuddy 5.8.3 国内版分发包
// （C:\Software\WorkBuddy\resources\app.asar）的只读逆向确认，官方的设备字段是
// **运行时读本机**，不是常量。两处独立实现逻辑一致：
//
//	main/main-bootstrap.js  getContext():
//	    osVersion:  node_os.release()
//	    cpuModel:   node_os.cpus()[0]?.model ?? ''
//	    cpuCores:   node_os.cpus().length
//	    memorySize: Math.round(node_os.totalmem() / 1024 / 1024 / 1024)
//	main/module-base.js     OSEventProcessor.process():
//	    r.osVersion = os.release(); let D = os.cpus();
//	    r.cpuModel = D[0].model; r.cpuCores = D.length;
//	    r.memorySize = Math.round(os.totalmem() / 1024 / 1024 / 1024)
//
// 于是「所有部署都报同一块 i5-11320H / 8 核 / 16G / 10.0.28000」在官方分布里是
// 概率为零的事件——不是「像不像官方」的问题，是「你属于哪一批」的问题。
//
// 三条纪律（与 docs/fingerprint-diversification.md 一致）：
//
//  1. **物理自洽**：池里每条都必须是真实机型。cpuCores 必须等于该 CPU 的
//     **逻辑处理器数**（os.cpus().length 是含超线程/大小核的线程数，不是物理核），
//     memorySize 必须与该机型常见配置相符。编造「i5 配 32 核」是分布外样本，
//     比全簇相同更容易被抓。
//  2. **跨重启稳定**：同 uid 恒得同一台机器（纯 hash 派生，无状态、不落盘）。
//     设备标识漂移比缺失更容易被关联。
//  3. **只落在官方真实出现过的取值上**：Windows NT 10.0.x 的每个版本号都对应
//     一个真实发行版，不编造。
//
// 与 deriveID 的分工（重要）：deriveID 产出 **36 位裸 hex**，那正好是 qimei36
// 的形态（腾讯设备号本来就是 36 hex 无横线），但对 machineId/sessionId 是**错的**
// ——官方那两处是 UUID（sidecar-manager 的 machineIdSync 读注册表 MachineGuid，
// 正则 /\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/；sessionId 是 randomUUID()）。故：
//
//	machineId / sessionId → buildStableUUID（带横线的 UUID v4 形态）
//	qimei36               → deriveID（36 裸 hex，形态本来就是对的）
package upstream

import (
	"crypto/sha256"
	"encoding/binary"
)

// DeviceProfile 一台真实 Windows 机器的自洽四元组（对应 /v2/report 的
// osVersion / cpuModel / cpuCores / memorySize 四个字段）。
type DeviceProfile struct {
	OSVersion  string // node_os.release()：Windows NT 10.0.<build>
	CPUModel   string // node_os.cpus()[0].model
	CPUCores   int    // node_os.cpus().length：逻辑处理器数
	MemorySize int    // GB，Math.round(totalmem/1GB)
}

// cpuSpec 真实 CPU 型号。Cores 必须等于该型号的**线程数**（os.cpus().length），
// Year 决定可搭配的 Windows 版本与内存档位（老机器不会装 24H2，也不会配 64G）。
type cpuSpec struct {
	Model string
	Cores int
	Year  int
}

// cpuPool 真实在售/在用的 Windows 机器 CPU。每条都标注了核数与发布年份，
// Cores 一律填线程数（含超线程 / Intel 大小核），与 os.cpus().length 口径一致。
//
// 规模要求：组合空间 = CPU 池 × 内存档 × 系统档。50 个账号的生日碰撞期望值
// ≈ n²/2m，池子 20 条 × 4 档 × 4 档 ≈ 320 时 50 个号预期撞 4 次（实测 7 次，
// 因为档位数不均匀）。扩到 32 条后组合空间 ≈ 500+，同部署 6 个号撞同一台的
// 概率 < 1%，50 个号的碰撞期望降到 2 次以内。
var cpuPool = []cpuSpec{
	// 2017-2019：4C8T 低压为主
	{"Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz", 4, 2017},
	{"Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", 8, 2017},
	{"Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz", 8, 2017},
	{"Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz", 12, 2018},
	{"Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz", 8, 2018},
	{"Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz", 8, 2019},
	{"Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz", 12, 2019},
	{"Intel(R) Core(TM) i7-10710U CPU @ 1.10GHz", 12, 2019},
	// 2020-2021：4C8T / 6C12T / 8C16T 混布
	{"Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz", 12, 2020},
	{"Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz", 12, 2020},
	{"Intel(R) Core(TM) i7-1165G7 @ 2.80GHz", 8, 2020},
	{"Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz", 8, 2020},
	{"11th Gen Intel(R) Core(TM) i5-11320H @ 3.20GHz", 8, 2021},
	{"11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz", 8, 2021},
	{"11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz", 8, 2021},
	{"AMD Ryzen 5 5600H with Radeon Graphics", 12, 2021},
	{"AMD Ryzen 7 5800H with Radeon Graphics", 16, 2021},
	{"AMD Ryzen 5 4600H with Radeon Graphics", 12, 2020},
	// 2022-2023：Intel 大小核（P+E）线程数普遍 > 物理核
	{"12th Gen Intel(R) Core(TM) i5-12450H", 12, 2022},
	{"12th Gen Intel(R) Core(TM) i5-12500H", 16, 2022},
	{"12th Gen Intel(R) Core(TM) i7-12700H", 20, 2022},
	{"12th Gen Intel(R) Core(TM) i3-1215U", 8, 2022},
	{"12th Gen Intel(R) Core(TM) i7-1260P", 16, 2022},
	{"12th Gen Intel(R) Core(TM) i9-12900H", 20, 2022},
	{"13th Gen Intel(R) Core(TM) i5-13500H", 16, 2023},
	{"13th Gen Intel(R) Core(TM) i7-13620H", 16, 2023},
	{"13th Gen Intel(R) Core(TM) i9-13900H", 20, 2023},
	{"AMD Ryzen 5 7530U with Radeon Graphics", 12, 2023},
	{"AMD Ryzen 7 7840HS w/ Radeon 780M Graphics", 16, 2023},
	{"AMD Ryzen 9 7945HX with Radeon Graphics", 32, 2023},
	{"AMD Ryzen 7 7735HS with Radeon Graphics", 16, 2023},
	// 2024：14 代与 Ryzen 8000
	{"14th Gen Intel(R) Core(TM) i7-14650HX", 24, 2024},
	{"14th Gen Intel(R) Core(TM) i5-14500HX", 20, 2024},
	{"AMD Ryzen 7 8845HS w/ Radeon 780M Graphics", 16, 2024},
	{"Intel(R) Core(TM) Ultra 7 155H", 22, 2024},
}

// ramChoices 按 CPU 年份给出合理的内存档位（GB）。老机器配 64G、新机器配 4G
// 都不符合真实分布，故分档而不是全池自由取。
func ramChoices(year int) []int {
	switch {
	case year <= 2019:
		return []int{8, 12, 16}
	case year <= 2021:
		return []int{8, 16, 16, 32}
	default:
		return []int{16, 16, 32, 32, 64}
	}
}

// osChoices 按 CPU 年份给出可搭配的 Windows 内部版本号（node_os.release() 的
// 第三段）。每个值都对应一个真实发行版：
//
//	19044 = Windows 10 21H2      19045 = Windows 10 22H2
//	22000 = Windows 11 21H2      22621 = Windows 11 22H2
//	22631 = Windows 11 23H2      26100 = Windows 11 24H2
//
// 2017 年的机器装 24H2 属于分布外，故老机型只给 Win10 档。
func osChoices(year int) []string {
	switch {
	case year <= 2019:
		return []string{"10.0.19044", "10.0.19045", "10.0.19045"}
	case year <= 2021:
		return []string{"10.0.19045", "10.0.22000", "10.0.22621", "10.0.22621"}
	default:
		return []string{"10.0.22621", "10.0.22631", "10.0.22631", "10.0.26100"}
	}
}

// pickDevice 按 uid 稳定派生一台真实机器。同 uid 恒同值、异 uid 高概率互异。
//
// 三段独立取样（CPU / 内存 / Windows 版本各用一个 hash 段），使组合空间
// ≈ 19 × 4~5 × 3~4 ≈ 300 种，同部署内 6 个账号撞同一台的概率 < 2%。
// 若三者共用一段 hash，组合会退化成「按 CPU 定死一切」，池子实际只有 19 种。
func pickDevice(uid string) DeviceProfile {
	sum := sha256.Sum256([]byte("wb2a:device:" + uid))
	cpu := cpuPool[binary.BigEndian.Uint32(sum[0:4])%uint32(len(cpuPool))]
	rams := ramChoices(cpu.Year)
	ram := rams[binary.BigEndian.Uint32(sum[4:8])%uint32(len(rams))]
	oss := osChoices(cpu.Year)
	osv := oss[binary.BigEndian.Uint32(sum[8:12])%uint32(len(oss))]
	return DeviceProfile{
		OSVersion:  osv,
		CPUModel:   cpu.Model,
		CPUCores:   cpu.Cores,
		MemorySize: ram,
	}
}

// stableDeviceUUID 按 (uid, purpose) 派生 UUID v4 形态的 36 字符设备标识。
//
// 直接复用 cache_key.go 的 buildStableUUID：它已按 RFC 4122 置位第 7 字节 0x40
// （version 4）与第 9 字节 0x80（variant），形态与真 UUID 完全一致。
// 这里只是给「设备域」一个固定 purpose，与 X-Conversation-ID 的派生输入互不碰撞
// （后者的输入是 uid|conversation，本函数是 uid||purpose）。
func stableDeviceUUID(uid, purpose string) string {
	return buildStableUUID(uid, "", purpose)
}
