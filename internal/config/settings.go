// Package config cung cấp danh sách quét của Tùy chọn 7 (Kiểm Tra Kích Hoạt Bên
// Thứ Ba).
//
// Ứng dụng dùng DANH SÁCH MẶC ĐỊNH TÍCH HỢP SẴN (các biến DefaultXxx dưới đây) —
// KHÔNG đọc/ghi tệp settings.ini bên ngoài; toàn bộ đóng gói trong một file .exe.
// Bộ phân tích Parse vẫn hiểu định dạng INI (dùng cho kiểm thử và tương thích),
// nhưng ứng dụng luôn gọi Parse("") nên chỉ dùng danh sách mặc định.
package config

import (
	"os"
	"strconv"
	"strings"
)

// ── Mặc định tích hợp sẵn (dùng khi thiếu settings.ini) ────────────────────────

// DefaultPorts là cổng KMS luôn được kiểm tra.
var DefaultPorts = []int{1688}

// DefaultServices là các từ khóa tên dịch vụ KMS giả lập đã biết.
var DefaultServices = []string{
	"KMSpico", "KMService", "WinKSO", "KMSELDI", "KMS_VL_ALL",
	"KMSAuto", "AutoKMS", "KMSSS", "KMSEmulator", "vlmcsd",
	"Activation-Renewal",
	// Chữ ký dịch vụ đặc trưng của bộ kích hoạt (độ chính xác cao):
	"SppExtComObjPatcher", // KMSpico vá sppsvc — gần như không dương tính giả
	"SppExtComObjHook", "AutoPico", "MicroKMS", "HEU_KMS",
	"service_kms", "KMSServerService", "KMSServer", "vlmcs", "pykms",
}

// DefaultProcesses là các từ khóa tên tiến trình công cụ kích hoạt đã biết.
var DefaultProcesses = []string{
	"KMSpico", "KMSELDI", "AutoKMS", "KMSAuto", "KMSguard",
	"WinKSO", "KMService", "vlmcsd", "AAct", "KMS_VL_ALL",
	"gatherosstate", "clipup",
	// Bổ sung các họ công cụ phổ biến khác:
	"SppExtComObjPatcher", "AutoPico", "MicroKMS", "HEU_KMS",
	"Re-Loader", "reloader", "AAct_x64", "KMS_VL_ALL_AIO", "pykms", "vlmcs",
}

// DefaultTaskKeywords là các từ khóa tên tác vụ định kỳ đáng ngờ.
var DefaultTaskKeywords = []string{
	"AutoKMS", "KMSAuto", "KMS_VL_ALL", "KMSpico",
	"KMSSS", "KMSEmulator", "KMService", "WinKSO", "vlmcsd",
	"Activation-Renewal",
	// Tác vụ định kỳ tái kích hoạt của các bộ công cụ khác:
	"AutoPico", "MicroKMS", "HEU_KMS", "SppExtComObjPatcher",
	"AutoRearm", "AAct",
}

// DefaultKmsPiracyDomains là các tên miền dịch vụ KMS lậu công cộng đã biết.
var DefaultKmsPiracyDomains = []string{
	"msguides", "kms.loli", "digiboy.ir", "0t.ng", "kms.chinancce",
	"kmscloud", "kms.cangshui", "kms.ddns.net", "e8.us.to", "kms.mrxinwang",
	"kms8.msguides", "kms9.msguides", "kms.xspace.in", "skms.netnr",
}

// HardcodedGvlkSuffixes là 5 ký tự cuối của các GVLK/HWID placeholder đã biết,
// dùng để đối chiếu với PartialProductKey của WMI.
var HardcodedGvlkSuffixes = []string{
	// Windows 11 / 10 Semi-Annual Channel
	"T83GX", "GCQG9", "6Q84J", "6XYWF", "J447Y", "66QFC", "VCFB2", "MDWWJ",
	"2YT43", "KHJW4", "4M68B", "T84FV",
	// LTSC / IoT / LTSB
	"J462D", "7CG2H", "PDQGT", "QJ4BJ", "8B639", "76DF9", "D69TJ",
	// Windows 8.1
	"9D6T9", "B4FXY", "MKKG7", "JFFXW",
	// HWID / DE placeholder
	"3V66T", "8HVX7", "H8Q99", "WXCHW", "WGGBY", "2YV77", "8DEC2",
}

// Settings chứa cấu hình quét đã tải từ settings.ini.
type Settings struct {
	Path string

	// Nạp từ khối DEFAULT của settings.ini
	DefaultGvlkSuffixes        []string
	DefaultIniKmsPiracyDomains []string
	DefaultIniServices         []string
	DefaultIniTaskKeywords     []string
	DefaultIniProcesses        []string
	DefaultIniFilePaths        []string
	DefaultIniPorts            []int

	// Nạp từ khối USER của settings.ini
	ExtraPorts            []int
	ExtraServices         []string
	ExtraProcesses        []string
	ExtraTaskKeywords     []string
	ExtraFilePaths        []string
	ExtraKmsPiracyDomains []string
	UserGvlkSuffixes      []string
}

// Load đọc settings.ini tại path. Nếu tệp không tồn tại, trả về Settings với
// các danh sách bổ sung rỗng (chỉ dùng mặc định tích hợp).
func Load(path string) *Settings {
	s := Parse("")
	s.Path = path
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	parsed := Parse(string(data))
	parsed.Path = path
	return parsed
}

// Parse phân tích nội dung settings.ini từ chuỗi. Tách khỏi thao tác tệp để
// thuận tiện kiểm thử.
func Parse(content string) *Settings {
	s := &Settings{}
	section := ""
	for _, raw := range strings.Split(content, "\n") {
		l := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if l == "" || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = normalizeSection(l[1 : len(l)-1])
			continue
		}
		value := stripInlineComment(l)
		if strings.TrimSpace(value) == "" {
			continue
		}
		switch section {
		// ── Khối DEFAULT ──────────────────────────────────────────────
		case "GVLKKEYS":
			if suf, ok := extractKeySuffix(value); ok {
				s.DefaultGvlkSuffixes = append(s.DefaultGvlkSuffixes, suf)
			}
		case "KMSPIRACYDOMAINS":
			s.DefaultIniKmsPiracyDomains = append(s.DefaultIniKmsPiracyDomains, value)
		case "DEFAULTPORTS":
			if p, ok := atoiPort(value); ok {
				s.DefaultIniPorts = append(s.DefaultIniPorts, p)
			}
		case "DEFAULTSERVICES":
			s.DefaultIniServices = append(s.DefaultIniServices, value)
		case "DEFAULTTASKEYWORDS", "DEFAULTTASKKEYWORDS":
			s.DefaultIniTaskKeywords = append(s.DefaultIniTaskKeywords, value)
		case "DEFAULTPROCESSES":
			s.DefaultIniProcesses = append(s.DefaultIniProcesses, value)
		case "DEFAULTFILEPATHS":
			s.DefaultIniFilePaths = append(s.DefaultIniFilePaths, value)

		// ── Khối USER ─────────────────────────────────────────────────
		case "USERGVLKKEYS":
			if suf, ok := extractKeySuffix(value); ok {
				s.UserGvlkSuffixes = append(s.UserGvlkSuffixes, suf)
			}
		case "USERKMSPIRACYDOMAINS":
			s.ExtraKmsPiracyDomains = append(s.ExtraKmsPiracyDomains, value)
		case "EXTRAPORTS":
			if p, ok := atoiPort(value); ok {
				s.ExtraPorts = append(s.ExtraPorts, p)
			}
		case "EXTRASERVICES":
			s.ExtraServices = append(s.ExtraServices, value)
		case "EXTRAPROCESSES":
			s.ExtraProcesses = append(s.ExtraProcesses, value)
		case "EXTRATASKEYWORDS", "EXTRATASKKEYWORDS":
			s.ExtraTaskKeywords = append(s.ExtraTaskKeywords, value)
		case "EXTRAFILEPATHS":
			s.ExtraFilePaths = append(s.ExtraFilePaths, value)
		}
	}
	return s
}

// ── Khung nhìn hợp nhất (mặc định + ini + bổ sung) ─────────────────────────────

// AllPorts trả về danh sách cổng đã hợp nhất, loại trùng.
func (s *Settings) AllPorts() []int {
	seen := map[int]bool{}
	var out []int
	for _, group := range [][]int{DefaultPorts, s.DefaultIniPorts, s.ExtraPorts} {
		for _, p := range group {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// AllServices trả về danh sách dịch vụ đã hợp nhất, loại trùng không phân biệt hoa thường.
func (s *Settings) AllServices() []string {
	return dedupeFold(DefaultServices, s.DefaultIniServices, s.ExtraServices)
}

// AllProcesses trả về danh sách tiến trình đã hợp nhất, loại trùng không phân biệt hoa thường.
func (s *Settings) AllProcesses() []string {
	return dedupeFold(DefaultProcesses, s.DefaultIniProcesses, s.ExtraProcesses)
}

// AllTaskKeywords trả về danh sách từ khóa tác vụ đã hợp nhất, loại trùng.
func (s *Settings) AllTaskKeywords() []string {
	return dedupe(DefaultTaskKeywords, s.DefaultIniTaskKeywords, s.ExtraTaskKeywords)
}

// AllGvlkSuffixes trả về tập hậu tố GVLK (5 ký tự cuối), viết hoa, loại trùng.
func (s *Settings) AllGvlkSuffixes() []string {
	return dedupeFold(HardcodedGvlkSuffixes, s.DefaultGvlkSuffixes, s.UserGvlkSuffixes)
}

// AllKmsPiracyDomains trả về danh sách tên miền KMS lậu đã hợp nhất, loại trùng
// không phân biệt hoa thường.
func (s *Settings) AllKmsPiracyDomains() []string {
	return dedupeFold(DefaultKmsPiracyDomains, s.DefaultIniKmsPiracyDomains, s.ExtraKmsPiracyDomains)
}

// ── Hàm nội bộ ─────────────────────────────────────────────────────────────────

func normalizeSection(raw string) string {
	r := strings.ReplaceAll(raw, "_", "")
	r = strings.ReplaceAll(r, " ", "")
	return strings.ToUpper(r)
}

func stripInlineComment(line string) string {
	if idx := strings.IndexByte(line, ';'); idx >= 0 {
		return strings.TrimSpace(line[:idx])
	}
	return strings.TrimSpace(line)
}

// extractKeySuffix lấy 5 ký tự chữ-số cuối của phần khóa (bỏ phần sau dấu '=').
// Ví dụ: "W269N-WFGWX-YVC9B-4J6C9-T83GX = Windows Pro" → "T83GX".
func extractKeySuffix(keyLine string) (string, bool) {
	key := keyLine
	if idx := strings.IndexByte(keyLine, '='); idx >= 0 {
		key = keyLine[:idx]
	}
	key = strings.TrimSpace(key)
	var b strings.Builder
	for _, r := range key {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	alnum := b.String()
	if len(alnum) < 5 {
		return "", false
	}
	return strings.ToUpper(alnum[len(alnum)-5:]), true
}

func atoiPort(v string) (int, bool) {
	// strconv.Atoi từ chối ký tự phi số và phát hiện tràn số (khác vòng lặp thủ công).
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

// dedupe loại trùng phân biệt hoa thường, giữ thứ tự xuất hiện đầu tiên.
func dedupe(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, v := range g {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// dedupeFold loại trùng không phân biệt hoa thường, giữ thứ tự xuất hiện đầu tiên.
func dedupeFold(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, v := range g {
			k := strings.ToLower(v)
			if !seen[k] {
				seen[k] = true
				out = append(out, v)
			}
		}
	}
	return out
}
