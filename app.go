package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/vinhwincheck/wincheck/internal/audit"
	"github.com/vinhwincheck/wincheck/internal/config"
	"github.com/vinhwincheck/wincheck/internal/i18n"
	"github.com/vinhwincheck/wincheck/internal/license"
	"github.com/vinhwincheck/wincheck/internal/logx"
	"github.com/vinhwincheck/wincheck/internal/ops"
	"github.com/vinhwincheck/wincheck/internal/sysinfo"
)

// dash trả về "(không có)" cho chuỗi rỗng để bảng thông tin không bị trống.
func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(không có)"
	}
	return s
}

// sessionLogPath là nơi lưu nhật ký để giữ lại qua lần nâng quyền (relaunch).
var sessionLogPath = filepath.Join(os.TempDir(), "wincheck_session.json")

// App là backend Wails: bao bọc tầng logic và phơi ra các phương thức cho React.
type App struct {
	ctx      context.Context
	provider sysinfo.Provider
	cfg      *config.Settings
	admin    bool
}

// NewApp tạo App với provider và trạng thái quyền đã xác định sẵn ở main.
func NewApp(provider sysinfo.Provider, admin bool) *App {
	return &App{
		provider: provider,
		cfg:      config.Parse(""), // danh sách quét mặc định tích hợp — không đọc settings.ini
		admin:    admin,
	}
}

// startup lưu context Wails (cần cho việc phát sự kiện).
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// domReady chạy khi giao diện đã sẵn sàng — phóng to cửa sổ để mở full màn hình
// một cách chắc chắn (bổ trợ cho WindowStartState: Maximised).
func (a *App) domReady(ctx context.Context) {
	wruntime.WindowMaximise(ctx)
}

// ── Kiểu dữ liệu phơi ra React (Wails sinh TypeScript từ đây) ──────────────────

// Line là một dòng nhật ký gửi cho giao diện.
type Line struct {
	Kind  int    `json:"kind"`
	Text  string `json:"text"`
	Label string `json:"label"`
	Value string `json:"value"`
	Muted bool   `json:"muted"`
}

func toLine(l logx.Line) Line {
	return Line{Kind: int(l.Kind), Text: l.Text, Label: l.Label, Value: l.Value}
}

// Status là trạng thái ban đầu cho giao diện.
type Status struct {
	Admin    bool              `json:"admin"`
	Strings  map[string]string `json:"strings"`
	Restored []Line            `json:"restored"`
}

// Fact là một thông tin cốt lõi hiển thị trên dashboard.
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Tone  string `json:"tone"` // ok | warn | bad | neutral
}

// Indicator là một dấu hiệu kích hoạt lậu phát hiện được.
type Indicator struct {
	Severity string `json:"severity"` // critical | warn
	Text     string `json:"text"`
}

// Check là một dòng trong bảng tình trạng kiểm tra: mục nào đã kiểm, có phát
// hiện dấu hiệu crack không, và chi tiết.
type Check struct {
	Name       string `json:"name"`
	Status     string `json:"status"`     // ok | detected | warn | skipped | info
	StatusText string `json:"statusText"` // nhãn tiếng Việt của trạng thái
	Detail     string `json:"detail"`
}

// KeyInfo là một key bản quyền của máy để hiển thị đầy đủ.
type KeyInfo struct {
	Label string `json:"label"`
	Value string `json:"value"` // key đầy đủ (OEM/dự phòng) hoặc "…-XXXXX" cho key đang cài
	Note  string `json:"note"`  // ghi chú: key thật / key chung / key cài đặt chung…
	Tone  string `json:"tone"`  // ok | warn | bad | neutral
}

// HwItem là một cặp nhãn/giá trị phần cứng để hiển thị.
type HwItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// HwGroup là một nhóm thông tin phần cứng (CPU, Bo mạch chủ, Bộ nhớ…), kiểu CPU-Z.
type HwGroup struct {
	Title string   `json:"title"`
	Items []HwItem `json:"items"`
}

// Recommendation là khuyến nghị nổi bật (ví dụ: cần thay key bản quyền).
type Recommendation struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

// checkStatusText đổi mã trạng thái sang nhãn tiếng Việt cho bảng.
func checkStatusText(status string) string {
	switch status {
	case audit.CheckOK:
		return i18n.T("V_StOK")
	case audit.CheckDetected:
		return i18n.T("V_StDetected")
	case audit.CheckWarn:
		return i18n.T("V_StWarn")
	case audit.CheckSkipped:
		return i18n.T("V_StSkipped")
	default:
		return i18n.T("V_StInfo")
	}
}

// Verdict là câu trả lời trọng tâm của ứng dụng: Windows này có đang dùng key lậu
// hay không, và nếu có thì kiểu gì — kèm bằng chứng và nhật ký kỹ thuật đầy đủ.
type Verdict struct {
	Level   string `json:"level"` // clean | suspicious | critical
	Title   string `json:"title"`
	Summary string `json:"summary"`
	// TypeLabel/TypeValue là dòng trả lời vế "như thế nào": khi lậu thì là KIỂU lậu
	// (KMS giả lập cục bộ, TSforge…), khi sạch thì là phương thức kích hoạt hợp lệ.
	TypeLabel  string          `json:"typeLabel"`
	TypeValue  string          `json:"typeValue"`
	Count      int             `json:"count"`
	Facts      []Fact          `json:"facts"`
	Hw         []HwGroup       `json:"hw"`   // thông tin phần cứng chi tiết (kiểu CPU-Z)
	Keys       []KeyInfo       `json:"keys"` // key bản quyền của máy (đầy đủ nếu có)
	Rec        *Recommendation `json:"rec"`  // khuyến nghị nổi bật (nil nếu không có)
	Indicators []Indicator     `json:"indicators"`
	Checks     []Check         `json:"checks"` // bảng tình trạng từng mục kiểm tra
	Lines      []Line          `json:"lines"`
	Admin      bool            `json:"admin"`
	Limits     string          `json:"limits"`
}

// piracyType suy ra KIỂU kích hoạt lậu từ dấu hiệu nghiêm trọng đầu tiên khớp
// (thứ tự quét của audit đặt nguyên nhân gốc — máy chủ KMS — lên trước).
// Trả về chuỗi rỗng nếu không có dấu hiệu nghiêm trọng nào.
func piracyType(inds []audit.Indicator) string {
	has := func(s string, subs ...string) bool {
		l := strings.ToLower(s)
		for _, sub := range subs {
			if strings.Contains(l, strings.ToLower(sub)) {
				return true
			}
		}
		return false
	}
	for _, ind := range inds {
		if ind.Severity != audit.SeverityCritical {
			continue
		}
		t := ind.Text
		switch {
		case has(t, "điện thoại", "ZeroCID"):
			return i18n.T("V_TypePhone")
		// GVLK phải xét TRƯỚC TSforge/KMS38: dấu hiệu GVLK vĩnh viễn có mô tả kèm
		// cụm "TSforge / KMS38" nên nếu xét sau sẽ bị phân loại nhầm.
		case has(t, "GVLK"):
			return i18n.T("V_TypeGvlkPerm")
		case has(t, "TSforge", "KMS4k"):
			return i18n.T("V_TypeTsforge")
		case has(t, "KMS38"):
			return i18n.T("V_TypeKms38")
		case has(t, "chính máy này", "localhost", "127.", "Cổng KMS", "hook IFEO", "bị VÁ"):
			return i18n.T("V_TypeLocalKms")
		case has(t, "tên miền lậu", "công cộng trên internet", "10.0.0.10"):
			return i18n.T("V_TypeCloudKms")
		}
	}
	for _, ind := range inds {
		if ind.Severity == audit.SeverityCritical {
			return i18n.T("V_TypeOther") // có dấu hiệu nghiêm trọng nhưng không khớp mẫu nào
		}
	}
	return ""
}

// RunOpts là các lựa chọn kèm theo khi chạy một chức năng.
type RunOpts struct {
	ShowFullKey bool   `json:"showFullKey"`
	Dlv         bool   `json:"dlv"`
	AutoRemove  bool   `json:"autoRemove"`
	Restart     bool   `json:"restart"`
	Confirm     bool   `json:"confirm"`
	Key         string `json:"key"`
	N           int    `json:"n"`
}

// ── Phương thức phơi cho React ────────────────────────────────────────────────

// GetStatus trả về trạng thái quyền, bảng chuỗi giao diện, và nhật ký khôi phục.
func (a *App) GetStatus() Status {
	return Status{Admin: a.admin, Strings: uiStrings(), Restored: a.loadSessionLog()}
}

// Scan là chức năng trọng tâm: quét toàn bộ 10 lớp dấu hiệu rồi trả về một phán
// quyết duy nhất ("có dùng key lậu không, và kiểu gì") kèm bằng chứng, thông tin
// cốt lõi và nhật ký kỹ thuật đầy đủ. Nhật ký cũng được phát dần qua sự kiện "log".
func (a *App) Scan() Verdict {
	a.cfg = config.Parse("")

	e := logx.NewWithSink(func(l logx.Line) {
		wruntime.EventsEmit(a.ctx, "log", toLine(l))
	})
	res := audit.Run(a.provider, a.cfg, time.Now(), e)

	flagged := res.SuspiciousCount > 0 || res.CriticalKms
	v := Verdict{
		Count:  res.SuspiciousCount,
		Facts:  a.buildFacts(flagged),
		Admin:  a.admin,
		Limits: i18n.T("V_Limits"),
	}
	for _, ind := range res.Indicators {
		v.Indicators = append(v.Indicators, Indicator{Severity: ind.Severity, Text: ind.Text})
	}
	if v.Indicators == nil {
		v.Indicators = []Indicator{}
	}
	for _, c := range res.Checks {
		v.Checks = append(v.Checks, Check{
			Name: c.Name, Status: c.Status, StatusText: checkStatusText(c.Status), Detail: c.Detail,
		})
	}
	if v.Checks == nil {
		v.Checks = []Check{}
	}
	for _, l := range e.Lines() {
		v.Lines = append(v.Lines, toLine(l))
	}

	v.Hw = a.buildHardware()
	v.Keys = a.buildKeys()
	v.Rec = a.buildRecommendation()

	switch {
	case res.CriticalKms:
		v.Level = "critical"
		v.Title = i18n.T("V_CriticalTitle")
		v.Summary = i18n.T("V_CriticalSummary")
		// Trả lời vế "như thế nào": lậu KIỂU gì.
		v.TypeLabel = i18n.T("V_TypeLabel")
		v.TypeValue = piracyType(res.Indicators)
	case res.SuspiciousCount > 0:
		v.Level = "suspicious"
		v.Title = i18n.T("V_SuspiciousTitle")
		v.Summary = i18n.Tf("V_SuspiciousSummary", res.SuspiciousCount)
		v.TypeLabel = i18n.T("V_TypeLabel")
		v.TypeValue = i18n.Tf("V_TypeSuspect", res.SuspiciousCount)
	default:
		v.Level = "clean"
		v.Title = i18n.T("V_CleanTitle")
		v.Summary = i18n.T("V_CleanSummary")
		// Máy sạch: cho biết Windows đang được kích hoạt hợp lệ bằng cách nào.
		v.TypeLabel = i18n.T("V_ActivatedBy")
		for _, f := range v.Facts {
			if f.Label == i18n.T("V_FactMethod") {
				v.TypeValue = f.Value
			}
		}
	}
	return v
}

// buildFacts thu thập các thông tin cốt lõi để trả lời "Windows này được kích hoạt
// như thế nào": ấn bản, kênh, trạng thái, phương thức và key đang dùng.
//
// flagged = true khi lần quét phát hiện dấu hiệu lậu. Khi đó KHÔNG trình bày máy
// như đang có bản quyền hợp lệ: trạng thái/phương thức bị hạ tông và ghi rõ "nghi
// vấn lậu" — dù Windows vẫn báo "đã kích hoạt".
func (a *App) buildFacts(flagged bool) []Fact {
	facts := []Fact{}

	if os, err := a.provider.OSInfo(); err == nil && os.Caption != "" {
		facts = append(facts, Fact{i18n.T("V_FactEdition"), os.Caption, "neutral"})
	}

	regKey, _ := a.provider.BackupProductKey()
	lic, err := a.provider.ActiveWindowsLicense()
	if err != nil || lic == nil {
		facts = append(facts, Fact{i18n.T("V_FactStatus"), i18n.T("O3_NoLicense"), "bad"})
		return facts
	}

	licensed := lic.LicenseStatus == 1
	statusText := license.StatusText(lic.LicenseStatus)
	statusTone := "bad"
	if licensed {
		statusTone = "ok"
	}
	// Có dấu hiệu lậu → không gọi là bản quyền: hạ tông và nói rõ nghi vấn.
	if flagged && licensed {
		statusText = i18n.T("V_FactStatusFlagged")
		statusTone = "warn"
	}
	facts = append(facts,
		Fact{i18n.T("V_FactChannel"), dash(lic.Description), "neutral"},
		Fact{i18n.T("V_FactStatus"), statusText, statusTone},
	)

	method := license.DetectActivationMethod(lic.Description, lic.PartialKey, regKey,
		lic.KmsDiscoveredName, lic.KmsCurrentCount)
	methTone := methodTone(method, licensed)
	if flagged {
		methTone = "warn" // phương thức kích hoạt cũng nghi vấn khi có dấu hiệu lậu
	}
	facts = append(facts, Fact{i18n.T("V_FactMethod"), methodLabel(method), methTone})

	if lic.PartialKey != "" {
		facts = append(facts, Fact{i18n.T("V_FactKey"), lic.PartialKey, "neutral"})
	}
	return facts
}

// buildKeys thu thập toàn bộ key bản quyền của máy để hiển thị ĐẦY ĐỦ nếu có:
//   - Key đang cài: giải mã ĐẦY ĐỦ 25 ký tự từ DigitalProductId (Registry). Nếu
//     không đọc được thì mới che thành "…-XXXXX" (chỉ còn 5 ký tự cuối từ WMI).
//   - Key OEM nhúng trong BIOS/UEFI và Key dự phòng Registry: đầy đủ 25 ký tự.
func (a *App) buildKeys() []KeyInfo {
	keys := []KeyInfo{}

	// Key đang cài + nhận định loại key.
	if lic, err := a.provider.ActiveWindowsLicense(); err == nil && lic != nil && lic.PartialKey != "" {
		note, tone := i18n.T("V_KeyRealNote"), "ok"
		if license.IsInstallOnlyKey(lic.PartialKey) {
			note, tone = i18n.T("V_KeyInstallOnly"), "bad"
		} else if license.IsGenericKeySuffix(lic.PartialKey) {
			note, tone = i18n.T("V_KeyGenericNote"), "warn"
		}
		// Ưu tiên khóa đầy đủ giải mã từ DigitalProductId; chỉ nhận khi 5 ký tự
		// cuối khớp license đang kích hoạt (bảo đảm đúng khóa hiện hành).
		val := "XXXXX-XXXXX-XXXXX-XXXXX-" + lic.PartialKey
		if full, _ := a.provider.InstalledProductKey(); full != "" &&
			strings.EqualFold(license.Last5(full), lic.PartialKey) {
			val = full
		}
		keys = append(keys, KeyInfo{
			Label: i18n.T("V_KeyInstalled"), Value: val, Note: note, Tone: tone,
		})
	}

	// Key OEM trong BIOS/UEFI (đầy đủ).
	if oem, _ := a.provider.OEMProductKey(); strings.TrimSpace(oem) != "" {
		note := i18n.T("V_KeyRealNote")
		if ed, ok := license.EditionFromGenericKey(oem); ok {
			note = ed
		}
		keys = append(keys, KeyInfo{Label: i18n.T("V_KeyOem"), Value: oem, Note: note, Tone: "neutral"})
	}

	// Key dự phòng trong Registry (đầy đủ) — bản sao SPP lưu từ lần cài/nhập key
	// trước, CÓ THỂ khác key đang kích hoạt (giải thích rõ trong ghi chú).
	if bk, _ := a.provider.BackupProductKey(); strings.TrimSpace(bk) != "" {
		note := i18n.T("V_KeyBackupNote")
		// Nếu 5 ký tự cuối khác key đang kích hoạt → đây là key CŨ/khác, nói rõ hơn.
		if lic, err := a.provider.ActiveWindowsLicense(); err == nil && lic != nil &&
			lic.PartialKey != "" && !strings.EqualFold(license.Last5(bk), lic.PartialKey) {
			note = i18n.T("V_KeyBackupDifferent")
		}
		keys = append(keys, KeyInfo{Label: i18n.T("V_KeyBackup"), Value: bk, Note: note, Tone: "neutral"})
	}

	return keys
}

// buildHardware gom thông tin phần cứng chi tiết (kiểu CPU-Z) thành các nhóm
// nhãn/giá trị để hiển thị: CPU, Bo mạch chủ/BIOS, Bộ nhớ, Đồ họa, Ổ đĩa.
func (a *App) buildHardware() []HwGroup {
	hw, err := a.provider.HardwareInfo()
	if err != nil {
		return []HwGroup{}
	}
	groups := []HwGroup{}
	add := func(title string, items []HwItem) {
		var kept []HwItem
		for _, it := range items {
			if strings.TrimSpace(it.Value) != "" {
				kept = append(kept, it)
			}
		}
		if len(kept) > 0 {
			groups = append(groups, HwGroup{Title: title, Items: kept})
		}
	}

	// CPU
	cpu := []HwItem{{i18n.T("V_HwCpuName"), hw.CpuName}}
	if hw.CpuCores > 0 {
		cpu = append(cpu, HwItem{i18n.T("V_HwCpuCores"), i18n.Tf("V_HwCoresThreads", hw.CpuCores, hw.CpuThreads)})
	}
	if hw.CpuClockMHz > 0 {
		cpu = append(cpu, HwItem{i18n.T("V_HwCpuClock"), ghz(hw.CpuClockMHz)})
	}
	add(i18n.T("V_HwGroupCpu"), cpu)

	// Hệ thống + Bo mạch chủ + BIOS
	board := []HwItem{
		{i18n.T("V_HwSystem"), joinNonEmpty(" ", hw.SystemVendor, hw.SystemModel)},
		{i18n.T("V_HwComputerName"), hw.ComputerName},
		{i18n.T("V_HwBoard"), joinNonEmpty(" ", hw.BoardVendor, hw.BoardProduct)},
		{i18n.T("V_HwBios"), joinNonEmpty(" · ", hw.BiosVendor, hw.BiosVersion, hw.BiosDate)},
	}
	add(i18n.T("V_HwGroupBoard"), board)

	// Bộ nhớ
	mem := []HwItem{}
	if hw.RamTotalBytes > 0 {
		mem = append(mem, HwItem{i18n.T("V_HwRamTotal"), gib(hw.RamTotalBytes)})
	}
	for _, m := range hw.RamModules {
		val := gib(m.CapacityBytes)
		if m.SpeedMHz > 0 {
			val += i18n.Tf("V_HwRamAt", m.SpeedMHz)
		}
		val = joinNonEmpty(" · ", val, m.Manufacturer, m.PartNumber)
		loc := m.Locator
		if loc == "" {
			loc = i18n.T("V_HwRamSlot")
		}
		mem = append(mem, HwItem{loc, val})
	}
	add(i18n.T("V_HwGroupMem"), mem)

	// Đồ họa
	gpu := []HwItem{}
	for i, g := range hw.Gpus {
		val := g.Name
		if g.VramBytes > 0 {
			val += i18n.Tf("V_HwVram", gib(g.VramBytes))
		}
		if g.DriverVersion != "" {
			val = joinNonEmpty(" · ", val, i18n.Tf("V_HwDriver", g.DriverVersion))
		}
		gpu = append(gpu, HwItem{i18n.Tf("V_HwGpuN", i+1), val})
	}
	add(i18n.T("V_HwGroupGpu"), gpu)

	// Ổ đĩa
	disk := []HwItem{}
	for i, d := range hw.Disks {
		val := d.Model
		if d.SizeBytes > 0 {
			val = joinNonEmpty(" · ", val, gib(d.SizeBytes))
		}
		if d.MediaType != "" {
			val = joinNonEmpty(" · ", val, d.MediaType)
		}
		disk = append(disk, HwItem{i18n.Tf("V_HwDiskN", i+1), val})
	}
	add(i18n.T("V_HwGroupDisk"), disk)

	return groups
}

// gib định dạng số byte thành GB (cơ số 1024), làm tròn hợp lý.
func gib(b uint64) string {
	if b == 0 {
		return ""
	}
	g := float64(b) / (1024 * 1024 * 1024)
	if g >= 100 {
		return fmt.Sprintf("%.0f GB", g)
	}
	return fmt.Sprintf("%.1f GB", g)
}

// ghz định dạng xung nhịp MHz thành "x.xx GHz".
func ghz(mhz uint32) string {
	return fmt.Sprintf("%.2f GHz", float64(mhz)/1000)
}

// joinNonEmpty nối các phần khác rỗng bằng sep.
func joinNonEmpty(sep string, parts ...string) string {
	var kept []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, strings.TrimSpace(p))
		}
	}
	return strings.Join(kept, sep)
}

// buildRecommendation trả về khuyến nghị nổi bật khi cần — hiện tại: cảnh báo
// key cài đặt chung (như Y4G6T) không có tác dụng bản quyền và cần được thay.
func (a *App) buildRecommendation() *Recommendation {
	lic, err := a.provider.ActiveWindowsLicense()
	if err != nil || lic == nil || lic.PartialKey == "" {
		return nil
	}
	name, ok := license.InstallOnlyKeys[strings.ToUpper(lic.PartialKey)]
	if !ok {
		return nil
	}
	rec := &Recommendation{Title: i18n.T("V_RecTitle")}
	if lic.LicenseStatus == 1 {
		rec.Text = i18n.Tf("V_RecInstallKeyActivated", lic.PartialKey, name)
	} else {
		rec.Text = i18n.Tf("V_RecInstallKeyNotAct", lic.PartialKey, name)
	}
	return rec
}

// methodLabel trả về tên tiếng Việt của phương thức kích hoạt.
func methodLabel(m license.ActivationMethod) string {
	switch m {
	case license.MethodDE:
		return i18n.T("V_MethodDE")
	case license.MethodKMS:
		return i18n.T("V_MethodKMS")
	case license.MethodStandard:
		return i18n.T("V_MethodStandard")
	default:
		return i18n.T("V_MethodUnknown")
	}
}

// methodTone quyết định màu của phương thức: KMS cần lưu ý (có thể là KMS lậu),
// DE/chuẩn là bình thường khi đã cấp phép.
func methodTone(m license.ActivationMethod, licensed bool) string {
	if !licensed {
		return "bad"
	}
	if m == license.MethodKMS {
		return "warn"
	}
	return "ok"
}

// RunOption chạy một tùy chọn (1–7), phát mỗi dòng nhật ký qua sự kiện "log", và
// trả về khi hoàn tất (React await để tắt spinner).
func (a *App) RunOption(opt int, opts RunOpts) {
	e := logx.NewWithSink(func(l logx.Line) {
		wruntime.EventsEmit(a.ctx, "log", toLine(l))
	})
	if opts.N > 0 {
		e.SetFirstAction(false)
	}
	ui := &wailsUI{opts: opts}

	switch opt {
	case 1:
		ops.Option1(a.provider, ui, e)
	case 2:
		ops.Option2(a.provider, e)
	case 3:
		ops.Option3(a.provider, ui, e)
	case 7:
		a.cfg = config.Parse("")
		audit.Run(a.provider, a.cfg, time.Now(), e)
	case 4:
		a.gatedAdmin(e, "Act4", func() { ops.Option4(a.provider, ui, e) })
	case 5:
		a.gatedAdmin(e, "Act5", func() { ops.Option5(a.provider, ui, e) })
	case 6:
		a.gatedAdmin(e, "Act6", func() { ops.Option6(a.provider, ui, e) })
	case 8:
		a.gatedAdmin(e, "Act8", func() { ops.CleanCrack(a.provider, config.Parse(""), ui, e) })
	case 9:
		a.gatedAdmin(e, "Act9", func() { ops.CleanOfficeKeys(a.provider, ui, e) })
	}
}

// gatedAdmin phát tiêu đề hành động trước; nếu chưa có quyền Admin thì báo cần
// nâng quyền và dừng (giữ đúng thứ tự hiển thị).
func (a *App) gatedAdmin(e *logx.Emitter, actKey string, run func()) {
	if a.admin {
		run()
		return
	}
	e.Action(i18n.T(actKey))
	e.Warn(i18n.T("NeedAdminOption"))
}

// Elevate lưu nhật ký hiện tại rồi khởi chạy lại ứng dụng với quyền Admin.
func (a *App) Elevate(lines []Line) {
	if data, err := json.Marshal(lines); err == nil {
		_ = os.WriteFile(sessionLogPath, data, 0o644)
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Nâng quyền qua ShellExecute("runas") — API Shell của Windows.
	if elevateSelf(exe, relaunchedFlag) == nil {
		wruntime.Quit(a.ctx)
	}
}

// Quit thoát ứng dụng.
func (a *App) Quit() { wruntime.Quit(a.ctx) }

// loadSessionLog đọc nhật ký đã lưu trước lần nâng quyền (đánh dấu mờ), rồi xóa.
func (a *App) loadSessionLog() []Line {
	data, err := os.ReadFile(sessionLogPath)
	if err != nil {
		return nil
	}
	_ = os.Remove(sessionLogPath)
	var lines []Line
	if json.Unmarshal(data, &lines) != nil {
		return nil
	}
	for i := range lines {
		lines[i].Muted = true
	}
	return lines
}

// ── Web Interaction cho Wails ─────────────────────────────────────────────────

// wailsUI trả lời các câu hỏi của tầng ops bằng cờ do giao diện gửi sẵn, phân
// biệt từng loại qua tiêu đề hộp thoại (mỗi loại một tiêu đề riêng).
type wailsUI struct{ opts RunOpts }

func (u *wailsUI) Confirm(message, title string) bool {
	switch title {
	case i18n.T("ShowKey_Title"):
		return u.opts.ShowFullKey
	case i18n.T("O3_DlvTitle"):
		return u.opts.Dlv
	case i18n.T("O3_RemoveTitle"):
		return u.opts.AutoRemove
	case i18n.T("O6_RestartTitle"):
		return u.opts.Restart
	default: // Confirm_Title: gỡ key (TC5) / rearm (TC6)
		return u.opts.Confirm
	}
}

func (u *wailsUI) PromptKey(prompt, title string) (string, bool) {
	if strings.TrimSpace(u.opts.Key) == "" {
		return "", false
	}
	return u.opts.Key, true
}

// ── Tiện ích ─────────────────────────────────────────────────────────────────

func uiStrings() map[string]string {
	keys := []string{
		"AppTitle", "AppVersion", "BtnAbout", "BtnElevate", "BtnClear",
		"Btn1", "Btn2", "Btn3", "Btn4", "Btn5", "Btn6", "Btn7", "BtnAuditSettings",
		"AdminOk", "AdminWarn", "Ready", "Startup_Ready", "Startup_NoAdmin",
		"LogCleared", "ElevateFromOption", "About_Desc", "O4_Prompt",
		"LogRestored",
		// Dashboard phán quyết — giao diện dùng trực tiếp các khóa này.
		"V_Scanning", "V_Rescan", "V_ShowDetails", "V_HideDetails",
		"V_IndicatorsTitle", "V_NoIndicators", "V_AdvancedTools",
		"V_FactEdition", "V_FactChannel", "V_FactStatus", "V_FactMethod", "V_FactKey",
		"V_TypeLabel", "V_SystemInfo",
		// Bảng tình trạng kiểm tra
		"V_ChkTitle", "V_ChkColName", "V_ChkColStatus", "V_ChkColDetail",
		// Khu vực key + khuyến nghị
		"V_HwTitle", "V_TabAudit", "V_TabSystem", "V_TabHardware",
		"V_KeysTitle", "V_KeyMaskedNote", "V_KeyFullNote", "V_RecTitle",
		// Menu công cụ tổ chức lại
		"V_ToolsHeader", "V_ToolsChangeHead", "V_ToolInstallKey", "V_ToolInstallDesc",
		"V_ToolRemoveKey", "V_ToolRemoveDesc", "V_ToolsActHead", "V_ToolRearm", "V_ToolRearmDesc",
		"V_ToolsCleanHead", "V_ToolClean", "V_ToolCleanDesc",
		"V_ToolCleanOffice", "V_ToolCleanOfficeDesc", "O9_Confirm",
		"V_ToolsOptHead", "V_OptDlv", "V_OptAutoRemove", "V_OptRestart",
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = i18n.T(k)
	}
	return out
}
