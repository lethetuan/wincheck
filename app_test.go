package main

import (
	"strings"
	"testing"

	"github.com/vinhwincheck/wincheck/internal/audit"
	"github.com/vinhwincheck/wincheck/internal/i18n"
	"github.com/vinhwincheck/wincheck/internal/license"
	"github.com/vinhwincheck/wincheck/internal/sysinfo"
	"github.com/vinhwincheck/wincheck/internal/testprovider"
)

func TestMethodLabel(t *testing.T) {
	cases := map[license.ActivationMethod]string{
		license.MethodDE:       "V_MethodDE",
		license.MethodKMS:      "V_MethodKMS",
		license.MethodStandard: "V_MethodStandard",
		license.MethodUnknown:  "V_MethodUnknown",
	}
	for m, key := range cases {
		if got := methodLabel(m); got != i18n.T(key) {
			t.Errorf("methodLabel(%v) = %q, muốn %q", m, got, i18n.T(key))
		}
	}
}

func TestMethodTone(t *testing.T) {
	if got := methodTone(license.MethodDE, false); got != "bad" {
		t.Errorf("chưa cấp phép phải là 'bad', được %q", got)
	}
	if got := methodTone(license.MethodKMS, true); got != "warn" {
		t.Errorf("KMS đã cấp phép phải là 'warn' (cần xác minh), được %q", got)
	}
	if got := methodTone(license.MethodDE, true); got != "ok" {
		t.Errorf("DE đã cấp phép phải là 'ok', được %q", got)
	}
}

func TestBuildFactsLicensed(t *testing.T) {
	f := testprovider.New()
	f.OS = sysinfo.OSInfo{Caption: "Windows 10 Pro"}
	f.ActiveLicense = &sysinfo.License{
		Name: "Windows 10 Pro", Description: "RETAIL channel",
		PartialKey: "3V66T", LicenseStatus: 1, // khóa chung + retail → DE
	}
	a := &App{provider: f, admin: true}
	facts := a.buildFacts(false)

	find := func(label string) *Fact {
		for i := range facts {
			if facts[i].Label == label {
				return &facts[i]
			}
		}
		return nil
	}
	if fx := find(i18n.T("V_FactEdition")); fx == nil || fx.Value != "Windows 10 Pro" {
		t.Errorf("thiếu/sai ấn bản Windows: %+v", fx)
	}
	if fx := find(i18n.T("V_FactStatus")); fx == nil || fx.Tone != "ok" {
		t.Errorf("đã cấp phép thì trạng thái phải tone 'ok': %+v", fx)
	}
	if fx := find(i18n.T("V_FactMethod")); fx == nil || fx.Value != i18n.T("V_MethodDE") {
		t.Errorf("khóa chung + RETAIL phải nhận diện Digital Entitlement: %+v", fx)
	}
	if fx := find(i18n.T("V_FactKey")); fx == nil || fx.Value != "3V66T" {
		t.Errorf("thiếu key đang dùng: %+v", fx)
	}
}

func TestBuildFactsNoLicense(t *testing.T) {
	f := testprovider.New()
	f.OS = sysinfo.OSInfo{Caption: "Windows 10 Pro"}
	a := &App{provider: f, admin: false}
	facts := a.buildFacts(false)
	for _, fx := range facts {
		if fx.Label == i18n.T("V_FactStatus") && fx.Tone != "bad" {
			t.Errorf("không có bản quyền thì trạng thái phải tone 'bad': %+v", fx)
		}
	}
}

// TestPiracyType kiểm tra việc suy ra KIỂU kích hoạt lậu — đây là câu trả lời
// trọng tâm "lậu như thế nào" hiển thị ngay trên thẻ phán quyết.
func TestPiracyType(t *testing.T) {
	crit := func(s string) audit.Indicator {
		return audit.Indicator{Severity: audit.SeverityCritical, Text: s}
	}
	cases := []struct {
		name string
		inds []audit.Indicator
		want string
	}{
		{"KMS cục bộ", []audit.Indicator{crit("Máy chủ KMS trỏ về chính máy này (127.0.0.1)")}, i18n.T("V_TypeLocalKms")},
		{"Cổng KMS mở", []audit.Indicator{crit("Cổng KMS 1688 đang mở trên máy")}, i18n.T("V_TypeLocalKms")},
		{"KMS cloud", []audit.Indicator{crit("Máy chủ KMS là dịch vụ công cộng trên internet: kms.x.com")}, i18n.T("V_TypeCloudKms")},
		{"Tên miền lậu", []audit.Indicator{crit("Máy chủ KMS là tên miền lậu đã biết: km8.msguides.com")}, i18n.T("V_TypeCloudKms")},
		{"TSforge", []audit.Indicator{crit(i18n.Tf("V_IndTsforge", 2200))}, i18n.T("V_TypeTsforge")},
		{"KMS38", []audit.Indicator{crit(i18n.Tf("V_IndKms38", 2038))}, i18n.T("V_TypeKms38")},
		{"GVLK vĩnh viễn", []audit.Indicator{crit(i18n.Tf("V_IndGvlkPermanent", "T83GX"))}, i18n.T("V_TypeGvlkPerm")},
		{"Điện thoại", []audit.Indicator{crit("Kênh kích hoạt qua điện thoại bất thường")}, i18n.T("V_TypePhone")},
		{"Không khớp mẫu", []audit.Indicator{crit("Dấu hiệu lạ chưa phân loại")}, i18n.T("V_TypeOther")},
		{"Chỉ có cảnh báo", []audit.Indicator{{Severity: audit.SeverityWarn, Text: "Dịch vụ đáng ngờ"}}, ""},
		{"Rỗng", nil, ""},
	}
	for _, c := range cases {
		if got := piracyType(c.inds); got != c.want {
			t.Errorf("%s: piracyType = %q, muốn %q", c.name, got, c.want)
		}
	}
}

// TestPiracyTypeUsesFirstCriticalMatch: khi có nhiều dấu hiệu, kiểu lấy theo dấu
// hiệu nghiêm trọng đầu tiên khớp mẫu (audit đặt nguyên nhân gốc lên trước).
func TestPiracyTypeUsesFirstCriticalMatch(t *testing.T) {
	inds := []audit.Indicator{
		{Severity: audit.SeverityWarn, Text: "Dịch vụ KMSpico"},
		{Severity: audit.SeverityCritical, Text: "Máy chủ KMS trỏ về chính máy này (127.0.0.1)"},
		{Severity: audit.SeverityCritical, Text: "Khóa GVLK 'T83GX' kích hoạt vĩnh viễn"},
	}
	if got := piracyType(inds); got != i18n.T("V_TypeLocalKms") {
		t.Errorf("phải lấy dấu hiệu nghiêm trọng đầu tiên (KMS cục bộ), được %q", got)
	}
}

// TestBuildRecommendationInstallOnlyKey: key cài đặt chung (Y4G6T) phải sinh
// khuyến nghị "cần thay key" — cả khi máy đã kích hoạt lẫn chưa.
func TestBuildRecommendationInstallOnlyKey(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{PartialKey: "Y4G6T", LicenseStatus: 1}
	a := &App{provider: f, admin: true}
	rec := a.buildRecommendation()
	if rec == nil {
		t.Fatal("key Y4G6T phải sinh khuyến nghị cần thay key")
	}
	if rec.Title != i18n.T("V_RecTitle") {
		t.Errorf("sai tiêu đề khuyến nghị: %q", rec.Title)
	}
	if !strings.Contains(rec.Text, "THAY") {
		t.Errorf("khuyến nghị phải nói cần THAY key: %q", rec.Text)
	}

	// Máy chưa kích hoạt → dùng thông điệp khác nhưng vẫn là cần thay.
	f.ActiveLicense.LicenseStatus = 0
	if rec := a.buildRecommendation(); rec == nil || !strings.Contains(rec.Text, "THAY") {
		t.Errorf("chưa kích hoạt cũng phải khuyến nghị thay key")
	}
}

func TestBuildRecommendationRealKey(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{PartialKey: "ABCDE", LicenseStatus: 1}
	a := &App{provider: f, admin: true}
	if a.buildRecommendation() != nil {
		t.Errorf("key bản quyền thật KHÔNG được sinh khuyến nghị thay key")
	}
}

// TestBuildKeys: hiển thị ĐẦY ĐỦ key đang cài (giải mã DigitalProductId) khi có,
// đầy đủ key OEM/dự phòng, và gắn đúng ghi chú/tone cho key cài đặt chung.
func TestBuildKeys(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{PartialKey: "Y4G6T", LicenseStatus: 1}
	f.InstalledKey = "C8NKQ-QCJWK-YPTDH-KC2FQ-Y4G6T" // giải mã đầy đủ, 5 ký tự cuối khớp
	f.OEMKey = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
	f.Backup = "MN6BV-H3XRF-89T3G-3Q7QB-2PQGT" // 5 ký tự cuối KHÁC key đang cài
	a := &App{provider: f}
	keys := a.buildKeys()

	find := func(label string) *KeyInfo {
		for i := range keys {
			if keys[i].Label == label {
				return &keys[i]
			}
		}
		return nil
	}
	if k := find(i18n.T("V_KeyInstalled")); k == nil || k.Value != "C8NKQ-QCJWK-YPTDH-KC2FQ-Y4G6T" || k.Tone != "bad" {
		t.Errorf("key đang cài phải hiển thị ĐẦY ĐỦ và tone 'bad' cho key cài đặt chung: %+v", k)
	}
	if k := find(i18n.T("V_KeyOem")); k == nil || k.Value != "VK7JG-NPHTM-C97JM-9MPGT-3V66T" {
		t.Errorf("key OEM phải hiển thị ĐẦY ĐỦ: %+v", k)
	}
	if k := find(i18n.T("V_KeyBackup")); k == nil || k.Value != "MN6BV-H3XRF-89T3G-3Q7QB-2PQGT" {
		t.Errorf("key dự phòng phải hiển thị ĐẦY ĐỦ: %+v", k)
	}
	// Key dự phòng khác key đang cài → ghi chú phải nói rõ đây là key CŨ/khác.
	if k := find(i18n.T("V_KeyBackup")); k == nil || k.Note != i18n.T("V_KeyBackupDifferent") {
		t.Errorf("key dự phòng khác key đang cài phải mang ghi chú 'khác': %+v", k)
	}
}

// TestBuildKeysMaskFallback: khi KHÔNG giải mã được DigitalProductId, key đang cài
// quay về che 5 ký tự cuối (chỉ dữ liệu WMI để lộ).
func TestBuildKeysMaskFallback(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{PartialKey: "Y4G6T", LicenseStatus: 1}
	f.InstalledKey = "" // không đọc được khối DigitalProductId
	a := &App{provider: f}
	for _, k := range a.buildKeys() {
		if k.Label == i18n.T("V_KeyInstalled") && k.Value != "XXXXX-XXXXX-XXXXX-XXXXX-Y4G6T" {
			t.Errorf("thiếu khóa đầy đủ phải che 5 ký tự cuối: %+v", k)
		}
	}
}

func TestDash(t *testing.T) {
	if dash("  ") != "(không có)" {
		t.Errorf("chuỗi rỗng phải thành '(không có)'")
	}
	if dash("x") != "x" {
		t.Errorf("chuỗi có nội dung phải giữ nguyên")
	}
}

func TestWailsUIConfirmMapping(t *testing.T) {
	ui := &wailsUI{opts: RunOpts{ShowFullKey: true, Dlv: false, AutoRemove: true, Restart: false, Confirm: true}}
	cases := []struct {
		title string
		want  bool
	}{
		{i18n.T("ShowKey_Title"), true},    // showFullKey
		{i18n.T("O3_DlvTitle"), false},     // dlv
		{i18n.T("O3_RemoveTitle"), true},   // autoRemove
		{i18n.T("O6_RestartTitle"), false}, // restart
		{i18n.T("Confirm_Title"), true},    // confirm (gỡ key / rearm)
	}
	for _, c := range cases {
		if got := ui.Confirm("", c.title); got != c.want {
			t.Errorf("Confirm(title=%q) = %v, muốn %v", c.title, got, c.want)
		}
	}
}

func TestWailsUIPromptKey(t *testing.T) {
	ui := &wailsUI{opts: RunOpts{Key: "VK7JG-NPHTM-C97JM-9MPGT-3V66T"}}
	if v, ok := ui.PromptKey("", ""); !ok || v == "" {
		t.Errorf("có key phải trả về ok=true")
	}
	empty := &wailsUI{}
	if _, ok := empty.PromptKey("", ""); ok {
		t.Errorf("không có key phải trả về ok=false")
	}
}

// TestUIStringsHasKeys bảo đảm mọi khóa mà giao diện React tra cứu đều có mặt
// trong uiStrings() — thiếu một khóa sẽ khiến chỗ đó hiển thị RỖNG trên app.
func TestUIStringsHasKeys(t *testing.T) {
	m := uiStrings()
	needed := []string{
		"AppTitle", "AppVersion", "Btn1", "Btn2", "Btn3", "Btn4", "Btn5", "Btn6", "Btn7",
		"BtnAuditSettings", "BtnElevate", "AdminWarn", "Ready",
		"ElevateFromOption", "O4_Prompt",
		// Dashboard phán quyết
		"V_Scanning", "V_Rescan", "V_ShowDetails", "V_AdvancedTools",
		"V_IndicatorsTitle", "V_NoIndicators", "V_SystemInfo", "V_FactMethod",
		// Bảng tình trạng kiểm tra (thiếu khóa ở đây = tiêu đề/cột hiện RỖNG trên app)
		"V_ChkTitle", "V_ChkColName", "V_ChkColStatus", "V_ChkColDetail",
		// Key + khuyến nghị
		"V_KeysTitle", "V_KeyMaskedNote", "V_RecTitle",
	}
	for _, k := range needed {
		if m[k] == "" || m[k] == k {
			t.Errorf("uiStrings thiếu bản dịch cho %q (được %q)", k, m[k])
		}
	}
}
