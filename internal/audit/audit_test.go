package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/vinhwincheck/wincheck/internal/config"
	"github.com/vinhwincheck/wincheck/internal/logx"
	"github.com/vinhwincheck/wincheck/internal/sysinfo"
	"github.com/vinhwincheck/wincheck/internal/testprovider"
)

var fixedNow = time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

func run(f *testprovider.Fake) (Result, *logx.Emitter) {
	cfg := config.Parse("")
	e := logx.New()
	res := Run(f, cfg, fixedNow, e)
	return res, e
}

func hasContaining(e *logx.Emitter, kind logx.Kind, substr string) bool {
	for _, l := range e.Lines() {
		if l.Kind == kind && strings.Contains(l.Text, substr) {
			return true
		}
	}
	return false
}

func TestAuditCleanSystem(t *testing.T) {
	f := testprovider.New()
	f.Product = &sysinfo.LicensingProduct{PartialKey: "ABCDE", LicenseStatus: 1, GracePeriodMins: 0}
	res, e := run(f)
	if res.CriticalKms {
		t.Errorf("hệ thống sạch không nên critical")
	}
	if res.SuspiciousCount != 0 {
		t.Errorf("hệ thống sạch phải có 0 dấu hiệu, được %d", res.SuspiciousCount)
	}
	// Phải có kết quả "sạch"
	if !containsClean(e) {
		t.Errorf("thiếu thông báo hệ thống sạch")
	}
}

func containsClean(e *logx.Emitter) bool {
	for _, l := range e.Lines() {
		if l.Kind == logx.KindOk && strings.Contains(l.Text, "hệ thống có vẻ sạch") {
			return true
		}
	}
	return false
}

func TestAuditLocalKmsEmulator(t *testing.T) {
	f := testprovider.New()
	f.Kms = "127.0.0.1"
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("KMS localhost phải là critical")
	}
	if res.SuspiciousCount < 1 {
		t.Errorf("phải có ít nhất 1 dấu hiệu")
	}
	if !hasContaining(e, logx.KindError, "GIẢ LẬP CỤC BỘ") {
		t.Errorf("thiếu cảnh báo KMS giả lập cục bộ")
	}
}

func TestAuditCloudPiracy(t *testing.T) {
	f := testprovider.New()
	f.Kms = "kms.somerandom.com"
	f.Internet = true
	f.Resolves = map[string][]string{"kms.somerandom.com": {"203.0.113.9"}}
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("KMS cloud lạ phải là critical")
	}
	if !hasContaining(e, logx.KindError, "CLOUD") {
		t.Errorf("thiếu cảnh báo KMS cloud lậu")
	}
	// DNS phân giải công cộng phải được ghi nhận
	if !hasContaining(e, logx.KindError, "IP công cộng") {
		t.Errorf("thiếu xác nhận phân giải IP công cộng")
	}
}

func TestAuditKnownPiracyDomain(t *testing.T) {
	f := testprovider.New()
	f.Kms = "km8.msguides.com"
	res, _ := run(f)
	if !res.CriticalKms {
		t.Errorf("tên miền lậu đã biết phải là critical")
	}
}

func TestAuditCorporateKmsClean(t *testing.T) {
	f := testprovider.New()
	f.Kms = "192.168.1.10"
	res := mustClean(t, f)
	if res.CriticalKms {
		t.Errorf("KMS nội bộ doanh nghiệp không nên critical")
	}
}

func mustClean(t *testing.T, f *testprovider.Fake) Result {
	t.Helper()
	res, _ := run(f)
	return res
}

func TestAuditPortOpen(t *testing.T) {
	f := testprovider.New()
	f.OpenPorts = map[int]bool{1688: true}
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("cổng 1688 mở phải là critical")
	}
	if !hasContaining(e, logx.KindError, "ĐANG MỞ") {
		t.Errorf("thiếu cảnh báo cổng mở")
	}
}

func TestAuditServiceFound(t *testing.T) {
	f := testprovider.New()
	f.Services = []sysinfo.Service{{Name: "KMSpicoSvc", DisplayName: "KMSpico Service"}}
	res, e := run(f)
	if res.SuspiciousCount < 1 {
		t.Errorf("dịch vụ KMSpico phải bị gắn cờ")
	}
	if res.CriticalKms {
		t.Errorf("chỉ có dịch vụ (không có KMS) không nên critical")
	}
	if !hasContaining(e, logx.KindWarn, "dịch vụ đáng ngờ") {
		t.Errorf("thiếu cảnh báo dịch vụ")
	}
}

// TestAuditInstallOnlyKeyLicensed: key cài đặt chung (Y4G6T) mà máy VẪN "đã kích
// hoạt" phải tính là một điểm đáng ngờ (warn) — dấu vân tay KMS/HWID cần xác minh.
func TestAuditInstallOnlyKeyLicensed(t *testing.T) {
	f := testprovider.New()
	f.Product = &sysinfo.LicensingProduct{PartialKey: "Y4G6T", LicenseStatus: 1, GracePeriodMins: 0}
	res, _ := run(f)
	if res.SuspiciousCount < 1 {
		t.Errorf("key cài đặt chung đã kích hoạt phải cho >=1 dấu hiệu, được %d", res.SuspiciousCount)
	}
	if res.CriticalKms {
		t.Errorf("key cài đặt chung chỉ nên là warn, KHÔNG critical (license số có thể chính hãng)")
	}
	found := false
	for _, ind := range res.Indicators {
		if strings.Contains(ind.Text, "Y4G6T") && ind.Severity == SeverityWarn {
			found = true
		}
	}
	if !found {
		t.Errorf("thiếu dấu hiệu warn cho key cài đặt chung Y4G6T: %+v", res.Indicators)
	}
}

// TestAuditSppImageHijack: hook IFEO trên nhị phân SPP (KMSpico/KMS_VL_ALL) phải
// là dấu hiệu NGHIÊM TRỌNG.
func TestAuditSppImageHijack(t *testing.T) {
	f := testprovider.New()
	f.SppHijack = "SppExtComObj.exe (VerifierDlls: SECOH-QAD.dll)"
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("hook vá dịch vụ SPP phải là critical")
	}
	if res.SuspiciousCount < 1 {
		t.Errorf("phải có ít nhất 1 dấu hiệu")
	}
	if !hasContaining(e, logx.KindError, "hook vá dịch vụ SPP") {
		t.Errorf("thiếu cảnh báo hook vá SPP trong nhật ký")
	}
}

func TestAuditTaskAndProcess(t *testing.T) {
	f := testprovider.New()
	f.Tasks = []string{`\Microsoft\AutoKMS`}
	f.Procs = []sysinfo.Process{{Name: "kmsauto", PID: 1234}}
	res, _ := run(f)
	if res.SuspiciousCount < 2 {
		t.Errorf("tác vụ + tiến trình phải cho >=2 dấu hiệu, được %d", res.SuspiciousCount)
	}
}

func TestAuditFileFound(t *testing.T) {
	f := testprovider.New()
	// Đường dẫn tùy chỉnh chắc chắn xuất hiện trong danh sách quét.
	cfg := config.Parse("# USER BLOCK\n[ExtraFilePaths]\nC:\\Fake\\KMSTool\n")
	f.ExistingPaths = map[string]bool{`C:\Fake\KMSTool`: true}
	e := logx.New()
	res := Run(f, cfg, fixedNow, e)
	if res.SuspiciousCount < 1 {
		t.Errorf("đường dẫn tồn tại phải bị gắn cờ")
	}
	if !hasContaining(e, logx.KindWarn, "công cụ kích hoạt") {
		t.Errorf("thiếu cảnh báo đường dẫn tập tin")
	}
}

func TestAuditGvlkPermanent(t *testing.T) {
	f := testprovider.New()
	f.Product = &sysinfo.LicensingProduct{PartialKey: "T83GX", LicenseStatus: 1, GracePeriodMins: 0}
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("GVLK + vĩnh viễn phải là critical")
	}
	if !hasContaining(e, logx.KindError, "CÓ KHẢ NĂNG LẬU") {
		t.Errorf("thiếu cảnh báo GVLK vĩnh viễn")
	}
}

func TestAuditGvlkWithRenewal(t *testing.T) {
	f := testprovider.New()
	f.Product = &sysinfo.LicensingProduct{PartialKey: "T83GX", LicenseStatus: 1, GracePeriodMins: 60000}
	res, e := run(f)
	if res.CriticalKms {
		t.Errorf("GVLK còn gia hạn KMS không nên critical")
	}
	if !hasContaining(e, logx.KindOk, "gia hạn KMS đang hoạt động") {
		t.Errorf("thiếu ghi nhận GVLK có gia hạn hợp lệ")
	}
}

func TestAuditPhoneAnomaly(t *testing.T) {
	f := testprovider.New()
	f.Product = &sysinfo.LicensingProduct{
		PartialKey: "ABCDE", LicenseStatus: 1, GracePeriodMins: 0,
		Description: "Windows(R), Phone activation",
	}
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("kích hoạt điện thoại bất thường phải là critical")
	}
	if !hasContaining(e, logx.KindError, "ĐIỆN THOẠI BẤT THƯỜNG") {
		t.Errorf("thiếu cảnh báo kênh điện thoại")
	}
}

func TestAuditExpiryKms38(t *testing.T) {
	f := testprovider.New()
	minsTo2038 := uint32(time.Date(2038, 3, 1, 0, 0, 0, 0, time.UTC).Sub(fixedNow).Minutes())
	f.Product = &sysinfo.LicensingProduct{PartialKey: "ABCDE", LicenseStatus: 1, GracePeriodMins: minsTo2038}
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("hết hạn 2038 (KMS38) phải là critical")
	}
	if !hasContaining(e, logx.KindError, "KMS38") {
		t.Errorf("thiếu cảnh báo KMS38")
	}
}

func TestAuditSppExternalEvent(t *testing.T) {
	f := testprovider.New()
	f.Events = []sysinfo.EventEntry{
		{EventCode: 12290, Source: "Microsoft-Windows-Security-SPP",
			Message: "KMS request sent to 203.0.113.50:1688", TimeGenerated: fixedNow},
	}
	res, e := run(f)
	if !res.CriticalKms {
		t.Errorf("sự kiện SPP tới máy chủ ngoài phải là critical")
	}
	if !hasContaining(e, logx.KindError, "203.0.113.50") {
		t.Errorf("thiếu ghi nhận địa chỉ máy chủ ngoài")
	}
}

func TestAuditSppInternalEventClean(t *testing.T) {
	f := testprovider.New()
	f.Events = []sysinfo.EventEntry{
		{EventCode: 12290, Source: "Microsoft-Windows-Security-SPP",
			Message: "KMS request to 192.168.1.5", TimeGenerated: fixedNow},
	}
	res, _ := run(f)
	if res.CriticalKms {
		t.Errorf("sự kiện SPP tới máy chủ nội bộ không nên critical")
	}
}

// TestIndicatorsPopulated kiểm tra danh sách dấu hiệu có cấu trúc (dùng cho
// dashboard phán quyết): đúng số lượng, đúng mức độ, và khớp với bộ đếm.
func TestIndicatorsPopulated(t *testing.T) {
	f := testprovider.New()
	f.Kms = "127.0.0.1"                                                       // critical
	f.OpenPorts = map[int]bool{1688: true}                                    // critical
	f.Services = []sysinfo.Service{{Name: "KMSpico", DisplayName: "KMSpico"}} // warn
	res, _ := run(f)

	if len(res.Indicators) != res.SuspiciousCount {
		t.Errorf("số dấu hiệu (%d) phải khớp SuspiciousCount (%d)", len(res.Indicators), res.SuspiciousCount)
	}
	var crit, warn int
	for _, ind := range res.Indicators {
		switch ind.Severity {
		case SeverityCritical:
			crit++
		case SeverityWarn:
			warn++
		default:
			t.Errorf("mức độ không hợp lệ: %q", ind.Severity)
		}
		if strings.TrimSpace(ind.Text) == "" {
			t.Errorf("dấu hiệu phải có mô tả")
		}
	}
	if crit < 2 {
		t.Errorf("phải có >=2 dấu hiệu nghiêm trọng (KMS cục bộ + cổng mở), được %d", crit)
	}
	if warn < 1 {
		t.Errorf("phải có >=1 dấu hiệu đáng ngờ (dịch vụ KMSpico), được %d", warn)
	}
}

func TestIndicatorsEmptyWhenClean(t *testing.T) {
	f := testprovider.New()
	f.Product = &sysinfo.LicensingProduct{PartialKey: "ABCDE", LicenseStatus: 1, GracePeriodMins: 0}
	res, _ := run(f)
	if len(res.Indicators) != 0 {
		t.Errorf("hệ thống sạch không được có dấu hiệu nào, được %v", res.Indicators)
	}
}

func TestSuspiciousPathsIncludesExtra(t *testing.T) {
	paths := SuspiciousPaths([]string{`C:\Custom\Tool`})
	found := false
	for _, p := range paths {
		if p.Path == `C:\Custom\Tool` {
			found = true
		}
	}
	if !found {
		t.Errorf("SuspiciousPaths phải bao gồm đường dẫn tùy chỉnh")
	}
	if len(paths) < 16 {
		t.Errorf("phải có ít nhất 16 đường dẫn tích hợp, được %d", len(paths))
	}
}
