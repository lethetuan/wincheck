package ops

import (
	"errors"
	"strings"
	"testing"

	"github.com/vinhwincheck/wincheck/internal/config"
	"github.com/vinhwincheck/wincheck/internal/logx"
	"github.com/vinhwincheck/wincheck/internal/sysinfo"
	"github.com/vinhwincheck/wincheck/internal/testprovider"
)

var errBoom = errors.New("boom")

func has(e *logx.Emitter, kind logx.Kind, substr string) bool {
	for _, l := range e.Lines() {
		if l.Kind == kind && strings.Contains(l.Text, substr) {
			return true
		}
	}
	return false
}

func hasData(e *logx.Emitter, valueSubstr string) bool {
	for _, l := range e.Lines() {
		if l.Kind == logx.KindData && strings.Contains(l.Value, valueSubstr) {
			return true
		}
	}
	return false
}

// ── Tùy chọn 1 ─────────────────────────────────────────────────────────────────

func TestOption1WithOemKey(t *testing.T) {
	f := testprovider.New()
	f.OS = sysinfo.OSInfo{Caption: "Windows 10 Pro", Version: "10.0.19045", Build: "19045", Arch: "64-bit"}
	f.OEMKey = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
	ui := &testprovider.FakeUI{ConfirmDefault: false} // không hiện đầy đủ key
	e := logx.New()
	Option1(f, ui, e)

	if !hasData(e, "Windows 10 Pro") {
		t.Errorf("thiếu thông tin OS")
	}
	if !has(e, logx.KindKey, "XXXXX-XXXXX-XXXXX-XXXXX-3V66T") {
		t.Errorf("key OEM phải được che (5 ký tự cuối 3V66T)")
	}
	if !has(e, logx.KindOk, "Windows 10/11 Pro") {
		t.Errorf("phải nhận diện ấn bản Pro từ khóa chung")
	}
}

func TestOption1NoOemKey(t *testing.T) {
	f := testprovider.New()
	ui := &testprovider.FakeUI{}
	e := logx.New()
	Option1(f, ui, e)
	if !has(e, logx.KindInfo, "Không phát hiện Key Bản Quyền OEM") {
		t.Errorf("phải báo không có key OEM")
	}
}

// ── Tùy chọn 2 ─────────────────────────────────────────────────────────────────

// TestOption2ShowsLicenseFromApi: Tùy chọn 2 lấy dữ liệu thẳng từ Software
// Licensing API (WMI), không còn phụ thuộc output text của slmgr.vbs.
func TestOption2ShowsLicenseFromApi(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{
		Name: "Windows(R), Professional edition", Description: "RETAIL channel",
		PartialKey: "Y4G6T", LicenseStatus: 1,
	}
	e := logx.New()
	Option2(f, e)
	if !has(e, logx.KindOk, "Đã được cấp phép") {
		t.Errorf("đã cấp phép phải hiển thị màu OK")
	}
	if !hasData(e, "Windows(R), Professional edition") {
		t.Errorf("ấn bản phải hiển thị dạng dữ liệu")
	}
	if !hasData(e, "Y4G6T") {
		t.Errorf("phải hiển thị key một phần")
	}
}

func TestOption2NoLicense(t *testing.T) {
	f := testprovider.New()
	e := logx.New()
	Option2(f, e)
	if !has(e, logx.KindWarn, "Không đọc được thông tin bản quyền") {
		t.Errorf("không có bản quyền phải báo cảnh báo")
	}
}

func TestOption5SurfacesApiError(t *testing.T) {
	// Software Licensing API tra loi -> phai dua ra nhat ky va dung lai.
	f := testprovider.New()
	f.UninstallErr = errBoom
	ui := &testprovider.FakeUI{ConfirmDefault: true}
	e := logx.New()
	Option5(f, ui, e)
	if !has(e, logx.KindError, "boom") {
		t.Errorf("lỗi API phải được đưa ra nhật ký")
	}
	if containsCmd(f.OpsLog, "ClearProductKeyFromRegistry") {
		t.Errorf("gỡ key thất bại thì KHÔNG được xóa registry")
	}
}

// ── Tùy chọn 3 ─────────────────────────────────────────────────────────────────

func TestOption3RemovesStaleBackupKey(t *testing.T) {
	f := testprovider.New()
	f.Admin = true
	f.ActiveLicense = &sysinfo.License{
		Name: "Windows 10 Pro", Description: "VOLUME_MAK channel",
		PartialKey: "ABCDE", LicenseStatus: 1,
	}
	f.Backup = "VK7JG-NPHTM-C97JM-9MPGT-ZZZZZ" // đuôi lệch
	ui := &testprovider.FakeUI{ConfirmDefault: true}
	e := logx.New()
	Option3(f, ui, e)

	if !f.Deleted {
		t.Errorf("key dự phòng cũ phải bị xóa khi admin xác nhận")
	}
	if !has(e, logx.KindOk, "Đã xóa Key Dự phòng") {
		t.Errorf("thiếu xác nhận đã xóa")
	}
}

func TestOption3MatchingKeys(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{
		Name: "Windows 10 Pro", Description: "OEM channel",
		PartialKey: "ABCDE", LicenseStatus: 1,
	}
	f.Backup = "VK7JG-NPHTM-C97JM-9MPGT-ABCDE" // khớp
	ui := &testprovider.FakeUI{ConfirmDefault: false}
	e := logx.New()
	Option3(f, ui, e)
	if !has(e, logx.KindOk, "khớp với Key Bản Quyền đang hoạt động") {
		t.Errorf("key khớp phải báo OK")
	}
}

func TestOption3DigitalEntitlement(t *testing.T) {
	f := testprovider.New()
	f.ActiveLicense = &sysinfo.License{
		Name: "Windows 10 Pro", Description: "RETAIL channel",
		PartialKey: "3V66T", LicenseStatus: 1, // khóa chung → DE
	}
	ui := &testprovider.FakeUI{ConfirmDefault: false}
	e := logx.New()
	Option3(f, ui, e)
	if !has(e, logx.KindDE, "Digital Entitlement") {
		t.Errorf("khóa chung + licensed phải nhận diện Digital Entitlement")
	}
}

// ── Tùy chọn 4 ─────────────────────────────────────────────────────────────────

func TestOption4Cancelled(t *testing.T) {
	f := testprovider.New()
	ui := &testprovider.FakeUI{KeyOK: false}
	e := logx.New()
	Option4(f, ui, e)
	if !has(e, logx.KindInfo, "Đã hủy") {
		t.Errorf("hủy nhập key phải báo đã hủy")
	}
}

func TestOption4BadFormat(t *testing.T) {
	f := testprovider.New()
	ui := &testprovider.FakeUI{KeyOK: true, KeyValue: "khong-hop-le"}
	e := logx.New()
	Option4(f, ui, e)
	if !has(e, logx.KindError, "Định dạng không hợp lệ") {
		t.Errorf("key sai định dạng phải báo lỗi")
	}
}

func TestOption4Success(t *testing.T) {
	f := testprovider.New()
	ui := &testprovider.FakeUI{KeyOK: true, KeyValue: "VK7JG-NPHTM-C97JM-9MPGT-3V66T", ConfirmDefault: false}
	e := logx.New()
	Option4(f, ui, e)
	if !has(e, logx.KindOk, "được chấp nhận") {
		t.Errorf("cài key thành công phải báo OK")
	}
}

func TestOption4FailSkuMismatch(t *testing.T) {
	f := testprovider.New()
	f.InstallErr = errors.New("InstallProductKey trả về mã lỗi 0xC004F069")
	ui := &testprovider.FakeUI{KeyOK: true, KeyValue: "VK7JG-NPHTM-C97JM-9MPGT-3V66T", ConfirmDefault: false}
	e := logx.New()
	Option4(f, ui, e)
	if !has(e, logx.KindError, "bị Windows từ chối") {
		t.Errorf("key bị từ chối phải báo lỗi")
	}
	if !has(e, logx.KindDiag, "SKU không khớp") {
		t.Errorf("mã 0xC004F069 phải chẩn đoán SKU không khớp")
	}
}

// ── Tùy chọn 5 ─────────────────────────────────────────────────────────────────

func TestOption5CancelAndProceed(t *testing.T) {
	// Hủy
	f := testprovider.New()
	ui := &testprovider.FakeUI{ConfirmDefault: false}
	e := logx.New()
	Option5(f, ui, e)
	if !has(e, logx.KindInfo, "Đã hủy") {
		t.Errorf("từ chối xác nhận phải hủy")
	}
	if len(f.OpsLog) != 0 {
		t.Errorf("hủy thì không được gọi API thay đổi")
	}

	// Thực hiện
	f2 := testprovider.New()
	ui2 := &testprovider.FakeUI{ConfirmDefault: true}
	e2 := logx.New()
	Option5(f2, ui2, e2)
	if !containsCmd(f2.OpsLog, "UninstallProductKey") || !containsCmd(f2.OpsLog, "ClearProductKeyFromRegistry") {
		t.Errorf("phải gọi UninstallProductKey và ClearProductKeyFromRegistry, log = %v", f2.OpsLog)
	}
	if !has(e2, logx.KindOk, "Đã gỡ cài đặt") {
		t.Errorf("thiếu xác nhận hoàn tất")
	}
}

// ── Tùy chọn 6 ─────────────────────────────────────────────────────────────────

func TestOption6RearmAndRestart(t *testing.T) {
	f := testprovider.New()
	ui := &testprovider.FakeUI{ConfirmDefault: true} // đồng ý cả rearm lẫn khởi động lại
	e := logx.New()
	Option6(f, ui, e)
	if !containsCmd(f.OpsLog, "ReArmWindows") {
		t.Errorf("phải gọi ReArmWindows")
	}
	if !f.Restarted {
		t.Errorf("đồng ý khởi động lại thì phải gọi Restart")
	}
}

func TestOption6Cancel(t *testing.T) {
	f := testprovider.New()
	ui := &testprovider.FakeUI{ConfirmDefault: false}
	e := logx.New()
	Option6(f, ui, e)
	if len(f.OpsLog) != 0 || f.Restarted {
		t.Errorf("hủy thì không rearm/khởi động lại")
	}
}

func containsCmd(log []string, cmd string) bool {
	for _, l := range log {
		if l == cmd {
			return true
		}
	}
	return false
}

// ── Tùy chọn 8 — Dọn Sạch Crack ───────────────────────────────────────────────

func containsUint(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func TestCleanCrackRemovesArtifacts(t *testing.T) {
	f := testprovider.New()
	f.Procs = []sysinfo.Process{
		{Name: "kmspico", PID: 100},
		{Name: "gatherosstate", PID: 200}, // nhị phân Windows hợp lệ — KHÔNG được kết thúc
		{Name: "clipup", PID: 250},        // nhị phân Windows hợp lệ — KHÔNG được kết thúc
		{Name: "chrome", PID: 300},        // không liên quan
	}
	f.Services = []sysinfo.Service{
		{Name: "Service_KMS", DisplayName: "KMS Service"},
		{Name: "Dhcp", DisplayName: "DHCP Client"}, // hợp lệ — không đụng
	}
	f.Tasks = []string{`\Microsoft\Windows\AutoKMS`, `\Microsoft\Windows\SvcRestartTask`}
	f.ExistingPaths = map[string]bool{`C:\Windows\SECOH-QAD.exe`: true}
	f.RemovedHijacks = 1
	f.ClearedKms = 1
	cfg := config.Parse("")
	e := logx.New()
	CleanCrack(f, cfg, &testprovider.FakeUI{ConfirmDefault: true}, e)

	if !containsUint(f.KilledPIDs, 100) {
		t.Error("phải kết thúc tiến trình crack (kmspico)")
	}
	if containsUint(f.KilledPIDs, 200) || containsUint(f.KilledPIDs, 250) {
		t.Error("KHÔNG được kết thúc nhị phân Windows hợp lệ (gatherosstate/clipup)")
	}
	if containsUint(f.KilledPIDs, 300) {
		t.Error("KHÔNG được kết thúc tiến trình không liên quan")
	}
	if !containsStr(f.StoppedSvcs, "Service_KMS") {
		t.Error("phải dừng+xóa dịch vụ crack")
	}
	if containsStr(f.StoppedSvcs, "Dhcp") {
		t.Error("KHÔNG được xóa dịch vụ hợp lệ")
	}
	if !containsStr(f.DeletedTasks, `\Microsoft\Windows\AutoKMS`) {
		t.Error("phải xóa tác vụ crack")
	}
	if !containsStr(f.DeletedPaths, `C:\Windows\SECOH-QAD.exe`) {
		t.Error("phải xóa tệp crack trong danh sách SuspiciousPaths")
	}
	for _, want := range []string{"UninstallProductKey", "RemoveSppImageHijack", "ClearKmsHost", "ClearProductKeyFromRegistry"} {
		if !containsStr(f.OpsLog, want) {
			t.Errorf("phải gọi %s", want)
		}
	}
}

func TestCleanCrackCancelledDoesNothing(t *testing.T) {
	f := testprovider.New()
	f.Procs = []sysinfo.Process{{Name: "kmspico", PID: 100}}
	CleanCrack(f, config.Parse(""), &testprovider.FakeUI{ConfirmDefault: false}, logx.New())
	if len(f.KilledPIDs) != 0 || len(f.OpsLog) != 0 {
		t.Error("hủy xác nhận thì KHÔNG được thay đổi gì")
	}
}
