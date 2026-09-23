// Package testprovider cung cấp Provider và Interaction giả lập cho kiểm thử tầng
// điều phối (audit, ops) mà không cần Windows thật.
package testprovider

import (
	"errors"
	"strings"
	"time"

	"github.com/vinhwincheck/wincheck/internal/sysinfo"
)

// Fake hiện thực sysinfo.Provider bằng dữ liệu cấu hình sẵn.
type Fake struct {
	OS           sysinfo.OSInfo
	OSErr        error
	Hardware     sysinfo.HardwareInfo
	HardwareErr  error
	OEMKey       string
	InstalledKey string // khóa đầy đủ giả lập (giải mã DigitalProductId)

	ActiveLicense *sysinfo.License
	ActiveErr     error
	AllProducts   []sysinfo.License

	Backup    string
	DeleteErr error
	Deleted   bool

	SppHijack string // bằng chứng hook IFEO giả lập ("" = sạch)

	// Dọn sạch crack: giá trị trả về + ghi lại lời gọi.
	RemovedHijacks int
	ClearedKms     int
	CleanErr       error // lỗi giả lập chung cho các thao tác dọn crack
	DeletedPaths   []string
	StoppedSvcs    []string
	KilledPIDs     []uint32
	DeletedTasks   []string

	// Lỗi giả lập cho các thao tác Software Licensing API.
	InstallErr   error
	UninstallErr error
	ClearErr     error
	ReArmErr     error
	// OpsLog ghi lại các thao tác đã gọi (để kiểm thử thứ tự/việc có gọi hay không).
	OpsLog []string

	Restarted bool

	Kms       string
	OfficeKms string
	Product   *sysinfo.LicensingProduct

	// Office giả lập
	OfficeDirs    []string
	OsppResponses map[string]string
	OsppCalls     []string
	OsppErr       error
	OsppHook      func(dir string, args ...string) (string, error)

	OpenPorts map[int]bool
	Services  []sysinfo.Service
	Tasks     []string
	Procs     []sysinfo.Process

	ExistingPaths map[string]bool
	ModTimes      map[string]time.Time
	Install       time.Time
	InstallOK     bool
	NearUpdate    bool
	Events        []sysinfo.EventEntry

	Internet bool
	Resolves map[string][]string

	Admin bool
}

// New tạo Fake với các map đã khởi tạo và mặc định hợp lý.
func New() *Fake {
	return &Fake{
		OpenPorts:     map[int]bool{},
		ExistingPaths: map[string]bool{},
		ModTimes:      map[string]time.Time{},
		Resolves:      map[string][]string{},
		OsppResponses: map[string]string{},
	}
}

func (f *Fake) OSInfo() (sysinfo.OSInfo, error) { return f.OS, f.OSErr }

func (f *Fake) HardwareInfo() (sysinfo.HardwareInfo, error) { return f.Hardware, f.HardwareErr }

func (f *Fake) OEMProductKey() (string, error) { return f.OEMKey, nil }

func (f *Fake) InstalledProductKey() (string, error) { return f.InstalledKey, nil }

func (f *Fake) ActiveWindowsLicense() (*sysinfo.License, error) {
	return f.ActiveLicense, f.ActiveErr
}

func (f *Fake) AllLicensingProducts() ([]sysinfo.License, error) { return f.AllProducts, nil }

func (f *Fake) BackupProductKey() (string, error) { return f.Backup, nil }

func (f *Fake) SppImageHijack() (string, bool) { return f.SppHijack, f.SppHijack != "" }

func (f *Fake) DeleteBackupProductKey() error {
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	f.Deleted = true
	return nil
}

func (f *Fake) InstallProductKey(key string) error {
	f.OpsLog = append(f.OpsLog, "InstallProductKey "+key)
	return f.InstallErr
}

func (f *Fake) UninstallProductKey() error {
	f.OpsLog = append(f.OpsLog, "UninstallProductKey")
	return f.UninstallErr
}

func (f *Fake) ClearProductKeyFromRegistry() error {
	f.OpsLog = append(f.OpsLog, "ClearProductKeyFromRegistry")
	return f.ClearErr
}

func (f *Fake) ReArmWindows() error {
	f.OpsLog = append(f.OpsLog, "ReArmWindows")
	return f.ReArmErr
}

func (f *Fake) Restart() error { f.Restarted = true; return nil }

// ── Dọn sạch crack (ghi lại lời gọi để kiểm thử) ────────────────────────────

func (f *Fake) RemoveSppImageHijack() (int, error) {
	f.OpsLog = append(f.OpsLog, "RemoveSppImageHijack")
	return f.RemovedHijacks, f.CleanErr
}

func (f *Fake) ClearKmsHost() (int, error) {
	f.OpsLog = append(f.OpsLog, "ClearKmsHost")
	return f.ClearedKms, nil
}

func (f *Fake) DeletePath(path string) error {
	f.DeletedPaths = append(f.DeletedPaths, path)
	return f.CleanErr
}

func (f *Fake) StopDeleteService(name string) error {
	f.StoppedSvcs = append(f.StoppedSvcs, name)
	return f.CleanErr
}

func (f *Fake) KillProcess(pid uint32) error {
	f.KilledPIDs = append(f.KilledPIDs, pid)
	return f.CleanErr
}

func (f *Fake) DeleteScheduledTask(fullName string) error {
	f.DeletedTasks = append(f.DeletedTasks, fullName)
	return f.CleanErr
}

func (f *Fake) KmsHostName() (string, error) { return f.Kms, nil }

func (f *Fake) OfficeKmsHostName() (string, error) { return f.OfficeKms, nil }

func (f *Fake) FindOfficeDirs() []string { return f.OfficeDirs }

func (f *Fake) RunOspp(dir string, args ...string) (string, error) {
	callKey := strings.Join(args, " ")
	f.OsppCalls = append(f.OsppCalls, dir+":"+callKey)
	if f.OsppHook != nil {
		return f.OsppHook(dir, args...)
	}
	if f.OsppErr != nil {
		return "", f.OsppErr
	}
	if f.OsppResponses != nil {
		if resp, ok := f.OsppResponses[callKey]; ok {
			return resp, nil
		}
		if resp, ok := f.OsppResponses[dir+":"+callKey]; ok {
			return resp, nil
		}
	}
	return "", nil
}

func (f *Fake) WindowsLicensingProduct() (*sysinfo.LicensingProduct, error) {
	return f.Product, nil
}

func (f *Fake) ProbeLocalPort(port int) bool { return f.OpenPorts[port] }

func (f *Fake) ListServices() ([]sysinfo.Service, error) { return f.Services, nil }

func (f *Fake) ListScheduledTaskNames() ([]string, error) { return f.Tasks, nil }

func (f *Fake) ListProcesses() ([]sysinfo.Process, error) { return f.Procs, nil }

func (f *Fake) PathExists(path string) bool {
	for k, v := range f.ExistingPaths {
		if strings.EqualFold(k, path) {
			return v
		}
	}
	return false
}

func (f *Fake) FileModTime(path string) (time.Time, bool) {
	t, ok := f.ModTimes[path]
	return t, ok
}

func (f *Fake) WindowsInstallDate() (time.Time, bool) { return f.Install, f.InstallOK }

func (f *Fake) HasUpdateEventNear(t time.Time, withinHours float64) bool { return f.NearUpdate }

func (f *Fake) SppSecurityEvents() ([]sysinfo.EventEntry, error) { return f.Events, nil }

func (f *Fake) HasInternet() bool { return f.Internet }

func (f *Fake) ResolveHost(host string) ([]string, error) {
	if ips, ok := f.Resolves[host]; ok {
		return ips, nil
	}
	return nil, errors.New("không phân giải được")
}

func (f *Fake) IsAdmin() bool { return f.Admin }

// ── Interaction giả lập ────────────────────────────────────────────────────────

// FakeUI hiện thực ops.Interaction bằng câu trả lời cấu hình sẵn.
type FakeUI struct {
	// ConfirmFunc, nếu đặt, quyết định kết quả theo message/title.
	ConfirmFunc func(message, title string) bool
	// ConfirmDefault dùng khi ConfirmFunc == nil.
	ConfirmDefault bool
	// KeyValue và KeyOK là kết quả cố định của PromptKey.
	KeyValue string
	KeyOK    bool

	Confirms []string // nhật ký các message đã hỏi
	Prompts  []string
}

func (u *FakeUI) Confirm(message, title string) bool {
	u.Confirms = append(u.Confirms, message)
	if u.ConfirmFunc != nil {
		return u.ConfirmFunc(message, title)
	}
	return u.ConfirmDefault
}

func (u *FakeUI) PromptKey(prompt, title string) (string, bool) {
	u.Prompts = append(u.Prompts, prompt)
	return u.KeyValue, u.KeyOK
}
