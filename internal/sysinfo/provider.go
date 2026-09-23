// Package sysinfo trừu tượng hóa mọi truy cập tới hệ thống Windows (WMI,
// Registry, slmgr, mạng, tiến trình…) sau một interface Provider.
//
// Tách interface khỏi phần hiện thực cho phép tầng điều phối (audit, ops) được
// kiểm thử với một Provider giả lập, không cần Windows thật. Phần hiện thực thật
// nằm ở windows.go (chỉ biên dịch trên Windows).
package sysinfo

import "time"

// OSInfo là thông tin hệ điều hành từ Win32_OperatingSystem.
type OSInfo struct {
	Caption string
	Version string
	Build   string
	Arch    string
}

// License mô tả bản quyền Windows đang hoạt động (SoftwareLicensingProduct).
type License struct {
	Name              string
	Description       string
	PartialKey        string
	LicenseStatus     uint32
	KmsDiscoveredName string
	KmsCurrentCount   uint32
}

// LicensingProduct là mục cấp phép Windows dùng cho phân tích GVLK/hết hạn
// (Win32_SoftwareLicensingProduct với ApplicationID của Windows).
type LicensingProduct struct {
	PartialKey      string
	LicenseStatus   uint32
	Description     string
	GracePeriodMins uint32
}

// HardwareInfo là thông tin phần cứng/hệ thống chi tiết (kiểu CPU-Z), gom từ nhiều
// lớp WMI (Win32_Processor, ComputerSystem, BaseBoard, BIOS, PhysicalMemory,
// VideoController, DiskDrive).
type HardwareInfo struct {
	CpuName      string
	CpuCores     uint32
	CpuThreads   uint32
	CpuClockMHz  uint32
	SystemVendor string
	SystemModel  string
	ComputerName string
	BoardVendor  string
	BoardProduct string
	BiosVendor   string
	BiosVersion  string
	BiosDate     string // YYYY-MM-DD (đã chuẩn hóa từ CIM_DATETIME)

	RamTotalBytes uint64
	RamModules    []RamModule
	Gpus          []GpuInfo
	Disks         []DiskInfo
}

// RamModule là một thanh RAM cắm trên máy (Win32_PhysicalMemory).
type RamModule struct {
	Locator       string
	CapacityBytes uint64
	SpeedMHz      uint32
	Manufacturer  string
	PartNumber    string
}

// GpuInfo là một card đồ họa (Win32_VideoController).
type GpuInfo struct {
	Name          string
	VramBytes     uint64
	DriverVersion string
}

// DiskInfo là một ổ đĩa vật lý (Win32_DiskDrive).
type DiskInfo struct {
	Model     string
	SizeBytes uint64
	MediaType string
}

// Service là một dịch vụ Windows (Win32_Service).
type Service struct {
	Name        string
	DisplayName string
}

// Process là một tiến trình đang chạy (Win32_Process).
type Process struct {
	Name string
	PID  uint32
}

// EventEntry là một mục nhật ký sự kiện (Win32_NTLogEvent).
type EventEntry struct {
	EventCode     uint32
	Source        string
	Message       string
	TimeGenerated time.Time
}

// Provider cung cấp mọi dữ liệu và thao tác hệ thống mà tầng điều phối cần.
//
// Các hàm trả về error khi truy vấn thất bại. Các hàm trả về (T, bool) dùng bool
// để báo dữ liệu có tồn tại hay không (ví dụ tệp có / không có).
type Provider interface {
	// ── Chỉ đọc (Tùy chọn 1, 2, 3) ─────────────────────────────────────────
	OSInfo() (OSInfo, error)
	HardwareInfo() (HardwareInfo, error) // thông tin phần cứng chi tiết (kiểu CPU-Z)
	OEMProductKey() (string, error)
	InstalledProductKey() (string, error) // khóa đầy đủ giải mã từ DigitalProductId ("" nếu không có)
	ActiveWindowsLicense() (*License, error)
	AllLicensingProducts() ([]License, error) // mọi mục SoftwareLicensingProduct (nhận diện ấn bản)
	BackupProductKey() (string, error)

	// ── Thay đổi hệ thống (qua Software Licensing API, không dùng slmgr.vbs) ──
	DeleteBackupProductKey() error      // Tùy chọn 3 (cần admin)
	InstallProductKey(key string) error // Tùy chọn 4 — thay slmgr /ipk
	UninstallProductKey() error         // Tùy chọn 5 — thay slmgr /upk
	ClearProductKeyFromRegistry() error // Tùy chọn 5 — thay slmgr /cpky
	ReArmWindows() error                // Tùy chọn 6 — thay slmgr /rearm
	Restart() error                     // Tùy chọn 6

	// ── Dọn sạch crack (cần admin) ──────────────────────────────────────────
	RemoveSppImageHijack() (int, error)        // gỡ hook IFEO trên nhị phân SPP, trả về số giá trị đã xóa
	ClearKmsHost() (int, error)                // xóa KeyManagementServiceName/Port trong Registry
	DeletePath(path string) error              // xóa tệp/thư mục công cụ crack
	StopDeleteService(name string) error       // dừng và xóa một dịch vụ
	KillProcess(pid uint32) error              // kết thúc một tiến trình
	DeleteScheduledTask(fullName string) error // xóa một tác vụ định kỳ (Task Scheduler COM)

	// ── Office (Tùy chọn 9) ──────────────────────────────────────────────────
	FindOfficeDirs() []string
	RunOspp(dir string, args ...string) (string, error)

	// ── Kiểm tra bên thứ ba (Tùy chọn 7) ───────────────────────────────────
	KmsHostName() (string, error)
	OfficeKmsHostName() (string, error)
	WindowsLicensingProduct() (*LicensingProduct, error)
	ProbeLocalPort(port int) bool
	SppImageHijack() (string, bool) // hook IFEO (VerifierDlls/Debugger) trên nhị phân SPP; ("" ,false) nếu sạch
	ListServices() ([]Service, error)
	ListScheduledTaskNames() ([]string, error)
	ListProcesses() ([]Process, error)
	PathExists(path string) bool
	FileModTime(path string) (time.Time, bool)
	WindowsInstallDate() (time.Time, bool)
	HasUpdateEventNear(t time.Time, withinHours float64) bool
	SppSecurityEvents() ([]EventEntry, error)

	// ── Mạng ────────────────────────────────────────────────────────────────
	HasInternet() bool
	ResolveHost(host string) ([]string, error)

	// ── Ngữ cảnh ──────────────────────────────────────────────────────────────
	IsAdmin() bool
}

// SppStorePath là đường dẫn tệp kho tin cậy SPP (kiểm tra dấu thời gian TSforge).
const SppStorePath = `C:\Windows\System32\spp\store\2.0\data.dat`

// WindowsAppID là ApplicationID của họ sản phẩm Windows trong SLP, dùng để lọc
// đúng mục cấp phép Windows (bỏ qua Office…).
const WindowsAppID = "55c92734-d682-4d71-983e-d6ec3f16059f"
