//go:build windows

package sysinfo

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/vinhwincheck/wincheck/internal/license"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// WindowsProvider là hiện thực thật của Provider.
//
// KHÔNG dùng PowerShell hay bất kỳ tiến trình con nào: mọi truy vấn đi thẳng qua
// API Windows cấp cao —
//   - WMI/COM (root\CIMV2 và root\Microsoft\Windows\TaskScheduler) cho thông tin
//     hệ thống, bản quyền, dịch vụ, tiến trình, tác vụ, nhật ký sự kiện;
//   - Software Licensing API qua phương thức WMI (InstallProductKey,
//     UninstallProductKey, ReArmWindows…) thay cho slmgr.vbs;
//   - Registry API (advapi32) cho khóa dự phòng / KMS / ngày cài đặt;
//   - Token API cho kiểm tra quyền Admin.
type WindowsProvider struct{}

// NewWindows tạo một WindowsProvider.
func NewWindows() *WindowsProvider { return &WindowsProvider{} }

const (
	sppPlatformKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform`
	sppWow64Key    = `SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform`
	officeSppKey   = `SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform`
	currentVerKey  = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	taskNamespace  = `root\Microsoft\Windows\TaskScheduler`
)

// wmiQuery chạy một truy vấn WQL qua COM. Khóa OS thread để COM ổn định.
func wmiQuery(query string, dst any) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return wmi.Query(query, dst)
}

// wmiQueryNS như wmiQuery nhưng trong một namespace WMI khác.
func wmiQueryNS(query string, dst any, namespace string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return wmi.QueryNamespace(query, dst, namespace)
}

// ── Tùy chọn 1/2/3 — chỉ đọc ──────────────────────────────────────────────────

func (w *WindowsProvider) OSInfo() (OSInfo, error) {
	var dst []struct {
		Caption        string
		Version        string
		BuildNumber    string
		OSArchitecture string
	}
	if err := wmiQuery("SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem", &dst); err != nil {
		return OSInfo{}, err
	}
	if len(dst) == 0 {
		return OSInfo{}, fmt.Errorf("không đọc được Win32_OperatingSystem")
	}
	return OSInfo{
		Caption: dst[0].Caption,
		Version: dst[0].Version,
		Build:   dst[0].BuildNumber,
		Arch:    dst[0].OSArchitecture,
	}, nil
}

// HardwareInfo gom thông tin phần cứng chi tiết từ nhiều lớp WMI. Mỗi truy vấn
// độc lập: lỗi một lớp không làm hỏng các lớp còn lại (trả về phần đọc được).
func (w *WindowsProvider) HardwareInfo() (HardwareInfo, error) {
	var hw HardwareInfo

	var cpu []struct {
		Name                      string
		NumberOfCores             uint32
		NumberOfLogicalProcessors uint32
		MaxClockSpeed             uint32
	}
	if wmiQuery("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor", &cpu) == nil && len(cpu) > 0 {
		hw.CpuName = strings.TrimSpace(cpu[0].Name)
		hw.CpuClockMHz = cpu[0].MaxClockSpeed
		for _, c := range cpu { // cộng dồn nếu có nhiều socket
			hw.CpuCores += c.NumberOfCores
			hw.CpuThreads += c.NumberOfLogicalProcessors
		}
	}

	var cs []struct {
		Manufacturer        string
		Model               string
		Name                string
		TotalPhysicalMemory uint64
	}
	if wmiQuery("SELECT Manufacturer, Model, Name, TotalPhysicalMemory FROM Win32_ComputerSystem", &cs) == nil && len(cs) > 0 {
		hw.SystemVendor = strings.TrimSpace(cs[0].Manufacturer)
		hw.SystemModel = strings.TrimSpace(cs[0].Model)
		hw.ComputerName = cs[0].Name
		hw.RamTotalBytes = cs[0].TotalPhysicalMemory
	}

	var bb []struct {
		Manufacturer string
		Product      string
	}
	if wmiQuery("SELECT Manufacturer, Product FROM Win32_BaseBoard", &bb) == nil && len(bb) > 0 {
		hw.BoardVendor = strings.TrimSpace(bb[0].Manufacturer)
		hw.BoardProduct = strings.TrimSpace(bb[0].Product)
	}

	var bios []struct {
		Manufacturer      string
		SMBIOSBIOSVersion string
		ReleaseDate       string
	}
	if wmiQuery("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS", &bios) == nil && len(bios) > 0 {
		hw.BiosVendor = strings.TrimSpace(bios[0].Manufacturer)
		hw.BiosVersion = strings.TrimSpace(bios[0].SMBIOSBIOSVersion)
		hw.BiosDate = cimDate(bios[0].ReleaseDate)
	}

	var mem []struct {
		DeviceLocator string
		Capacity      uint64
		Speed         uint32
		Manufacturer  string
		PartNumber    string
	}
	if wmiQuery("SELECT DeviceLocator, Capacity, Speed, Manufacturer, PartNumber FROM Win32_PhysicalMemory", &mem) == nil {
		for _, m := range mem {
			hw.RamModules = append(hw.RamModules, RamModule{
				Locator:       strings.TrimSpace(m.DeviceLocator),
				CapacityBytes: m.Capacity,
				SpeedMHz:      m.Speed,
				Manufacturer:  strings.TrimSpace(m.Manufacturer),
				PartNumber:    strings.TrimSpace(m.PartNumber),
			})
		}
	}

	var gpu []struct {
		Name          string
		AdapterRAM    uint32
		DriverVersion string
	}
	if wmiQuery("SELECT Name, AdapterRAM, DriverVersion FROM Win32_VideoController", &gpu) == nil {
		for _, g := range gpu {
			if strings.TrimSpace(g.Name) == "" {
				continue
			}
			hw.Gpus = append(hw.Gpus, GpuInfo{
				Name:          strings.TrimSpace(g.Name),
				VramBytes:     uint64(g.AdapterRAM),
				DriverVersion: g.DriverVersion,
			})
		}
	}

	var disks []struct {
		Model     string
		Size      uint64
		MediaType string
	}
	if wmiQuery("SELECT Model, Size, MediaType FROM Win32_DiskDrive", &disks) == nil {
		for _, d := range disks {
			if strings.TrimSpace(d.Model) == "" {
				continue
			}
			hw.Disks = append(hw.Disks, DiskInfo{
				Model:     strings.TrimSpace(d.Model),
				SizeBytes: d.Size,
				MediaType: strings.TrimSpace(d.MediaType),
			})
		}
	}

	return hw, nil
}

// cimDate chuyển CIM_DATETIME (vd "20210302000000.000000+000") sang "2021-03-02".
func cimDate(s string) string {
	if len(s) < 8 {
		return ""
	}
	return s[0:4] + "-" + s[4:6] + "-" + s[6:8]
}

func (w *WindowsProvider) OEMProductKey() (string, error) {
	var dst []struct{ OA3xOriginalProductKey string }
	if err := wmiQuery("SELECT OA3xOriginalProductKey FROM SoftwareLicensingService", &dst); err != nil {
		return "", err
	}
	if len(dst) == 0 {
		return "", nil
	}
	return dst[0].OA3xOriginalProductKey, nil
}

// InstalledProductKey trả về khóa sản phẩm ĐẦY ĐỦ 25 ký tự đang cài, giải mã từ
// khối nhị phân DigitalProductId trong Registry (giống ShowKeyPlus/ProduKey).
// Windows chỉ để lộ 5 ký tự cuối qua WMI; khối này chứa toàn bộ khóa. Trả về ""
// nếu không đọc được hoặc khối không hợp lệ.
func (w *WindowsProvider) InstalledProductKey() (string, error) {
	b := regBinary(registry.LOCAL_MACHINE, currentVerKey, "DigitalProductId")
	return license.DecodeDigitalProductID(b), nil
}

type slpRow struct {
	Name                                      string
	Description                               string
	PartialProductKey                         string
	LicenseStatus                             uint32
	DiscoveredKeyManagementServiceMachineName string
	KeyManagementServiceCurrentCount          uint32
}

func (w *WindowsProvider) ActiveWindowsLicense() (*License, error) {
	var dst []slpRow
	err := wmiQuery(
		"SELECT Name, Description, PartialProductKey, LicenseStatus, "+
			"DiscoveredKeyManagementServiceMachineName, KeyManagementServiceCurrentCount "+
			"FROM SoftwareLicensingProduct "+
			"WHERE PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'", &dst)
	if err != nil {
		return nil, err
	}
	if len(dst) == 0 {
		return nil, nil
	}
	d := dst[0]
	return &License{
		Name:              d.Name,
		Description:       d.Description,
		PartialKey:        d.PartialProductKey,
		LicenseStatus:     d.LicenseStatus,
		KmsDiscoveredName: d.DiscoveredKeyManagementServiceMachineName,
		KmsCurrentCount:   d.KeyManagementServiceCurrentCount,
	}, nil
}

func (w *WindowsProvider) AllLicensingProducts() ([]License, error) {
	var dst []struct {
		Name              string
		PartialProductKey string
	}
	if err := wmiQuery("SELECT Name, PartialProductKey FROM SoftwareLicensingProduct", &dst); err != nil {
		return nil, err
	}
	out := make([]License, 0, len(dst))
	for _, d := range dst {
		out = append(out, License{Name: d.Name, PartialKey: d.PartialProductKey})
	}
	return out, nil
}

func (w *WindowsProvider) BackupProductKey() (string, error) {
	return regString(registry.LOCAL_MACHINE, sppPlatformKey, "BackupProductKeyDefault"), nil
}

// ── Thay đổi hệ thống (qua phương thức WMI, không dùng slmgr.vbs) ─────────────

func (w *WindowsProvider) DeleteBackupProductKey() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sppPlatformKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue("BackupProductKeyDefault")
}

// InstallProductKey cài key mới qua SoftwareLicensingService.InstallProductKey
// rồi làm mới trạng thái — tương đương slmgr /ipk nhưng gọi thẳng API.
func (w *WindowsProvider) InstallProductKey(key string) error {
	if err := callSlsMethod("InstallProductKey", key); err != nil {
		return err
	}
	return callSlsMethod("RefreshLicenseStatus")
}

// UninstallProductKey gỡ key của sản phẩm Windows đang hoạt động — tương đương
// slmgr /upk (phương thức nằm trên chính đối tượng SoftwareLicensingProduct).
func (w *WindowsProvider) UninstallProductKey() error {
	return callWindowsProductMethod("UninstallProductKey")
}

// ClearProductKeyFromRegistry xóa key khỏi registry — tương đương slmgr /cpky.
func (w *WindowsProvider) ClearProductKeyFromRegistry() error {
	return callSlsMethod("ClearProductKeyFromRegistry")
}

// ReArmWindows đặt lại bộ đếm kích hoạt — tương đương slmgr /rearm.
func (w *WindowsProvider) ReArmWindows() error {
	return callSlsMethod("ReArmWindows")
}

func (w *WindowsProvider) Restart() error {
	// Khởi động lại qua API Windows (ExitWindowsEx) sau khi bật đặc quyền shutdown.
	if err := enablePrivilege("SeShutdownPrivilege"); err != nil {
		return err
	}
	const (
		ewxReboot           = 0x00000002
		ewxForce            = 0x00000004
		shtdnReasonMajorApp = 0x00040000
	)
	return windows.ExitWindowsEx(ewxReboot|ewxForce, shtdnReasonMajorApp)
}

// ── Dọn sạch crack ──────────────────────────────────────────────────────────

// RemoveSppImageHijack gỡ mọi hook IFEO (VerifierDlls/GlobalFlag/Debugger) trên
// SppExtComObj.exe/sppsvc.exe/osppsvc.exe. Trả về số giá trị đã xóa.
func (w *WindowsProvider) RemoveSppImageHijack() (int, error) {
	const ifeo = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	n := 0
	for _, exe := range []string{"SppExtComObj.exe", "sppsvc.exe", "osppsvc.exe"} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeo+`\`+exe, registry.SET_VALUE)
		if err != nil {
			continue // subkey không tồn tại → không có gì để gỡ
		}
		// Best-effort: DeleteValue trả lỗi nếu giá trị không có; chỉ đếm khi xóa được.
		for _, val := range []string{"VerifierDlls", "GlobalFlag", "Debugger"} {
			if err := k.DeleteValue(val); err == nil {
				n++
			}
		}
		k.Close()
	}
	return n, nil
}

// ClearKmsHost xóa cấu hình máy chủ KMS (KeyManagementServiceName/Port) mà công cụ
// crack đặt trong Registry cho cả Windows và Office. Trả về số giá trị đã xóa.
func (w *WindowsProvider) ClearKmsHost() (int, error) {
	n := 0
	for _, path := range []string{sppPlatformKey, sppWow64Key, officeSppKey} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
		if err != nil {
			continue
		}
		for _, val := range []string{"KeyManagementServiceName", "KeyManagementServicePort"} {
			if err := k.DeleteValue(val); err == nil {
				n++
			}
		}
		k.Close()
	}
	return n, nil
}

// DeletePath xóa một tệp hoặc thư mục (kể cả cây con). Best-effort: tệp đang bị
// khóa (đang nạp vào tiến trình) sẽ trả lỗi để tầng trên ghi nhật ký.
func (w *WindowsProvider) DeletePath(path string) error {
	return os.RemoveAll(path)
}

// StopDeleteService dừng rồi xóa một dịch vụ Windows qua Service Control Manager.
func (w *WindowsProvider) StopDeleteService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err // dịch vụ không tồn tại
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop) // bỏ qua lỗi nếu vốn đã dừng
	return s.Delete()
}

// KillProcess kết thúc một tiến trình theo PID qua TerminateProcess.
func (w *WindowsProvider) KillProcess(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// DeleteScheduledTask xóa một tác vụ định kỳ qua COM Task Scheduler 2.0
// (Schedule.Service), không gọi schtasks.exe. fullName dạng "\Folder\Con\Tên".
func (w *WindowsProvider) DeleteScheduledTask(fullName string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 1 {
			return err
		}
	}
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return err
	}
	defer unk.Release()
	svcDisp, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer svcDisp.Release()
	if _, err := oleutil.CallMethod(svcDisp, "Connect"); err != nil {
		return err
	}

	folder, leaf := `\`, fullName
	if idx := strings.LastIndex(fullName, `\`); idx >= 0 {
		if idx > 0 {
			folder = fullName[:idx]
		}
		leaf = fullName[idx+1:]
	}
	fRaw, err := oleutil.CallMethod(svcDisp, "GetFolder", folder)
	if err != nil {
		return err
	}
	f := fRaw.ToIDispatch()
	defer fRaw.Clear()
	_, err = oleutil.CallMethod(f, "DeleteTask", leaf, 0)
	return err
}

// ── Tùy chọn 7 ─────────────────────────────────────────────────────────────────

func (w *WindowsProvider) KmsHostName() (string, error) {
	if v := regString(registry.LOCAL_MACHINE, sppPlatformKey, "KeyManagementServiceName"); v != "" {
		return v, nil
	}
	if v := regString(registry.LOCAL_MACHINE, sppWow64Key, "KeyManagementServiceName"); v != "" {
		return v, nil
	}
	var dst []struct{ KeyManagementServiceMachine string }
	if err := wmiQuery("SELECT KeyManagementServiceMachine FROM SoftwareLicensingService", &dst); err == nil {
		for _, d := range dst {
			if d.KeyManagementServiceMachine != "" {
				return d.KeyManagementServiceMachine, nil
			}
		}
	}
	return "", nil
}

func (w *WindowsProvider) OfficeKmsHostName() (string, error) {
	return regString(registry.LOCAL_MACHINE, officeSppKey, "KeyManagementServiceName"), nil
}

// FindOfficeDirs tìm kiếm tất cả các thư mục cài đặt Office có chứa file ospp.vbs.
func (w *WindowsProvider) FindOfficeDirs() []string {
	var roots []string
	addRoot := func(v string) {
		if v != "" {
			roots = append(roots, v)
		}
	}
	addRoot(os.Getenv("ProgramFiles"))
	addRoot(os.Getenv("ProgramFiles(x86)"))
	addRoot(os.Getenv("ProgramW6432"))

	subPaths := []string{
		filepath.Join("Microsoft Office", "root", "Office16"),
		filepath.Join("Microsoft Office", "Office16"),
		filepath.Join("Microsoft Office", "root", "Office15"),
		filepath.Join("Microsoft Office", "Office15"),
		filepath.Join("Microsoft Office", "root", "Office14"),
		filepath.Join("Microsoft Office", "Office14"),
	}

	seen := make(map[string]bool)
	var found []string

	for _, root := range roots {
		for _, sub := range subPaths {
			candidate := filepath.Join(root, sub)
			norm := filepath.Clean(strings.ToLower(candidate))
			if seen[norm] {
				continue
			}
			seen[norm] = true

			osppPath := filepath.Join(candidate, "ospp.vbs")
			if fi, err := os.Stat(osppPath); err == nil && !fi.IsDir() {
				found = append(found, candidate)
			}
		}
	}
	return found
}

// RunOspp chạy cscript //nologo ospp.vbs với các tham số tương ứng trong thư mục dir.
func (w *WindowsProvider) RunOspp(dir string, args ...string) (string, error) {
	cscriptPath := "cscript.exe"
	if sysRoot := os.Getenv("SystemRoot"); sysRoot != "" {
		p := filepath.Join(sysRoot, "System32", "cscript.exe")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			cscriptPath = p
		}
	}

	cmdArgs := append([]string{"//nologo", "ospp.vbs"}, args...)
	cmd := exec.Command(cscriptPath, cmdArgs...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (w *WindowsProvider) WindowsLicensingProduct() (*LicensingProduct, error) {
	var dst []struct {
		PartialProductKey    string
		LicenseStatus        uint32
		Description          string
		GracePeriodRemaining uint32
	}
	err := wmiQuery(
		"SELECT PartialProductKey, LicenseStatus, Description, GracePeriodRemaining "+
			"FROM SoftwareLicensingProduct "+
			"WHERE ApplicationID='"+WindowsAppID+"' AND PartialProductKey IS NOT NULL", &dst)
	if err != nil {
		return nil, err
	}
	if len(dst) == 0 {
		return nil, nil
	}
	d := dst[0]
	return &LicensingProduct{
		PartialKey:      d.PartialProductKey,
		LicenseStatus:   d.LicenseStatus,
		Description:     d.Description,
		GracePeriodMins: d.GracePeriodRemaining,
	}, nil
}

func (w *WindowsProvider) ProbeLocalPort(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (w *WindowsProvider) ListServices() ([]Service, error) {
	var dst []struct {
		Name        string
		DisplayName string
	}
	if err := wmiQuery("SELECT Name, DisplayName FROM Win32_Service", &dst); err != nil {
		return nil, err
	}
	out := make([]Service, 0, len(dst))
	for _, d := range dst {
		out = append(out, Service{Name: d.Name, DisplayName: d.DisplayName})
	}
	return out, nil
}

// ListScheduledTaskNames đọc tác vụ định kỳ qua namespace WMI của Task Scheduler
// (MSFT_ScheduledTask) — API cấp cao, không gọi schtasks.exe.
func (w *WindowsProvider) ListScheduledTaskNames() ([]string, error) {
	var dst []struct {
		TaskName string
		TaskPath string
	}
	if err := wmiQueryNS("SELECT TaskName, TaskPath FROM MSFT_ScheduledTask", &dst, taskNamespace); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(dst))
	for _, d := range dst {
		names = append(names, d.TaskPath+d.TaskName)
	}
	return names, nil
}

func (w *WindowsProvider) ListProcesses() ([]Process, error) {
	var dst []struct {
		Name      string
		ProcessId uint32
	}
	if err := wmiQuery("SELECT Name, ProcessId FROM Win32_Process", &dst); err != nil {
		return nil, err
	}
	out := make([]Process, 0, len(dst))
	for _, d := range dst {
		out = append(out, Process{
			Name: strings.TrimSuffix(strings.ToLower(d.Name), ".exe"),
			PID:  d.ProcessId,
		})
	}
	return out, nil
}

func (w *WindowsProvider) PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (w *WindowsProvider) FileModTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

func (w *WindowsProvider) WindowsInstallDate() (time.Time, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVerKey, registry.QUERY_VALUE)
	if err != nil {
		return time.Time{}, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("InstallDate")
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0), true
}

func (w *WindowsProvider) HasUpdateEventNear(t time.Time, withinHours float64) bool {
	var dst []struct{ TimeGenerated time.Time }
	err := wmiQuery(
		"SELECT TimeGenerated FROM Win32_NTLogEvent "+
			"WHERE Logfile='System' AND EventCode=19 "+
			"AND SourceName='Microsoft-Windows-WindowsUpdateClient'", &dst)
	if err != nil {
		return false
	}
	for _, d := range dst {
		if abs(d.TimeGenerated.Sub(t).Hours()) < withinHours {
			return true
		}
	}
	return false
}

func (w *WindowsProvider) SppSecurityEvents() ([]EventEntry, error) {
	var dst []struct {
		EventCode     uint32
		SourceName    string
		Message       string
		TimeGenerated time.Time
	}
	err := wmiQuery(
		"SELECT EventCode, SourceName, Message, TimeGenerated FROM Win32_NTLogEvent "+
			"WHERE Logfile='System' AND "+
			"(EventCode=12288 OR EventCode=12289 OR EventCode=12290 OR EventCode=8198)", &dst)
	if err != nil {
		return nil, err
	}
	var out []EventEntry
	for _, d := range dst {
		if !strings.Contains(d.SourceName, "Security-SPP") &&
			!strings.Contains(d.SourceName, "SoftwareProtection") {
			continue
		}
		out = append(out, EventEntry{
			EventCode:     d.EventCode,
			Source:        d.SourceName,
			Message:       d.Message,
			TimeGenerated: d.TimeGenerated,
		})
	}
	return out, nil
}

// ── Mạng ────────────────────────────────────────────────────────────────────────

func (w *WindowsProvider) HasInternet() bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 1500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (w *WindowsProvider) ResolveHost(host string) ([]string, error) {
	return net.LookupHost(host)
}

// ── Ngữ cảnh ──────────────────────────────────────────────────────────────────────

// IsAdmin kiểm tra token hiệu lực của tiến trình có thuộc nhóm Administrators
// (đã bật) hay không — dùng CheckTokenMembership của Win32.
func (w *WindowsProvider) IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// ── COM: gọi phương thức Software Licensing qua WMI ───────────────────────────

// withWmiObject mở COM, lấy một đối tượng WMI theo WQL rồi gọi fn trên đối tượng
// đầu tiên tìm được.
func withWmiObject(query string, fn func(obj *ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		// S_FALSE nghĩa là COM đã được khởi tạo trên thread này — vẫn dùng được.
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 1 {
			return err
		}
	}
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return err
	}
	defer unk.Release()
	loc, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer loc.Release()

	svcRaw, err := oleutil.CallMethod(loc, "ConnectServer", nil, `root\CIMV2`)
	if err != nil {
		return err
	}
	svc := svcRaw.ToIDispatch()
	defer svcRaw.Clear()

	resRaw, err := oleutil.CallMethod(svc, "ExecQuery", query)
	if err != nil {
		return err
	}
	res := resRaw.ToIDispatch()
	defer resRaw.Clear()

	countRaw, err := oleutil.GetProperty(res, "Count")
	if err != nil {
		return err
	}
	count := int(countRaw.Val)
	countRaw.Clear()
	if count == 0 {
		return fmt.Errorf("không tìm thấy đối tượng WMI cho truy vấn")
	}

	itemRaw, err := oleutil.CallMethod(res, "ItemIndex", 0)
	if err != nil {
		return err
	}
	item := itemRaw.ToIDispatch()
	defer itemRaw.Clear()

	return fn(item)
}

// callSlsMethod gọi một phương thức trên SoftwareLicensingService.
func callSlsMethod(method string, args ...any) error {
	return withWmiObject("SELECT * FROM SoftwareLicensingService", func(obj *ole.IDispatch) error {
		ret, err := oleutil.CallMethod(obj, method, args...)
		if err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		defer ret.Clear()
		if code := uint32(ret.Val); code != 0 {
			return fmt.Errorf("%s trả về mã lỗi 0x%08X", method, code)
		}
		return nil
	})
}

// callWindowsProductMethod gọi một phương thức trên mục cấp phép Windows đang dùng.
func callWindowsProductMethod(method string, args ...any) error {
	q := "SELECT * FROM SoftwareLicensingProduct WHERE ApplicationID='" +
		WindowsAppID + "' AND PartialProductKey IS NOT NULL"
	return withWmiObject(q, func(obj *ole.IDispatch) error {
		ret, err := oleutil.CallMethod(obj, method, args...)
		if err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		defer ret.Clear()
		if code := uint32(ret.Val); code != 0 {
			return fmt.Errorf("%s trả về mã lỗi 0x%08X", method, code)
		}
		return nil
	})
}

// ── Tiện ích ─────────────────────────────────────────────────────────────────────

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// SppImageHijack kiểm tra Image File Execution Options (IFEO) trên các nhị phân
// của Software Protection Platform. KMSpico gắn VerifierDlls=SECOH-QAD.dll và
// KMS_VL_ALL gắn VerifierDlls=SppExtComObjHook.dll vào SppExtComObj.exe; các bản
// cũ đặt Debugger=SppExtComObjPatcher.exe trên sppsvc.exe/osppsvc.exe. Không phần
// mềm hợp lệ nào gắn Application-Verifier DLL hay Debugger lên các tệp này, nên
// bất kỳ giá trị nào khác rỗng đều là dấu hiệu bị vá. Trả về bằng chứng và true.
func (w *WindowsProvider) SppImageHijack() (string, bool) {
	const ifeo = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	for _, exe := range []string{"SppExtComObj.exe", "sppsvc.exe", "osppsvc.exe"} {
		base := ifeo + `\` + exe
		for _, val := range []string{"VerifierDlls", "Debugger"} {
			if v := strings.TrimSpace(regString(registry.LOCAL_MACHINE, base, val)); v != "" {
				return exe + " (" + val + ": " + v + ")", true
			}
		}
	}
	return "", false
}

// regBinary đọc một giá trị REG_BINARY. Trả về nil nếu không có.
func regBinary(root registry.Key, path, name string) []byte {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetBinaryValue(name)
	if err != nil {
		return nil
	}
	return v
}

// enablePrivilege bật một đặc quyền trên token của tiến trình hiện tại.
func enablePrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()

	var luid windows.LUID
	np, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, np, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
