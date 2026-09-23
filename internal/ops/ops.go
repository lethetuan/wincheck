// Package ops điều phối các Tùy chọn 1–6 (xem/kiểm tra/thay đổi bản quyền).
//
// Mỗi tùy chọn nhận một sysinfo.Provider (dữ liệu hệ thống), một Interaction
// (hộp thoại người dùng) và một logx.Emitter (nhật ký). Nhờ đó toàn bộ luồng có
// thể kiểm thử với provider và interaction giả lập.
package ops

import (
	"regexp"
	"strings"
	"time"

	"github.com/vinhwincheck/wincheck/internal/audit"
	"github.com/vinhwincheck/wincheck/internal/config"
	"github.com/vinhwincheck/wincheck/internal/i18n"
	"github.com/vinhwincheck/wincheck/internal/license"
	"github.com/vinhwincheck/wincheck/internal/logx"
	"github.com/vinhwincheck/wincheck/internal/sysinfo"
)

// Interaction là các hộp thoại người dùng mà tầng điều phối cần.
type Interaction interface {
	// Confirm hiển thị câu hỏi Có/Không, trả về true nếu người dùng chọn Có.
	Confirm(message, title string) bool
	// PromptKey yêu cầu nhập một chuỗi; ok=false nếu người dùng hủy.
	PromptKey(prompt, title string) (value string, ok bool)
}

// askShowFullKey hỏi có hiển thị đầy đủ key hay không (ghép ngữ cảnh + câu hỏi chung).
func askShowFullKey(ui Interaction, ctx string) bool {
	return ui.Confirm(ctx+"\n\n"+i18n.T("ShowKey_Q"), i18n.T("ShowKey_Title"))
}

// keyDisplay trả về key đầy đủ hoặc đã che tùy theo lựa chọn.
func keyDisplay(key string, full bool) string {
	if full {
		return key
	}
	return license.MaskKey(key)
}

// identifyEdition nhận diện ấn bản Windows từ một key: ưu tiên bảng khóa chung,
// sau đó đối chiếu với mọi mục SoftwareLicensingProduct qua WMI (chỉ đọc).
func identifyEdition(p sysinfo.Provider, fullKey string) string {
	if ed, ok := license.EditionFromGenericKey(fullKey); ok {
		return ed
	}
	products, err := p.AllLicensingProducts()
	if err != nil {
		return ""
	}
	for _, prod := range products {
		if prod.PartialKey == "" {
			continue
		}
		if strings.HasSuffix(strings.ToUpper(fullKey), strings.ToUpper(prod.PartialKey)) &&
			strings.HasPrefix(strings.ToLower(prod.Name), "windows") {
			return prod.Name
		}
	}
	return ""
}

// ── Tùy chọn 1 — Phiên bản OS & Key OEM BIOS ──────────────────────────────────

func Option1(p sysinfo.Provider, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act1"))

	e.Fetch(i18n.T("Fetch_OS"))
	if os, err := p.OSInfo(); err == nil {
		e.Data(i18n.T("D_OsEdition"), dash(os.Caption))
		e.Data(i18n.T("D_Version"), dash(os.Version))
		e.Data(i18n.T("D_Build"), dash(os.Build))
		e.Data(i18n.T("D_Arch"), dash(os.Arch))
	}

	e.Blank()
	e.Fetch(i18n.T("Fetch_BiosKey"))
	oemKey, _ := p.OEMProductKey()
	if strings.TrimSpace(oemKey) != "" {
		full := askShowFullKey(ui, i18n.T("O1_BiosDetectedCtx"))
		e.Key(i18n.T("O1_BiosKey") + keyDisplay(oemKey, full))

		e.Blank()
		e.Fetch(i18n.T("Fetch_OemEdition"))
		if ed := identifyEdition(p, oemKey); ed != "" {
			e.Ok(i18n.T("OemEd_Found") + "  " + ed)
		} else {
			e.Info(i18n.T("OemEd_NoMatch"))
			e.Diag(i18n.T("OemEd_Hint"))
		}
	} else {
		e.Info(i18n.T("O1_BiosNone"))
	}
}

// ── Tùy chọn 2 — Kênh & Loại Bản Quyền (slmgr /dli) ───────────────────────────

// Option2 hiển thị kênh & loại bản quyền. Dữ liệu lấy thẳng từ Software Licensing
// API qua WMI (không gọi slmgr.vbs) — chính là nguồn mà slmgr /dli đọc.
func Option2(p sysinfo.Provider, e *logx.Emitter) {
	e.Action(i18n.T("Act2"))
	e.Info(i18n.T("O2_Note"))
	e.Blank()
	e.Fetch(i18n.T("O2_Running"))

	lic, err := p.ActiveWindowsLicense()
	if err != nil {
		e.Error("WMI: " + err.Error())
		return
	}
	if lic == nil {
		e.Warn(i18n.T("O2_NoOutput"))
		return
	}
	e.Data(i18n.T("D_Edition"), dash(lic.Name))
	e.Data(i18n.T("D_Channel"), dash(lic.Description))
	e.Data(i18n.T("D_PartialKey"), dash(lic.PartialKey))
	if lic.LicenseStatus == 1 {
		e.Ok(i18n.T("O2_LicenseStatus") + license.StatusText(lic.LicenseStatus))
	} else {
		e.Warn(i18n.T("O2_LicenseStatus") + license.StatusText(lic.LicenseStatus))
	}
	if lic.KmsDiscoveredName != "" {
		e.Data(i18n.T("KMS_Server"), lic.KmsDiscoveredName)
	}
}

// ── Tùy chọn 3 — Xem Key & Trạng thái Kích Hoạt ───────────────────────────────

func Option3(p sysinfo.Provider, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act3"))

	e.Fetch(i18n.T("Fetch_RegKey"))
	regKey, regErr := p.BackupProductKey()
	if regErr != nil {
		e.Error(i18n.T("O3_RegReadErr") + regErr.Error())
	}

	e.Fetch(i18n.T("Fetch_License"))
	var (
		partialKey  string
		isLicensed  bool
		kmsServer   string
		method      = license.MethodUnknown
		foundActive bool
	)
	lic, licErr := p.ActiveWindowsLicense()
	if licErr != nil {
		e.Error("WMI: " + licErr.Error())
	}
	if lic != nil {
		foundActive = true
		partialKey = lic.PartialKey
		isLicensed = lic.LicenseStatus == 1
		kmsServer = lic.KmsDiscoveredName
		method = license.DetectActivationMethod(lic.Description, partialKey, regKey, lic.KmsDiscoveredName, lic.KmsCurrentCount)

		e.Data(i18n.T("D_Edition"), lic.Name)
		e.Data(i18n.T("D_Channel"), dash(lic.Description))
		e.Data(i18n.T("D_PartialKey"), dash(partialKey))
		if isLicensed {
			e.Ok(i18n.T("O3_Activation") + license.StatusText(lic.LicenseStatus))
		} else {
			e.Warn(i18n.T("O3_Activation") + license.StatusText(lic.LicenseStatus))
		}
	}
	if !foundActive {
		e.Warn(i18n.T("O3_NoLicense"))
	}

	// Khối phương thức kích hoạt
	e.Blank()
	switch method {
	case license.MethodDE:
		if isLicensed {
			e.DE(i18n.T("DE_Confirmed"))
			e.Diag(i18n.T("DE_Explain1"))
			e.Diag(i18n.T("DE_Explain2"))
			e.Diag(i18n.T("DE_Explain3"))
			e.Diag(i18n.T("DE_KeyMismatch"))
			e.Diag(i18n.T("DE_Verify"))
		} else {
			e.Warn(i18n.T("DE_NotActivated"))
			e.Diag(i18n.T("DE_Verify"))
		}
	case license.MethodKMS:
		e.Ok(i18n.T("KMS_Detected"))
		if kmsServer != "" {
			e.Data(i18n.T("KMS_Server"), kmsServer)
		}
	case license.MethodStandard:
		if isLicensed {
			e.Ok(i18n.T("MAK_Detected"))
		} else {
			e.Warn(i18n.T("MAK_Detected"))
		}
	}

	// Key OEM BIOS
	e.Blank()
	e.Fetch(i18n.T("Fetch_BiosKey"))
	oemKey, _ := p.OEMProductKey()
	hasOem := strings.TrimSpace(oemKey) != ""
	if hasOem {
		e.Data(i18n.T("D_BiosOemKey"), i18n.T("O3_BiosDetected"))
	} else {
		e.Data(i18n.T("D_BiosOemKey"), i18n.T("O3_BiosNone"))
	}
	if hasOem {
		e.Fetch(i18n.T("Fetch_OemEdition"))
		if ed := identifyEdition(p, oemKey); ed != "" {
			e.Ok(i18n.T("OemEd_Found") + "  " + ed)
		} else {
			e.Info(i18n.T("OemEd_NoMatch"))
		}
	}

	// Key dự phòng Registry
	hasReg := strings.TrimSpace(regKey) != ""
	if hasReg {
		e.Data(i18n.T("D_RegBackupKey"), i18n.T("O3_BiosDetected"))
	} else {
		e.Data(i18n.T("D_RegBackupKey"), i18n.T("O3_RegNone"))
	}

	// Hiển thị key
	if hasOem || hasReg {
		e.Blank()
		full := askShowFullKey(ui, i18n.T("O3_KeysFoundCtx"))
		if hasOem {
			e.Key(i18n.T("O3_KeyBios") + keyDisplay(oemKey, full))
		}
		if hasReg {
			e.Key(i18n.T("O3_KeyReg") + keyDisplay(regKey, full))
		}
	}

	// Báo cáo lệch key
	if hasReg && partialKey != "" {
		e.Blank()
		match := strings.EqualFold(suffix5(regKey), partialKey)
		switch {
		case !match && method == license.MethodDE:
			e.Info(i18n.T("DE_KeyMismatch"))
		case !match:
			e.Warn(i18n.T("O3_Mismatch"))
			e.Diag(i18n.T("O3_MismatchReason"))
			e.Diag(i18n.T("O3_ActivePartial") + partialKey)
			e.Diag(i18n.T("O3_BackupEnds") + suffix5(regKey))
			e.Blank()
			if p.IsAdmin() {
				if ui.Confirm(i18n.T("O3_ConfirmRemove"), i18n.T("O3_RemoveTitle")) {
					if err := p.DeleteBackupProductKey(); err != nil {
						e.Error(i18n.T("O3_RemoveErr") + err.Error())
					} else {
						e.Ok(i18n.T("O3_RegKeyRemoved"))
					}
				}
			} else {
				e.Warn(i18n.T("O3_NeedAdmin"))
			}
		default:
			e.Ok(i18n.T("O3_KeyMatch"))
		}
	}

	// Báo cáo mở rộng (tùy chọn): các trường bổ sung từ Software Licensing API.
	if ui.Confirm(i18n.T("O3_DlvQ"), i18n.T("O3_DlvTitle")) {
		e.Blank()
		if prod, perr := p.WindowsLicensingProduct(); perr == nil && prod != nil {
			e.Data(i18n.T("D_PartialKey"), dash(prod.PartialKey))
			e.Data(i18n.T("D_Channel"), dash(prod.Description))
			e.Data(i18n.T("O3_Activation"), license.StatusText(prod.LicenseStatus))
			if prod.GracePeriodMins > 0 {
				e.Data(i18n.T("P7_ExpiryDate"),
					time.Now().Add(time.Duration(prod.GracePeriodMins)*time.Minute).Format("02/01/2006 15:04"))
			} else {
				e.Info(i18n.T("P7_ExpiryPermanent"))
			}
		} else {
			e.Warn(i18n.T("O3_NoLicense"))
		}
	}
}

// ── Tùy chọn 4 — Kiểm thử & Cài Key Bản Quyền ─────────────────────────────────

func Option4(p sysinfo.Provider, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act4"))
	e.Info(i18n.T("O4_Info1"))
	e.Info(i18n.T("O4_Info2"))
	e.Blank()

	raw, ok := ui.PromptKey(i18n.T("O4_Prompt"), i18n.T("O4_PromptTitle"))
	if !ok || strings.TrimSpace(raw) == "" {
		e.Info(i18n.T("O4_Cancelled"))
		return
	}
	key := license.NormalizeKey(raw)
	if !license.ValidKeyFormat(key) {
		e.Error(i18n.T("O4_BadFormat"))
		return
	}

	full := askShowFullKey(ui, i18n.T("O4_ShowKeyCtx"))
	e.Info(i18n.T("O4_Installing") + keyDisplay(key, full))
	e.Cmd("SoftwareLicensingService.InstallProductKey(" + keyDisplay(key, full) + ")")
	e.Blank()

	err := p.InstallProductKey(key)
	if err == nil {
		e.Ok(i18n.T("O4_Success1"))
		e.Info(i18n.T("O4_Success2"))
		return
	}

	msg := err.Error()
	e.Error(i18n.T("O4_Fail"))
	e.Diag(msg)
	switch {
	case strings.Contains(msg, "C004F069"):
		e.Diag(i18n.T("O4_DiagSku"))
	case strings.Contains(msg, "C004F050"):
		e.Diag(i18n.T("O4_DiagInvalid"))
	case strings.Contains(msg, "C004C003"):
		e.Diag(i18n.T("O4_DiagBlocked"))
	default:
		e.Diag(i18n.T("O4_DiagGeneral"))
	}
	e.Blank()
	e.Help("https://support.microsoft.com/help/10738")
	e.Help("https://learn.microsoft.com/vi-vn/windows-server/get-started/activation-error-codes")
}

// ── Tùy chọn 5 — Gỡ Key Bản Quyền ─────────────────────────────────────────────

func Option5(p sysinfo.Provider, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act5"))
	if !ui.Confirm(i18n.T("O5_Confirm"), i18n.T("Confirm_Title")) {
		e.Info(i18n.T("O5_Cancelled"))
		return
	}
	e.Blank()
	e.Info(i18n.T("O5_Uninstalling"))
	e.Cmd("SoftwareLicensingProduct.UninstallProductKey()")
	if err := p.UninstallProductKey(); err != nil {
		e.Error(err.Error())
		return
	}

	e.Blank()
	e.Info(i18n.T("O5_Clearing"))
	e.Cmd("SoftwareLicensingService.ClearProductKeyFromRegistry()")
	if err := p.ClearProductKeyFromRegistry(); err != nil {
		e.Error(err.Error())
		return
	}

	e.Blank()
	e.Ok(i18n.T("O5_Done"))
}

// ── Tùy chọn 6 — Đặt Lại Kích Hoạt (Rearm) ────────────────────────────────────

func Option6(p sysinfo.Provider, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act6"))
	if !ui.Confirm(i18n.T("O6_Confirm"), i18n.T("Confirm_Title")) {
		e.Info(i18n.T("O6_Cancelled"))
		return
	}
	e.Blank()
	e.Info(i18n.T("O6_Rearming"))
	e.Cmd("SoftwareLicensingService.ReArmWindows()")
	if err := p.ReArmWindows(); err != nil {
		e.Error(err.Error())
		return
	}

	e.Blank()
	e.Ok(i18n.T("O6_Done"))

	if ui.Confirm(i18n.T("O6_RestartQ"), i18n.T("O6_RestartTitle")) {
		e.Info(i18n.T("O6_Restarting"))
		_ = p.Restart()
	}
}

// ── Tùy chọn 8 — Dọn Sạch Crack ───────────────────────────────────────────────

// legitAbusedBinaries là các nhị phân HỢP LỆ của Windows nhưng bị công cụ crack
// lợi dụng (gatherosstate/clipup dùng cho HWID). Chỉ dùng để PHÁT HIỆN, TUYỆT ĐỐI
// không xóa/kết thúc khi dọn crack vì đó là thành phần thật của hệ điều hành.
var legitAbusedBinaries = map[string]bool{
	"gatherosstate": true,
	"clipup":        true,
	"cliprenew":     true,
}

// CleanCrack gỡ bỏ toàn bộ dấu vết crack và đưa Windows về trạng thái CHƯA kích
// hoạt: kết thúc tiến trình, dừng & xóa dịch vụ, xóa tác vụ định kỳ, gỡ hook IFEO,
// xóa cấu hình KMS trong Registry, xóa tệp/thư mục công cụ, và gỡ key crack.
//
// Best-effort: lỗi ở một mục không dừng cả quá trình; mọi việc đều ghi nhật ký.
func CleanCrack(p sysinfo.Provider, cfg *config.Settings, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act8"))
	e.Warn(i18n.T("O8_Warn1"))
	e.Warn(i18n.T("O8_Warn2"))
	e.Blank()
	if !ui.Confirm(i18n.T("O8_Confirm"), i18n.T("Confirm_Title")) {
		e.Info(i18n.T("O8_Cancelled"))
		return
	}
	removed := 0

	// 1. Kết thúc tiến trình crack (bỏ qua nhị phân Windows hợp lệ bị lợi dụng).
	e.Blank()
	e.Fetch(i18n.T("O8_StepProc"))
	if procs, err := p.ListProcesses(); err == nil {
		for _, pr := range procs {
			if legitAbusedBinaries[strings.ToLower(pr.Name)] {
				continue
			}
			if matchesAny(pr.Name, cfg.AllProcesses()) {
				if err := p.KillProcess(pr.PID); err == nil {
					e.Ok(i18n.Tf("O8_ProcKilled", pr.Name, pr.PID))
					removed++
				} else {
					e.Warn(i18n.Tf("O8_ProcFail", pr.Name, err.Error()))
				}
			}
		}
	}

	// 2. Dừng và xóa dịch vụ crack.
	e.Fetch(i18n.T("O8_StepSvc"))
	if svcs, err := p.ListServices(); err == nil {
		for _, s := range svcs {
			if matchesAny(s.Name, cfg.AllServices()) {
				if err := p.StopDeleteService(s.Name); err == nil {
					e.Ok(i18n.Tf("O8_SvcDeleted", s.Name))
					removed++
				} else {
					e.Warn(i18n.Tf("O8_SvcFail", s.Name, err.Error()))
				}
			}
		}
	}

	// 3. Xóa tác vụ định kỳ crack.
	e.Fetch(i18n.T("O8_StepTask"))
	if tasks, err := p.ListScheduledTaskNames(); err == nil {
		for _, t := range tasks {
			if matchesAny(t, cfg.AllTaskKeywords()) {
				if err := p.DeleteScheduledTask(t); err == nil {
					e.Ok(i18n.Tf("O8_TaskDeleted", t))
					removed++
				} else {
					e.Warn(i18n.Tf("O8_TaskFail", t, err.Error()))
				}
			}
		}
	}

	// 4. Gỡ hook IFEO trên nhị phân dịch vụ bản quyền.
	e.Fetch(i18n.T("O8_StepHook"))
	if n, err := p.RemoveSppImageHijack(); err != nil {
		e.Warn(i18n.Tf("O8_HookFail", err.Error()))
	} else if n > 0 {
		e.Ok(i18n.Tf("O8_HookRemoved", n))
		removed += n
	} else {
		e.Info(i18n.T("O8_HookNone"))
	}

	// 5. Xóa cấu hình máy chủ KMS trong Registry.
	e.Fetch(i18n.T("O8_StepKms"))
	if n, _ := p.ClearKmsHost(); n > 0 {
		e.Ok(i18n.Tf("O8_KmsCleared", n))
		removed += n
	} else {
		e.Info(i18n.T("O8_KmsNone"))
	}

	// 6. Xóa tệp/thư mục công cụ crack (danh sách toàn crack, không gồm nhị phân Windows).
	e.Fetch(i18n.T("O8_StepFiles"))
	for _, entry := range audit.SuspiciousPaths(cfg.ExtraFilePaths) {
		if !p.PathExists(entry.Path) {
			continue
		}
		if err := p.DeletePath(entry.Path); err == nil {
			e.Ok(i18n.Tf("O8_FileDeleted", entry.Tool, entry.Path))
			removed++
		} else {
			e.Warn(i18n.Tf("O8_FileFail", entry.Path, err.Error()))
		}
	}

	// 7. Gỡ key crack: gỡ key, xóa khỏi Registry, xóa key dự phòng.
	e.Fetch(i18n.T("O8_StepKey"))
	if err := p.UninstallProductKey(); err != nil {
		e.Warn(i18n.Tf("O8_KeyFail", err.Error()))
	} else {
		e.Ok(i18n.T("O8_KeyUninstalled"))
		removed++
	}
	_ = p.ClearProductKeyFromRegistry()
	_ = p.DeleteBackupProductKey()

	// Tổng kết.
	e.Blank()
	e.Sep()
	if removed > 0 {
		e.Ok(i18n.Tf("O8_Done", removed))
		e.Info(i18n.T("O8_DoneNote"))
	} else {
		e.Info(i18n.T("O8_Nothing"))
	}
	e.Info(i18n.T("O8_BuyHint"))
}

// matchesAny trả về true nếu name (không phân biệt hoa thường) chứa một từ khóa.
func matchesAny(name string, keywords []string) bool {
	l := strings.ToLower(name)
	for _, k := range keywords {
		if k != "" && strings.Contains(l, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// ── Hàm nội bộ ─────────────────────────────────────────────────────────────────

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func suffix5(key string) string {
	parts := strings.Split(key, "-")
	last := parts[len(parts)-1]
	if len(last) >= 5 {
		return last[len(last)-5:]
	}
	if len(key) >= 5 {
		return key[len(key)-5:]
	}
	return last
}

// ── Tùy chọn 9 — Gỡ Sạch Key Office Lậu ─────────────────────────────────────

var (
	reLast5OfficeKey = regexp.MustCompile(`(?i)Last 5 characters of installed product key:\s*([A-Z0-9]{5})`)
	reLineEnd5       = regexp.MustCompile(`(?m)[: ]\s*([A-Z0-9]{5})\s*$`)
)

// ExtractOfficeKeys trích xuất 5 ký tự cuối của các product key Office từ đầu ra
// của lệnh ospp.vbs /dstatus, loại bỏ các kết quả trùng lặp.
func ExtractOfficeKeys(output string) []string {
	seen := make(map[string]bool)
	var keys []string

	addKey := func(k string) {
		k = strings.ToUpper(strings.TrimSpace(k))
		if len(k) == 5 && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}

	matches := reLast5OfficeKey.FindAllStringSubmatch(output, -1)
	for _, m := range matches {
		if len(m) > 1 {
			addKey(m[1])
		}
	}

	// Nếu mẫu chuẩn không khớp, thử regex từ script
	if len(keys) == 0 {
		subMatches := reLineEnd5.FindAllStringSubmatch(output, -1)
		for _, m := range subMatches {
			if len(m) > 1 {
				addKey(m[1])
			}
		}
	}

	return keys
}

// CleanOfficeKeys gỡ sạch toàn bộ key Office lậu và xóa máy chủ KMS lậu
// theo quy trình của Microsoft OSPP (ospp.vbs) từ Office 2010 đến 2024/365.
func CleanOfficeKeys(p sysinfo.Provider, ui Interaction, e *logx.Emitter) {
	e.Action(i18n.T("Act9"))
	e.Warn(i18n.T("O9_Warn1"))
	e.Warn(i18n.T("O9_Warn2"))
	e.Blank()

	if !ui.Confirm(i18n.T("O9_Confirm"), i18n.T("Confirm_Title")) {
		e.Info(i18n.T("O9_Cancelled"))
		return
	}

	e.Fetch(i18n.T("O9_ScanningOffice"))
	officeDirs := p.FindOfficeDirs()
	if len(officeDirs) == 0 {
		e.Blank()
		e.Error(i18n.T("O9_NoOfficeFound"))
		e.Blank()
		e.Info(i18n.T("O9_BuyHint"))
		return
	}

	totalDirs := len(officeDirs)
	totalRemoved := 0
	totalFailed := 0

	for _, dir := range officeDirs {
		e.Blank()
		e.Ok(i18n.Tf("O9_OfficeFound", dir))

		// 1. Xóa máy chủ KMS trước (/remhst)
		e.Fetch(i18n.T("O9_RemovingKms"))
		e.Cmd("ospp.vbs /remhst")
		if remOut, err := p.RunOspp(dir, "/remhst"); err != nil {
			e.Warn(i18n.T("O9_RemovingKms") + ": " + strings.TrimSpace(remOut))
		} else {
			e.Ok(i18n.T("O9_KmsRemoved"))
		}

		// 2. Quét key hiện có (/dstatus)
		e.Fetch(i18n.T("O9_ScanningKeys"))
		e.Cmd("ospp.vbs /dstatus")
		dstatusOut, _ := p.RunOspp(dir, "/dstatus")
		keys := ExtractOfficeKeys(dstatusOut)

		if len(keys) == 0 {
			e.Info(i18n.T("O9_NoKeysFound"))
			continue
		}

		e.Ok(i18n.Tf("O9_KeysFound", len(keys)))

		// 3. Xóa từng key (/unpkey:XXXXX)
		for _, key := range keys {
			e.Fetch(i18n.Tf("O9_DeletingKey", key))
			e.Cmd("ospp.vbs /unpkey:" + key)
			unpOut, err := p.RunOspp(dir, "/unpkey:"+key)
			if err == nil || strings.Contains(strings.ToLower(unpOut), "uninstall successful") {
				e.Ok(i18n.Tf("O9_KeyDeleted", key))
				totalRemoved++
			} else {
				e.Error(i18n.Tf("O9_KeyDeleteFail", key))
				totalFailed++
			}
		}

		// 4. Kiểm tra lại sau khi gỡ (/dstatus)
		e.Fetch(i18n.T("O9_Rechecking"))
		e.Cmd("ospp.vbs /dstatus")
		checkOut, _ := p.RunOspp(dir, "/dstatus")
		remainingKeys := ExtractOfficeKeys(checkOut)
		if len(remainingKeys) == 0 {
			e.Ok(i18n.T("O9_AllClean"))
		} else {
			e.Warn(i18n.Tf("O9_StillRemaining", len(remainingKeys)))
		}
	}

	// 5. Dọn dẹp máy chủ KMS Office trong Registry (officeSppKey)
	e.Blank()
	e.Fetch(i18n.T("O9_ClearRegistry"))
	if n, _ := p.ClearKmsHost(); n > 0 {
		e.Ok(i18n.Tf("O9_RegistryCleaned", n))
	}

	// 6. Tổng kết
	e.Blank()
	e.Sep()
	e.Ok(i18n.Tf("O9_DoneSummary", totalDirs, totalRemoved))
	if totalFailed > 0 {
		e.Warn(i18n.Tf("O9_StillRemaining", totalFailed))
	}
	e.Info(i18n.T("O9_BuyHint"))
}
