package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vinhwincheck/wincheck/internal/config"
	"github.com/vinhwincheck/wincheck/internal/i18n"
	"github.com/vinhwincheck/wincheck/internal/license"
	"github.com/vinhwincheck/wincheck/internal/logx"
	"github.com/vinhwincheck/wincheck/internal/sysinfo"
)

// Mức độ của một dấu hiệu phát hiện được.
const (
	SeverityCritical = "critical" // dấu hiệu nghiêm trọng — gần như chắc chắn lậu
	SeverityWarn     = "warn"     // dấu hiệu đáng ngờ — cần xem xét
)

// Indicator là một dấu hiệu cụ thể mà lần quét phát hiện được. Danh sách này cho
// phép giao diện trình bày bằng chứng gọn gàng thay vì bắt người dùng đọc nhật ký.
type Indicator struct {
	Severity string // SeverityCritical hoặc SeverityWarn
	Text     string // mô tả tiếng Việt
}

// Trạng thái của một mục kiểm tra trong bảng tình trạng.
const (
	CheckOK       = "ok"       // đã kiểm — KHÔNG thấy dấu hiệu crack
	CheckDetected = "detected" // PHÁT HIỆN dấu hiệu crack (nghiêm trọng)
	CheckWarn     = "warn"     // phát hiện điểm đáng ngờ
	CheckSkipped  = "skipped"  // không kiểm được (thiếu dữ liệu/quyền)
	CheckInfo     = "info"     // thông tin, không phải dấu hiệu
)

// Check là một mục trong bảng tình trạng kiểm tra: cho biết mục đó đã kiểm gì và
// có phát hiện dấu hiệu crack hay không.
type Check struct {
	Name   string // tên mục kiểm tra (vd "Máy chủ KMS")
	Status string // CheckOK / CheckDetected / CheckWarn / CheckSkipped / CheckInfo
	Detail string // mô tả ngắn kết quả
}

// Result là kết quả tổng hợp của một lần quét.
type Result struct {
	SuspiciousCount int
	CriticalKms     bool
	Indicators      []Indicator
	Checks          []Check
}

// addCheck ghi một mục vào bảng tình trạng kiểm tra.
func (r *Result) addCheck(name, status, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// flagCritical ghi nhận một dấu hiệu nghiêm trọng (đồng thời đặt CriticalKms).
func (r *Result) flagCritical(text string) {
	r.CriticalKms = true
	r.SuspiciousCount++
	r.Indicators = append(r.Indicators, Indicator{Severity: SeverityCritical, Text: text})
}

// flagWarn ghi nhận một dấu hiệu đáng ngờ (không đặt CriticalKms).
func (r *Result) flagWarn(text string) {
	r.SuspiciousCount++
	r.Indicators = append(r.Indicators, Indicator{Severity: SeverityWarn, Text: text})
}

// SppEventCodes là các mã sự kiện SPP quan tâm trong nhật ký Hệ thống.
var SppEventCodes = map[uint32]bool{12288: true, 12289: true, 12290: true, 8198: true}

var reEventAddr = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)`)

// PathEntry là một đường dẫn cần kiểm tra kèm tên công cụ tương ứng.
type PathEntry struct {
	Path string
	Tool string
}

// Run thực hiện toàn bộ Tùy chọn 7 (10 lớp), phát nhật ký qua e và trả về tổng
// hợp kết quả. now là thời điểm hiện tại (tách ra để kiểm thử tất định).
func Run(p sysinfo.Provider, cfg *config.Settings, now time.Time, e *logx.Emitter) Result {
	e.Action(i18n.T("Act7"))

	// ── Phần mở đầu: phạm vi quét ──────────────────────────────────────────
	e.Text(logx.KindAction, i18n.T("P7_Header"))
	e.Diag(i18n.T("P7_CanDetect1"))
	e.Diag(i18n.T("P7_CanDetect2"))
	e.Diag(i18n.T("P7_CanDetect3"))
	e.Diag(i18n.T("P7_CanDetect4"))
	e.Diag(i18n.T("P7_CanDetect5"))
	e.Diag(i18n.T("P7_CanDetect6"))
	e.Blank()
	e.Text(logx.KindWarn, i18n.T("P7_LimitHeader"))
	e.Diag(i18n.T("P7_Limit1"))
	e.Diag(i18n.T("P7_Limit2"))
	e.Diag(i18n.T("P7_Limit3"))
	e.Diag(i18n.T("P7_Limit4"))
	e.Blank()

	e.Diag(i18n.Tf("P7_KmsDomainCount", len(cfg.AllKmsPiracyDomains())))
	e.Sep()
	e.Blank()

	r := Result{}
	piracyDomains := cfg.AllKmsPiracyDomains()

	// Windows Server có thể chạy dịch vụ KMS host hợp lệ (cổng 1688 mở là bình
	// thường). Trên máy khách (Home/Pro/Edu) thì cổng 1688 mở là dấu hiệu giả lập.
	osCaption := ""
	if os, err := p.OSInfo(); err == nil {
		osCaption = os.Caption
	}
	isServerSKU := strings.Contains(strings.ToLower(osCaption), "server")

	// ── 1. Tên máy chủ KMS ──────────────────────────────────────────────────
	e.Fetch(i18n.T("Fetch_KmsHost"))
	e.Diag(i18n.T("P7_KmsExplain"))
	kmsHost, _ := p.KmsHostName()
	if kmsHost == "" {
		e.Ok(i18n.T("P7_KmsNone"))
		r.addCheck(i18n.T("V_ChkKms"), CheckOK, i18n.T("V_ChkKmsNone"))
	} else {
		e.Data(i18n.T("P7_KmsName"), kmsHost)
		switch ClassifyKmsHost(kmsHost, piracyDomains) {
		case KmsLocal:
			e.Error(i18n.T("P7_KmsLocal"))
			e.Error(i18n.T("P7_KmsLocal2"))
			r.flagCritical(i18n.Tf("V_IndKmsLocal", kmsHost))
			r.addCheck(i18n.T("V_ChkKms"), CheckDetected, i18n.Tf("V_ChkKmsLocal", kmsHost))
		case KmsBogusPlaceholder:
			e.Error(i18n.T("P7_KmsBogusIp"))
			r.flagCritical(i18n.T("V_IndKmsBogus"))
			r.addCheck(i18n.T("V_ChkKms"), CheckDetected, i18n.T("V_ChkKmsBogus"))
		case KmsKnownPiracy:
			e.Error(i18n.T("P7_KmsKnownPiracy"))
			e.Error("  " + kmsHost)
			r.flagCritical(i18n.Tf("V_IndKmsPiracyDomain", kmsHost))
			r.addCheck(i18n.T("V_ChkKms"), CheckDetected, i18n.Tf("V_ChkKmsPiracy", kmsHost))
			checkKmsHostDNS(p, kmsHost, e)
		case KmsMsOfficial:
			e.Ok(i18n.T("P7_KmsMsOfficial"))
			e.Info(i18n.T("P7_KmsMsOfficialNote"))
			r.addCheck(i18n.T("V_ChkKms"), CheckInfo, i18n.Tf("V_ChkKmsAzure", kmsHost))
			checkKmsHostDNS(p, kmsHost, e)
		case KmsCorporate:
			e.Info(i18n.T("P7_KmsCorporate"))
			r.addCheck(i18n.T("V_ChkKms"), CheckInfo, i18n.Tf("V_ChkKmsCorp", kmsHost))
		case KmsCloudPiracy:
			e.Error(i18n.T("P7_KmsCloudPiracy"))
			e.Error("  " + kmsHost)
			r.flagCritical(i18n.Tf("V_IndKmsCloud", kmsHost))
			r.addCheck(i18n.T("V_ChkKms"), CheckDetected, i18n.Tf("V_ChkKmsCloud", kmsHost))
			checkKmsHostDNS(p, kmsHost, e)
		}
	}

	// ── 2. Kiểm tra cổng trên localhost ─────────────────────────────────────
	e.Fetch(i18n.T("Fetch_Port1688"))
	e.Diag(i18n.T("P7_Port1688Explain"))
	openPorts := 0
	for _, port := range cfg.AllPorts() {
		if p.ProbeLocalPort(port) {
			if isServerSKU {
				// Trên Server, cổng 1688 mở có thể là KMS host chính hãng: chỉ ghi
				// thông tin, không kết luận lậu.
				e.Info(i18n.Tf("P7_PortOpenServer", port))
				r.addCheck(i18n.T("V_ChkPort"), CheckInfo, i18n.Tf("V_ChkPortServer", port))
			} else {
				e.Error(i18n.Tf("P7_PortOpen", port))
				r.flagCritical(i18n.Tf("V_IndPortOpen", port))
				r.addCheck(i18n.T("V_ChkPort"), CheckDetected, i18n.Tf("V_ChkPortOpen", port))
			}
			openPorts++
		} else {
			e.Ok(i18n.Tf("P7_PortClosed", port))
		}
	}
	if openPorts == 0 {
		r.addCheck(i18n.T("V_ChkPort"), CheckOK, i18n.Tf("V_ChkPortClosed", len(cfg.AllPorts())))
	}

	// ── 3. Dịch vụ hệ thống ─────────────────────────────────────────────────
	e.Fetch(i18n.T("Fetch_Services"))
	e.Diag(i18n.T("P7_ServiceExplain"))
	svcKeywords := cfg.AllServices()
	found := 0
	if services, err := p.ListServices(); err == nil {
		for _, s := range services {
			if matchesAny(s.Name, svcKeywords) || matchesAny(s.DisplayName, svcKeywords) {
				e.Warn(i18n.T("P7_ServiceFound") + "  " + s.Name + "  (" + s.DisplayName + ")")
				r.flagWarn(i18n.Tf("V_IndService", s.Name))
				found++
			}
		}
	}
	if found == 0 {
		e.Ok(i18n.T("P7_NoServices"))
		r.addCheck(i18n.T("V_ChkService"), CheckOK, i18n.Tf("V_ChkServiceNone", len(svcKeywords)))
	} else {
		r.addCheck(i18n.T("V_ChkService"), CheckWarn, i18n.Tf("V_ChkServiceFound", found))
	}

	// ── 4. Tác vụ định kỳ ───────────────────────────────────────────────────
	e.Fetch(i18n.T("Fetch_Tasks"))
	e.Diag(i18n.T("P7_TaskExplain"))
	taskKeywords := cfg.AllTaskKeywords()
	found = 0
	if tasks, err := p.ListScheduledTaskNames(); err == nil {
		for _, t := range tasks {
			if matchesAny(t, taskKeywords) {
				e.Warn(i18n.T("P7_TaskFound") + "  " + t)
				r.flagWarn(i18n.Tf("V_IndTask", t))
				found++
			}
		}
	}
	if found == 0 {
		e.Ok(i18n.T("P7_NoTasks"))
		r.addCheck(i18n.T("V_ChkTask"), CheckOK, i18n.Tf("V_ChkTaskNone", len(taskKeywords)))
	} else {
		r.addCheck(i18n.T("V_ChkTask"), CheckWarn, i18n.Tf("V_ChkTaskFound", found))
	}

	// ── 5. Đường dẫn tập tin/thư mục ────────────────────────────────────────
	e.Fetch(i18n.T("Fetch_Files"))
	e.Diag(i18n.T("P7_FileExplain"))
	found = 0
	for _, entry := range SuspiciousPaths(cfg.ExtraFilePaths) {
		if p.PathExists(entry.Path) {
			e.Warn(i18n.T("P7_FileFound") + "  " + entry.Tool + "  →  " + entry.Path)
			r.flagWarn(i18n.Tf("V_IndFile", entry.Tool, entry.Path))
			found++
		}
	}
	if found == 0 {
		e.Ok(i18n.T("P7_NoFiles"))
		r.addCheck(i18n.T("V_ChkFile"), CheckOK, i18n.Tf("V_ChkFileNone", len(SuspiciousPaths(cfg.ExtraFilePaths))))
	} else {
		r.addCheck(i18n.T("V_ChkFile"), CheckWarn, i18n.Tf("V_ChkFileFound", found))
	}

	// ── 6. Tiến trình đang chạy ─────────────────────────────────────────────
	e.Fetch(i18n.T("Fetch_Procs"))
	e.Diag(i18n.T("P7_ProcExplain"))
	procKeywords := cfg.AllProcesses()
	found = 0
	if procs, err := p.ListProcesses(); err == nil {
		for _, pr := range procs {
			if matchesAny(pr.Name, procKeywords) {
				e.Warn(fmt.Sprintf("%s  %s  (PID %d)", i18n.T("P7_ProcFound"), pr.Name, pr.PID))
				r.flagWarn(i18n.Tf("V_IndProcess", pr.Name, pr.PID))
				found++
			}
		}
	}
	if found == 0 {
		e.Ok(i18n.T("P7_NoProcs"))
		r.addCheck(i18n.T("V_ChkProc"), CheckOK, i18n.Tf("V_ChkProcNone", len(procKeywords)))
	} else {
		r.addCheck(i18n.T("V_ChkProc"), CheckWarn, i18n.Tf("V_ChkProcFound", found))
	}

	// ── 6b. Hook IFEO trên nhị phân SPP ─────────────────────────────────────
	// Dấu hiệu rất mạnh: KMSpico/KMS_VL_ALL gắn VerifierDlls/Debugger vào
	// SppExtComObj.exe/sppsvc.exe để trả lời kích hoạt KMS ngay trong tiến trình
	// hợp lệ của Microsoft (nên không lộ tên tiến trình/dịch vụ riêng).
	e.Diag(i18n.T("P7_SppHookExplain"))
	if ev, ok := p.SppImageHijack(); ok {
		e.Error(i18n.Tf("P7_SppHookFound", ev))
		r.flagCritical(i18n.Tf("V_IndSppHook", ev))
		r.addCheck(i18n.T("V_ChkSppHook"), CheckDetected, i18n.Tf("V_ChkSppHookFound", ev))
	} else {
		e.Ok(i18n.T("P7_SppHookNone"))
		r.addCheck(i18n.T("V_ChkSppHook"), CheckOK, i18n.T("V_ChkSppHookNone"))
	}

	// ── 7 & 8. GVLK + kênh kích hoạt, và phân tích hết hạn ──────────────────
	e.Blank()
	e.Sep()
	e.Fetch(i18n.T("Fetch_ActChannel"))
	e.Diag(i18n.T("P7_GvlkExplain"))
	e.Diag(i18n.Tf("P7_GvlkCount", len(cfg.AllGvlkSuffixes())))

	prod, _ := p.WindowsLicensingProduct()
	if prod != nil && prod.PartialKey != "" {
		ppk := prod.PartialKey
		isLicensed := prod.LicenseStatus == 1
		isPermanent := prod.GracePeriodMins == 0 && isLicensed
		isGvlk := containsFold(cfg.AllGvlkSuffixes(), ppk)
		isPhone := strings.Contains(strings.ToLower(prod.Description), "phone")

		// 7a. Kênh điện thoại bất thường (dấu hiệu TSforge ZeroCID)
		if isPhone && isLicensed {
			e.Error(i18n.T("P7_PhoneChannel"))
			r.flagCritical(i18n.T("V_IndPhone"))
		}

		// 7b. GVLK + vĩnh viễn = lậu
		switch {
		case isGvlk && isPermanent:
			e.Error(i18n.Tf("P7_GvlkPermanent", ppk))
			r.flagCritical(i18n.Tf("V_IndGvlkPermanent", ppk))
			r.addCheck(i18n.T("V_ChkGvlk"), CheckDetected, i18n.Tf("V_ChkGvlkPerm", ppk))
		case isGvlk:
			e.Ok(i18n.Tf("P7_GvlkWithKms", ppk))
			r.addCheck(i18n.T("V_ChkGvlk"), CheckInfo, i18n.Tf("V_ChkGvlkKms", ppk))
		default:
			e.Ok(i18n.Tf("P7_NoGvlk", ppk))
			r.addCheck(i18n.T("V_ChkGvlk"), CheckOK, i18n.Tf("V_ChkGvlkNone", ppk))
		}

		// 7d. Key CÀI ĐẶT CHUNG (vd Y4G6T): chỉ mồi cài, không tự kích hoạt được.
		// Nếu máy vẫn "đã kích hoạt" thì kích hoạt thật đến từ nguồn khác (DE/KMS).
		if name, ok := license.InstallOnlyKeys[strings.ToUpper(ppk)]; ok {
			e.Info(i18n.Tf("P7_InstallOnlyKey", ppk, name))
			// Key cài đặt chung tự nó KHÔNG kích hoạt được. Máy vẫn "đã kích hoạt"
			// nghĩa là kích hoạt đến từ nguồn khác (Digital Entitlement/KMS/HWID) —
			// đây chính là dấu vân tay của kích hoạt kiểu KMS/HWID nên tính là một
			// điểm đáng ngờ CẦN XÁC MINH (warn, không phải chắc chắn lậu vì license
			// số chính hãng cũng dùng key chung như vậy).
			r.addCheck(i18n.T("V_ChkInstallKey"), CheckWarn, i18n.Tf("V_ChkInstallKeyActivated", ppk))
			if isLicensed {
				r.flagWarn(i18n.Tf("V_IndInstallOnlyLicensed", ppk))
			} else {
				r.flagWarn(i18n.Tf("V_IndInstallOnlyKey", ppk))
			}
		} else {
			r.addCheck(i18n.T("V_ChkInstallKey"), CheckOK, i18n.Tf("V_ChkInstallKeyNo", ppk))
		}

		// 7c. Kiểm tra bổ sung KMS Office trong registry
		if offKms, _ := p.OfficeKmsHostName(); offKms != "" {
			if IsOfficeKmsSuspicious(offKms, piracyDomains) {
				e.Warn(i18n.Tf("P7_OfficeKmsFound", offKms))
				r.flagWarn(i18n.Tf("V_IndOfficeKms", offKms))
			}
		}

		// ── 8. Phân tích ngày hết hạn ─────────────────────────────────────
		e.Blank()
		e.Sep()
		e.Fetch(i18n.T("Fetch_Expiry"))
		e.Diag(i18n.T("P7_ExpiryExplain"))
		ex := AnalyzeExpiry(prod.GracePeriodMins, isLicensed, now)
		switch ex.Class {
		case ExpiryPermanent:
			e.Info(i18n.T("P7_ExpiryPermanent"))
			r.addCheck(i18n.T("V_ChkExpiry"), CheckOK, i18n.T("V_ChkExpiryPerm"))
		case ExpiryTsforge:
			e.Error(i18n.Tf("P7_TsforgeExpiry", ex.Year))
			r.flagCritical(i18n.Tf("V_IndTsforge", ex.Year))
			r.addCheck(i18n.T("V_ChkExpiry"), CheckDetected, i18n.Tf("V_ChkExpiryTsforge", ex.Year))
		case ExpiryKms38:
			e.Error(i18n.Tf("P7_Kms38Expiry", ex.Year))
			r.flagCritical(i18n.Tf("V_IndKms38", ex.Year))
			r.addCheck(i18n.T("V_ChkExpiry"), CheckDetected, i18n.Tf("V_ChkExpiryKms38", ex.Year))
		case ExpiryOnline180:
			e.Data(i18n.T("P7_ExpiryDate"), ex.Expiry.Format("2006-01-02 15:04"))
			e.Warn(i18n.T("P7_OnlineKms180"))
			r.flagWarn(i18n.Tf("V_IndOnline180", int(ex.DaysLeft)))
			r.addCheck(i18n.T("V_ChkExpiry"), CheckWarn, i18n.Tf("V_ChkExpiry180", int(ex.DaysLeft)))
		case ExpiryNormal:
			e.Data(i18n.T("P7_ExpiryDate"), ex.Expiry.Format("2006-01-02 15:04"))
			e.Ok(i18n.T("P7_ExpiryNormal"))
			r.addCheck(i18n.T("V_ChkExpiry"), CheckOK, i18n.Tf("V_ChkExpiryNormal", ex.Expiry.Format("02/01/2006")))
		default:
			r.addCheck(i18n.T("V_ChkExpiry"), CheckSkipped, i18n.T("V_ChkNoData"))
		}
	} else {
		e.Info(i18n.T("P7_NoLicensedKey"))
		r.addCheck(i18n.T("V_ChkGvlk"), CheckSkipped, i18n.T("V_ChkNoLicense"))
		r.addCheck(i18n.T("V_ChkInstallKey"), CheckSkipped, i18n.T("V_ChkNoLicense"))
		r.addCheck(i18n.T("V_ChkExpiry"), CheckSkipped, i18n.T("V_ChkNoLicense"))
	}

	// ── 9. Dấu thời gian tệp kho SPP (độ tin cậy thấp) ──────────────────────
	e.Blank()
	e.Sep()
	e.Fetch(i18n.T("Fetch_SppStore"))
	e.Diag(i18n.T("P7_SppStoreExplain"))
	if !p.PathExists(sysinfo.SppStorePath) {
		e.Info(i18n.T("P7_SppStoreNotFound"))
		r.addCheck(i18n.T("V_ChkSppStore"), CheckSkipped, i18n.T("V_ChkSppStoreMissing"))
	} else {
		datMod, ok := p.FileModTime(sysinfo.SppStorePath)
		if !ok {
			e.Info(i18n.T("P7_SppStoreNotFound"))
			r.addCheck(i18n.T("V_ChkSppStore"), CheckSkipped, i18n.T("V_ChkSppStoreMissing"))
		} else {
			installDate, _ := p.WindowsInstallDate()
			if p.HasUpdateEventNear(datMod, 48) {
				e.Ok(i18n.T("P7_SppStoreOk"))
				r.addCheck(i18n.T("V_ChkSppStore"), CheckOK, i18n.T("V_ChkSppStoreOk"))
			} else if datMod.After(installDate.AddDate(0, 0, 2)) {
				e.Warn(i18n.Tf("P7_SppStoreModified", datMod.Format("2006-01-02 15:04")))
				r.flagWarn(i18n.Tf("V_IndSppStore", datMod.Format("2006-01-02 15:04")))
				r.addCheck(i18n.T("V_ChkSppStore"), CheckWarn, i18n.Tf("V_ChkSppStoreMod", datMod.Format("02/01/2006")))
			} else {
				e.Ok(i18n.T("P7_SppStoreOk"))
				r.addCheck(i18n.T("V_ChkSppStore"), CheckOK, i18n.T("V_ChkSppStoreOk"))
			}
		}
	}

	// ── 10. Nhật ký sự kiện bảo mật SPP ─────────────────────────────────────
	e.Blank()
	e.Sep()
	e.Fetch(i18n.T("Fetch_SppEvents"))
	e.Blank()
	events, _ := p.SppSecurityEvents()
	if len(events) == 0 {
		e.Ok(i18n.T("P7_SppEventNone"))
		r.addCheck(i18n.T("V_ChkSppEvent"), CheckOK, i18n.T("V_ChkSppEventNone"))
	} else {
		e.Info(i18n.Tf("P7_SppEventFound", len(events)))
		externalFound := false
		for _, ev := range events {
			if ev.EventCode != 12290 || ev.Message == "" {
				continue
			}
			m := reEventAddr.FindString(ev.Message)
			if m == "" {
				continue
			}
			if !IsPrivateOrLoopbackIP(m) && m != "localhost" {
				e.Error(i18n.Tf("P7_SppEventExternal", m))
				e.Error(i18n.T("P7_SppEventExternal2"))
				r.flagCritical(i18n.Tf("V_IndSppEvent", m))
				externalFound = true
			}
		}
		if !externalFound {
			e.Ok(i18n.T("P7_SppEventClean"))
			r.addCheck(i18n.T("V_ChkSppEvent"), CheckOK, i18n.Tf("V_ChkSppEventClean", len(events)))
		} else {
			r.addCheck(i18n.T("V_ChkSppEvent"), CheckDetected, i18n.T("V_ChkSppEventExt"))
		}
	}

	// ── Tổng kết ────────────────────────────────────────────────────────────
	e.Blank()
	e.Sep()
	e.Text(logx.KindAction, i18n.T("P7_SummaryHeader"))
	e.Blank()
	switch {
	case r.CriticalKms:
		e.Error(i18n.T("P7_Critical"))
		if r.SuspiciousCount > 1 {
			e.Error("  " + i18n.Tf("P7_TotalFlagged", r.SuspiciousCount))
		}
	case r.SuspiciousCount > 0:
		e.Warn(i18n.T("P7_Suspicious"))
		e.Warn("  " + i18n.Tf("P7_TotalFlagged", r.SuspiciousCount))
	default:
		e.Ok(i18n.T("P7_Clean"))
	}

	// ── Thông báo pháp lý (luôn hiển thị) ───────────────────────────────────
	e.Blank()
	e.Sep()
	e.Text(logx.KindWarn, i18n.T("P7_LegalHeader"))
	e.Diag(i18n.T("P7_LegalLine1"))
	e.Diag(i18n.T("P7_LegalLine2"))
	e.Diag(i18n.T("P7_LegalLine3"))
	e.Diag(i18n.T("P7_LegalLine4"))
	e.Blank()
	e.Diag(i18n.T("P7_LegalScanLimit"))

	return r
}

// checkKmsHostDNS kiểm tra internet và phân giải DNS của một host KMS đáng ngờ.
func checkKmsHostDNS(p sysinfo.Provider, host string, e *logx.Emitter) {
	e.Info(i18n.T("P7_CheckDns"))
	if !p.HasInternet() {
		e.Info(i18n.T("P7_NoInternet"))
		return
	}
	ips, err := p.ResolveHost(host)
	if err != nil || len(ips) == 0 {
		e.Warn(i18n.T("P7_KmsDnsNoResolve"))
		return
	}
	e.Info(i18n.T("P7_KmsDnsResolved") + strings.Join(ips, ", "))
	if HasPublicResolution(ips) {
		e.Error(i18n.T("P7_KmsDnsPublic"))
	} else {
		e.Warn(i18n.T("P7_KmsDnsPrivate"))
	}
}

// SuspiciousPaths dựng danh sách đường dẫn công cụ kích hoạt cần kiểm tra: các
// đường dẫn tích hợp (giải từ biến môi trường) cộng với đường dẫn tùy chỉnh.
func SuspiciousPaths(extra []string) []PathEntry {
	pf := envOr("ProgramFiles", `C:\Program Files`)
	pf86 := envOr("ProgramFiles(x86)", `C:\Program Files (x86)`)
	apd := envOr("APPDATA", "")
	pgd := envOr("ProgramData", `C:\ProgramData`)
	win := envOr("SystemRoot", `C:\Windows`)
	sys := filepath.Join(win, "System32")
	sysWow := filepath.Join(win, "SysWOW64")

	entries := []PathEntry{
		{filepath.Join(pf, "KMSpico"), "KMSpico"},
		{filepath.Join(pf86, "KMSpico"), "KMSpico"},
		{filepath.Join(apd, "KMSpico"), "KMSpico"},
		{filepath.Join(pgd, "KMSpico"), "KMSpico"},
		{filepath.Join(sys, "KMSELDI.exe"), "KMSpico/ELDI"},
		{filepath.Join(pf, "KMSAuto Net"), "KMSAuto Net"},
		{filepath.Join(pf86, "KMSAuto Net"), "KMSAuto Net"},
		{filepath.Join(pf, "KMSAuto"), "KMSAuto"},
		{filepath.Join(pf86, "KMSAuto"), "KMSAuto"},
		{filepath.Join(win, "KMS"), "KMS tools folder"},
		{filepath.Join(sys, "SppExtComObj.exe.bak"), "Patched SPP backup"},
		{filepath.Join(pf, "AAct"), "AAct"},
		{filepath.Join(pf86, "AAct"), "AAct"},
		{`C:\ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket\GenuineTicket.xml`, "KMS38 GenuineTicket"},
		{`C:\Program Files\Activation-Renewal\Activation_task.cmd`, "MAS Online KMS renewal task"},
		{`C:\Program Files\Activation-Renewal\Info.txt`, "MAS Online KMS renewal info"},

		// ── Bổ sung từ nghiên cứu: tệp payload/hook nạp thẳng vào SppExtComObj.exe
		//    của Microsoft nên không lộ tên tiến trình/dịch vụ — chỉ bắt được trên đĩa.
		{filepath.Join(win, "SECOH-QAD.exe"), "KMSpico SECOH-QAD"},
		{filepath.Join(win, "SECOH-QAD.dll"), "KMSpico SECOH-QAD"},
		{filepath.Join(sys, "SppExtComObjHook.dll"), "KMS_VL_ALL hook"},
		{filepath.Join(sysWow, "SppExtComObjHook.dll"), "KMS_VL_ALL hook"},
		{filepath.Join(sys, "SppExtComObjHookAvrf.dll"), "KMS_VL_ALL hook"},
		{filepath.Join(sys, "SppExtComObjPatcher.dll"), "SPP patcher"},
		{filepath.Join(sys, "SppExtComObjPatcher.exe"), "SPP patcher"},
		{filepath.Join(win, "Migration", "WTR", "KMS_VL_ALL.inf"), "KMS_VL_ALL (tàn dư cài đặt)"},
		// Thư mục/nhị phân activator nằm trong C:\Windows (còn sót dù tiến trình đã tắt).
		{filepath.Join(win, "AutoKMS", "AutoKMS.exe"), "Microsoft Toolkit AutoKMS"},
		{filepath.Join(win, "KMSAuto", "KMSSS.exe"), "KMSAuto/KMS server"},
		{filepath.Join(win, "AAct_Tools", "KMSSS.exe"), "AAct/KMS server"},
		{filepath.Join(win, "AAct_Tools"), "AAct Tools"},
		{filepath.Join(win, "AutoRearm", "AutoRearm.exe"), "Microsoft Toolkit AutoRearm"},
	}
	for _, x := range extra {
		entries = append(entries, PathEntry{Path: x, Tool: "[Tùy chỉnh]"})
	}
	return entries
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// matchesAny kiểm tra s có chứa (không phân biệt hoa thường) bất kỳ từ khóa nào.
func matchesAny(s string, keywords []string) bool {
	ls := strings.ToLower(s)
	for _, k := range keywords {
		if k != "" && strings.Contains(ls, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// containsFold kiểm tra danh sách có phần tử bằng target (không phân biệt hoa thường).
func containsFold(list []string, target string) bool {
	for _, v := range list {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}
