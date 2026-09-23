// Package i18n chứa toàn bộ chuỗi hiển thị của WinCheck bằng tiếng Việt.
//
// Ứng dụng này được phát hành riêng cho thị trường Việt Nam nên chỉ có một ngôn
// ngữ duy nhất. Việc gom chuỗi vào một nơi giúp giữ giao diện nhất quán và thuận
// tiện khi cần rà soát câu chữ.
package i18n

import "fmt"

// M là bảng tra chuỗi theo khóa.
var M = map[string]string{
	// ── Cửa sổ / tiêu đề ────────────────────────────────────────────────────
	"AppTitle":   "WinCheck - Trình Quản Lý Bản Quyền Windows",
	"AppVersion": "v1.0",
	"AdminOk":    "✔  Đang chạy với quyền Quản trị viên, đầy đủ tính năng",
	"AdminWarn":  "⚠  Chưa có quyền Quản trị viên, tùy chọn 4, 5, 6 cần nâng quyền",
	"BtnElevate": "⚡ Chạy lại với quyền Admin",
	"BtnAbout":   "Giới thiệu",

	// ── Nút chức năng ở thanh bên ──────────────────────────────────────────
	"Btn1":             "1. Phiên bản OS & Key OEM BIOS",
	"Btn2":             "2. Kênh & Loại Bản Quyền",
	"Btn3":             "3. Key & Trạng thái Kích Hoạt",
	"Btn4":             "4. Kiểm thử & Cài Key Bản Quyền",
	"Btn5":             "5. Gỡ Key Bản Quyền",
	"Btn6":             "6. Đặt Lại Kích Hoạt (Rearm)",
	"Btn7":             "7. Kiểm Tra Kích Hoạt Bên Thứ Ba",
	"BtnAuditSettings": "⚙  Cài đặt Kiểm tra",
	"BtnClear":         "Xóa nhật ký",

	// ── Tiêu đề hành động trong nhật ký ────────────────────────────────────
	"Act1": "Tùy chọn 1: Phiên bản OS & Key Bản Quyền OEM BIOS",
	"Act2": "Tùy chọn 2: Kênh & Loại Bản Quyền",
	"Act3": "Tùy chọn 3: Xem Key Đang Dùng & Trạng thái Kích Hoạt",
	"Act4": "Tùy chọn 4: Kiểm thử & Cài Key Bản Quyền",
	"Act5": "Tùy chọn 5: Gỡ Key Bản Quyền hiện tại",
	"Act6": "Tùy chọn 6: Đặt lại Trạng thái Bản quyền / Rearm",
	"Act7": "Tùy chọn 7: Kiểm Tra Kích Hoạt Bên Thứ Ba",
	"Act8": "Tùy chọn 8: Dọn Sạch Crack",
	"Act9": "Tùy chọn 9: Gỡ Sạch Key Office Lậu",

	// ── Tùy chọn 8: Dọn Sạch Crack ─────────────────────────────────────────
	"O8_Warn1":          "⚠ Thao tác này XÓA công cụ crack và GỠ key kích hoạt: sau khi chạy, Windows sẽ trở thành CHƯA KÍCH HOẠT.",
	"O8_Warn2":          "Chỉ chạy khi bạn muốn gỡ sạch crack để chuyển sang key bản quyền thật.",
	"O8_Confirm":        "Bạn CHẮC CHẮN muốn dọn sạch crack?\n\nWinCheck sẽ: kết thúc tiến trình + dừng/xóa dịch vụ + xóa tác vụ định kỳ + gỡ hook IFEO + xóa cấu hình KMS + xóa tệp công cụ crack + gỡ key kích hoạt.\n\nSau khi chạy, Windows sẽ CHƯA kích hoạt và cần cài key bản quyền thật.",
	"O8_Cancelled":      "Đã hủy dọn crack.",
	"O8_StepProc":       "Đang kết thúc tiến trình công cụ crack…",
	"O8_StepSvc":        "Đang dừng và xóa dịch vụ crack…",
	"O8_StepTask":       "Đang xóa tác vụ định kỳ crack…",
	"O8_StepHook":       "Đang gỡ hook IFEO trên nhị phân dịch vụ bản quyền…",
	"O8_StepKms":        "Đang xóa cấu hình máy chủ KMS trong Registry…",
	"O8_StepFiles":      "Đang xóa tệp/thư mục công cụ crack…",
	"O8_StepKey":        "Đang gỡ key kích hoạt và dọn Registry…",
	"O8_ProcKilled":     "Đã kết thúc tiến trình:  %s  (PID %d)",
	"O8_ProcFail":       "Không kết thúc được tiến trình %s: %s",
	"O8_SvcDeleted":     "Đã dừng và xóa dịch vụ:  %s",
	"O8_SvcFail":        "Không xóa được dịch vụ %s: %s",
	"O8_TaskDeleted":    "Đã xóa tác vụ định kỳ:  %s",
	"O8_TaskFail":       "Không xóa được tác vụ %s: %s",
	"O8_HookRemoved":    "Đã gỡ %d hook IFEO trên nhị phân dịch vụ bản quyền.",
	"O8_HookFail":       "Không gỡ được hook IFEO: %s",
	"O8_HookNone":       "Không có hook IFEO nào cần gỡ.",
	"O8_KmsCleared":     "Đã xóa %d cấu hình máy chủ KMS trong Registry.",
	"O8_KmsNone":        "Không có cấu hình máy chủ KMS nào trong Registry.",
	"O8_FileDeleted":    "Đã xóa:  %s  →  %s",
	"O8_FileFail":       "Không xóa được %s: %s  (có thể đang bị khóa bởi tiến trình khác)",
	"O8_KeyUninstalled": "Đã gỡ key kích hoạt và dọn key khỏi Registry.",
	"O8_KeyFail":        "Không gỡ được key kích hoạt: %s",
	"O8_Done":           "Đã dọn xong %d mục crack.",
	"O8_DoneNote":       "Windows hiện CHƯA kích hoạt. Hãy cài key bản quyền thật để kích hoạt lại.",
	"O8_Nothing":        "Không tìm thấy dấu vết crack nào để dọn. Máy đã sạch.",
	"O8_BuyHint":        "Cần mua key bản quyền Windows + Office chính hãng? Liên hệ Zalo: 0352 194 195 (https://zalo.me/0352194195)",

	// ── Tùy chọn 9: Gỡ Sạch Key Office Lậu ────────────────────────────────────
	"O9_Warn1":          "⚠ Thao tác này XÓA cấu hình máy chủ KMS lậu và GỠ toàn bộ key Office đã kích hoạt lậu trên máy.",
	"O9_Warn2":          "Chỉ chạy khi bạn muốn gỡ sạch key crack để chuyển sang sử dụng key bản quyền Office chính hãng.",
	"O9_Confirm":        "GỠ SẠCH KEY OFFICE LẬU\n\nWinCheck sẽ quét tất cả phiên bản Office (Office 2010 - 2024, Office 365), xóa máy chủ KMS lậu và gỡ bỏ toàn bộ key kích hoạt tồn đọng.\n\nSau khi gỡ, bạn có thể nhập key bản quyền chính hãng để kích hoạt lại Office.\n\nBạn CHẮC CHẮN muốn tiếp tục?",
	"O9_Cancelled":      "Đã hủy thao tác gỡ key Office.",
	"O9_ScanningOffice": "Đang tìm kiếm các bản cài đặt Microsoft Office trên máy…",
	"O9_NoOfficeFound":  "Không tìm thấy file ospp.vbs nào! Office của bạn có thể là bản Microsoft Store (không hỗ trợ ospp.vbs) hoặc chưa được cài đặt.",
	"O9_OfficeFound":    "Tìm thấy Office tại: %s",
	"O9_RemovingKms":    "Xóa cấu hình máy chủ KMS Office (ospp.vbs /remhst)…",
	"O9_KmsRemoved":     "Đã xóa máy chủ KMS cho thư mục Office này.",
	"O9_ScanningKeys":   "Đang quét các key Office hiện có (ospp.vbs /dstatus)…",
	"O9_NoKeysFound":    "Không tìm thấy key nào tại đây.",
	"O9_KeysFound":      "Tìm thấy %d key Office cần gỡ.",
	"O9_DeletingKey":    "Đang gỡ key: %s",
	"O9_KeyDeleted":     "Đã xóa thành công key %s",
	"O9_KeyDeleteFail":  "Không xóa được key %s",
	"O9_Rechecking":     "Kiểm tra lại trạng thái bản quyền sau khi gỡ…",
	"O9_AllClean":       "[THÀNH CÔNG] Đã xóa toàn bộ key crack! Liên hệ : 0352 194 195 (gặp Tuấn) để mua key bản quyền",
	"O9_StillRemaining": "[CẢNH BÁO] Vẫn còn %d key Office chưa được gỡ!",
	"O9_ClearRegistry":  "Đang dọn dẹp cấu hình KMS Office trong Registry…",
	"O9_RegistryCleaned": "Đã xóa %d khóa cấu hình KMS Office trong Registry.",
	"O9_DoneSummary":    "Tổng kết: Đã xử lý %d thư mục Office, gỡ thành công %d key.",
	"O9_BuyHint":        "Cần mua key bản quyền Office 2016 / 2019 / 2021 / 365 chính hãng? Liên hệ: 0352 194 195 (Zalo: https://zalo.me/0352194195)",

	// ── Nâng quyền ─────────────────────────────────────────────────────────
	"ElevateTitle":      "Yêu Cầu Quyền Admin",
	"ElevateFail":       "Không thể yêu cầu nâng quyền: ",
	"ElevateFromOption": "Tùy chọn này yêu cầu quyền Quản trị viên.\n\nKhởi chạy lại WinCheck với quyền Admin ngay bây giờ?\n\nLưu ý: Nhật ký phiên trước sẽ được giữ lại.",
	"NeedAdminOption":   "Tùy chọn này cần quyền Quản trị viên. Hãy bấm nút '⚡ Chạy lại với quyền Admin' ở góc trên bên phải.",

	// ── Hộp thoại chung ────────────────────────────────────────────────────
	"Confirm_Title":   "Xác nhận",
	"ShowKey_Title":   "Hiển thị Key Bản Quyền",
	"ShowKey_Q":       "Hiển thị đầy đủ Key Bản Quyền?\n(Không = chỉ hiện 5 ký tự cuối)",
	"O3_RemoveTitle":  "Xóa Key Dự phòng cũ",
	"O6_RestartTitle": "Khởi động lại máy tính",

	// ── Thanh trạng thái / chung ───────────────────────────────────────────
	"Ready":           "Sẵn sàng",
	"LogCleared":      "Đã xóa nhật ký.",
	"Startup_Ready":   "WinCheck sẵn sàng.",
	"LogRestored":     "▲ Nhật ký được khôi phục từ phiên trước (trước khi nâng quyền)",
	"Startup_NoAdmin": "Không có quyền Quản trị. Tùy chọn 1, 2, 3, 7 hoạt động bình thường. Tùy chọn 4, 5, 6 sẽ yêu cầu nâng quyền khi được chọn.",

	// ── Nút hộp thoại nhập ─────────────────────────────────────────────────
	"Dialog_OK":     "Xác nhận",
	"Dialog_Cancel": "Hủy",

	// ── Thông điệp truy vấn ────────────────────────────────────────────────
	"Fetch_OS":      "Đang truy vấn thông tin hệ điều hành…",
	"Fetch_BiosKey": "Đang kiểm tra Key Bản Quyền OEM trên BIOS/UEFI…",
	"Fetch_License": "Đang truy vấn bản quyền Windows đang hoạt động (WMI)…",
	"Fetch_RegKey":  "Đang đọc Key Bản Quyền dự phòng từ Registry…",

	// ── Nhãn dữ liệu ───────────────────────────────────────────────────────
	"D_OsEdition":    "Phiên bản Windows:",
	"D_Version":      "Số phiên bản:",
	"D_Build":        "Số build:",
	"D_Arch":         "Kiến trúc hệ thống:",
	"D_Edition":      "Ấn bản:",
	"D_Channel":      "Kênh phân phối:",
	"D_PartialKey":   "Key một phần:",
	"D_BiosOemKey":   "Key Bản Quyền OEM BIOS:",
	"D_RegBackupKey": "Key Dự phòng (Registry):",

	// ── Trạng thái bản quyền ───────────────────────────────────────────────
	"LS_0":       "Chưa được cấp phép",
	"LS_1":       "Đã được cấp phép (Kích hoạt vĩnh viễn)",
	"LS_2":       "Thời gian ân hạn OOB",
	"LS_3":       "Thời gian ân hạn OOT",
	"LS_4":       "Thời gian ân hạn không chính hãng",
	"LS_5":       "Chế độ thông báo",
	"LS_6":       "Thời gian ân hạn mở rộng",
	"LS_Unknown": "Không xác định",

	// ── Nhận diện ấn bản từ key OEM BIOS ───────────────────────────────────
	"Fetch_OemEdition": "Đang xác định ấn bản từ Key Bản Quyền OEM BIOS…",
	"OemEd_Found":      "Phát hiện ấn bản tương ứng:",
	"OemEd_NoMatch":    "Không thể xác định ấn bản chỉ từ Key Bản Quyền.",
	"OemEd_Hint":       "Gợi ý: cài đặt Key (Tùy chọn 4) để Windows xác nhận ấn bản.",

	// ── Digital Entitlement ────────────────────────────────────────────────
	"DE_Confirmed":    "Phương thức kích hoạt:  Digital Entitlement (bản quyền gắn phần cứng)",
	"DE_Explain1":     "Windows được cấp phép qua Digital Entitlement lưu trên máy chủ Microsoft.",
	"DE_Explain2":     "Bản quyền này gắn với phần cứng (dấu vân tay bo mạch chủ) và/hoặc tài khoản Microsoft của bạn.",
	"DE_Explain3":     "Key Bản Quyền đang dùng ở trên là key chung thay thế, kích hoạt thực sự nằm trên cloud của Microsoft.",
	"DE_KeyMismatch":  "Key Bản Quyền OEM BIOS và dự phòng có thể khác Key đang dùng, điều này bình thường với hệ thống kích hoạt bằng DE.",
	"DE_Verify":       "Để xác nhận: Cài đặt → Hệ thống → Kích hoạt → tìm 'Giấy phép kỹ thuật số'",
	"DE_NotActivated": "Phương thức kích hoạt:  Phát hiện key chung DE, nhưng trạng thái KHÔNG được kích hoạt.",
	"KMS_Detected":    "Phương thức kích hoạt:  KMS (Bản quyền doanh nghiệp/tập thể)",
	"KMS_Server":      "Máy chủ KMS:",
	"MAK_Detected":    "Phương thức kích hoạt:  MAK / Retail / OEM (kích hoạt tiêu chuẩn)",

	// ── Tùy chọn 2 ─────────────────────────────────────────────────────────
	"O2_Note":          "Lưu ý: chỉ 5 ký tự cuối của Key Bản Quyền đang hoạt động được hiển thị.",
	"O2_NoOutput":      "Không đọc được thông tin bản quyền đang hoạt động.",
	"O2_LicenseStatus": "Trạng thái bản quyền:  ",
	"O2_Running":       "Đang đọc thông tin bản quyền qua Software Licensing API (WMI)…",

	// ── Tùy chọn 3 ─────────────────────────────────────────────────────────
	"O3_NoLicense":      "Không tìm thấy bản quyền Windows đang hoạt động qua WMI.",
	"O3_BiosNone":       "Không phát hiện",
	"O3_BiosDetected":   "✔ Đã phát hiện",
	"O3_RegNone":        "Không tìm thấy",
	"O3_KeysFoundCtx":   "Phát hiện Key Bản Quyền trong BIOS và/hoặc Registry.",
	"O3_KeyBios":        "Key OEM BIOS:  ",
	"O3_KeyReg":         "Key Dự phòng (Registry):  ",
	"O3_Mismatch":       "⚠  Key Dự phòng trong Registry KHÔNG khớp với Key Bản Quyền đang hoạt động.",
	"O3_MismatchReason": "Điều này có thể xảy ra sau khi nâng cấp ấn bản hoặc thay đổi phương thức kích hoạt.",
	"O3_ActivePartial":  "Key đang dùng kết thúc với:  ",
	"O3_BackupEnds":     "Key Dự phòng Registry kết thúc với:  ",
	"O3_ConfirmRemove":  "Key Dự phòng trong Registry (lưu tại HKLM\\...\\SoftwareProtectionPlatform → BackupProductKeyDefault) không khớp với Key đang hoạt động.\n\nKey dự phòng này có thể là tàn dư từ lần kích hoạt hoặc nâng cấp ấn bản trước đó.\n\nXóa Key Dự phòng trong Registry?\n\nLưu ý: Trạng thái kích hoạt Windows hiện tại sẽ KHÔNG bị ảnh hưởng, chỉ xóa bản sao lưu.",
	"O3_RegKeyRemoved":  "Đã xóa Key Dự phòng khỏi Registry.",
	"O3_NeedAdmin":      "⚠ Chạy với quyền Administrator để xóa key dự phòng cũ.",
	"O3_RemoveErr":      "Không thể xóa Key Bản Quyền: ",
	"O3_RegReadErr":     "Lỗi đọc Registry: ",
	"O3_KeyMatch":       "✔  Key Dự phòng trong Registry khớp với Key Bản Quyền đang hoạt động.",
	"O3_DlvQ":           "Có muốn xem báo cáo bản quyền mở rộng không?\n\nBáo cáo này hiển thị:\n  • Kênh & kênh phụ bản quyền (Retail / OEM / Volume)\n  • SKU ID đầy đủ và mô tả\n  • Cấu hình máy chủ KMS & số lượng client\n  • Số lần rearm (đặt lại) còn lại\n  • Thời hạn kích hoạt / thời gian ân hạn\n  • ID máy duy nhất (CMID)\n\nHữu ích để chẩn đoán chi tiết vấn đề kích hoạt.",
	"O3_DlvTitle":       "Báo cáo Bản quyền Mở rộng",
	"O3_Activation":     "Kích hoạt:  ",

	// ── Tùy chọn 1 ─────────────────────────────────────────────────────────
	"O1_BiosDetectedCtx": "Phát hiện Key Bản Quyền OEM được nhúng trong firmware BIOS/UEFI.",
	"O1_BiosKey":         "Key Bản Quyền OEM BIOS:  ",
	"O1_BiosNone":        "Không phát hiện Key Bản Quyền OEM trên firmware BIOS/UEFI.",

	// ── Tùy chọn 4 ─────────────────────────────────────────────────────────
	"O4_Info1":       "Kiểm thử Key Bản Quyền bằng cách thử cài đặt key đã nhập trên máy.",
	"O4_Info2":       "Trạng thái kích hoạt hiện tại sẽ KHÔNG bị ảnh hưởng nếu key bị từ chối hoặc thuộc ấn bản khác.",
	"O4_Prompt":      "Nhập Key Bản Quyền gồm 25 ký tự:\n\nĐịnh dạng:  XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
	"O4_PromptTitle": "Nhập Key Bản Quyền",
	"O4_Cancelled":   "Đã hủy, không nhập Key Bản Quyền.",
	"O4_BadFormat":   "Định dạng không hợp lệ. Key phải có dạng  XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
	"O4_ShowKeyCtx":  "Sắp cài đặt Key Bản Quyền.",
	"O4_Installing":  "Đang cài đặt key:  ",
	"O4_Success1":    "Key Bản Quyền được chấp nhận! Windows sẽ tự động kích hoạt trực tuyến.",
	"O4_Success2":    "Kiểm tra trạng thái kích hoạt ở Tùy chọn 3 hoặc Tùy chọn 2.",
	"O4_Fail":        "Key Bản Quyền bị Windows từ chối.",
	"O4_DiagSku":     "SKU không khớp, Key thuộc ấn bản Windows khác (ví dụ: Home và Pro).",
	"O4_DiagInvalid": "Key không hợp lệ, Key Bản Quyền bị sai hoặc nhập nhầm.",
	"O4_DiagBlocked": "Key bị chặn, Key Bản Quyền này đã bị Microsoft thu hồi.",
	"O4_DiagGeneral": "Kiểm tra mã lỗi để biết thêm thông tin.",

	// ── Tùy chọn 5 ─────────────────────────────────────────────────────────
	"O5_Confirm":      "⚠  CẢNH BÁO\n\nThao tác này sẽ gỡ cài đặt Key Bản Quyền Windows hiện tại VÀ xóa khỏi Registry.\n\nWindows sẽ trở thành CHƯA ĐƯỢC KÍCH HOẠT sau thao tác này.\n\nTiếp tục?",
	"O5_Cancelled":    "Đã hủy.",
	"O5_Uninstalling": "Đang gỡ cài đặt Key Bản Quyền qua Software Licensing API…",
	"O5_Clearing":     "Đang xóa Key Bản Quyền khỏi Registry qua Software Licensing API…",
	"O5_Done":         "Đã gỡ cài đặt Key Bản Quyền và xóa khỏi Registry.",

	// ── Tùy chọn 6 ─────────────────────────────────────────────────────────
	"O6_Confirm":    "⚠  CẢNH BÁO\n\nThao tác này đặt lại trạng thái bản quyền và bộ đếm kích hoạt (rearm).\n\nCần khởi động lại máy tính để áp dụng thay đổi.\n\nTiếp tục?",
	"O6_Cancelled":  "Đã hủy.",
	"O6_Rearming":   "Đang đặt lại bộ đếm kích hoạt qua Software Licensing API…",
	"O6_Done":       "Rearm hoàn tất. Khởi động lại máy tính để áp dụng thay đổi.",
	"O6_RestartQ":   "Khởi động lại máy tính ngay bây giờ?",
	"O6_Restarting": "Đang khởi động lại sau 5 giây…",

	// ── Tùy chọn 7, phần mở đầu ───────────────────────────────────────────
	"P7_Header":      "══ CÁC KIỂM TRA TRONG LẦN QUÉT NÀY ══",
	"P7_CanDetect1":  "① Tên máy chủ KMS / registry → phát hiện KMS giả lập CỤC BỘ (KMSpico, vlmcsd…) VÀ dịch vụ KMS lậu trên CLOUD (ví dụ msguides.com, máy chủ KMS công cộng)",
	"P7_CanDetect2":  "② Kiểm tra cổng localhost → xác nhận dịch vụ KMS cục bộ đang hoạt động",
	"P7_CanDetect3":  "③ Dịch vụ hệ thống → dịch vụ kích hoạt cài cố định, tồn tại qua các lần khởi động lại",
	"P7_CanDetect4":  "④ Tác vụ định kỳ → tác vụ tự động kích hoạt lại, phổ biến ở KMSpico/KMSAuto",
	"P7_CanDetect5":  "⑤ Đường dẫn tập tin/thư mục → phần còn lại sau khi cài đặt công cụ kích hoạt",
	"P7_CanDetect6":  "⑥ Tiến trình đang chạy → công cụ kích hoạt đang hoạt động tại thời điểm quét",
	"P7_LimitHeader": "══ GIỚI HẠN ĐÃ BIẾT, KHÔNG THỂ PHÁT HIỆN ══",
	"P7_Limit1":      "• HWID (MAS): lấy bản quyền kỹ thuật số DO MICROSOFT CẤP, không thể phân biệt với bản quyền mua. Chỉ có thể phát hiện nếu GVLK / key chung vẫn còn cài đặt.",
	"P7_Limit2":      "• Kích hoạt đã dọn sạch: nếu công cụ bị gỡ hoàn toàn sau khi dùng, mọi dấu vết đều mất, kích hoạt vẫn còn nhưng không để lại vết.",
	"P7_Limit3":      "• Vá SLIC/OEM BIOS kiểu cũ (thời Windows Loader): sửa đổi bảng firmware ở mức không thể thấy qua phân tích phần mềm.",
	"P7_Limit4":      "• KMS doanh nghiệp: KMS hợp lệ của công ty trên máy chủ nội bộ có thể kích hoạt một số cảnh báo GVLK, luôn xác nhận với bộ phận IT.",

	// ── Tùy chọn 7, giải thích từng bước ──────────────────────────────────
	"P7_KmsExplain":      "KMS lậu hoạt động dưới hai dạng: (1) GIẢ LẬP CỤC BỘ, máy chủ KMS giả chạy trên 127.x.x.x lừa Windows từ bên trong máy; (2) DỊCH VỤ CLOUD, máy chủ KMS bên thứ ba trên internet (ví dụ km8.msguides.com) mà bất kỳ ai cũng có thể cấu hình. Microsoft KHÔNG cung cấp máy chủ KMS công cộng, bất kỳ máy chủ KMS nào trên internet đều là dịch vụ kích hoạt trái phép.",
	"P7_Port1688Explain": "Cổng kích hoạt KMS bên dưới được kiểm tra trên localhost. Cổng mở nghĩa là có KMS giả lập đang chạy cục bộ, đây là dấu hiệu đơn lẻ mạnh nhất của kích hoạt KMS lậu.",
	"P7_ServiceExplain":  "KMS giả lập thường cài đặt dưới dạng dịch vụ Windows để tồn tại qua khởi động lại và định kỳ kích hoạt lại. Các tên dịch vụ đã biết được kiểm tra bên dưới.",
	"P7_TaskExplain":     "Công cụ như KMSpico tạo tác vụ định kỳ (ví dụ 'AutoKMS') để kích hoạt lại Windows theo chu kỳ, ngăn hết hạn thời gian ân hạn.",
	"P7_FileExplain":     "Thư mục cài đặt, tập tin thực thi (KMSELDI.exe) và tập tin hệ thống bị vá được kiểm tra đối chiếu danh sách đường dẫn đã biết.",
	"P7_ProcExplain":     "Một số công cụ kích hoạt để lại tiến trình thường trú. Kiểm tra này liệt kê các tiến trình đang chạy có tên trùng với công cụ đã biết.",

	// ── Tùy chọn 7, nhãn bước quét ────────────────────────────────────────
	"Fetch_KmsHost":    "① Kiểm tra tên máy chủ KMS (registry + WMI)…",
	"Fetch_Port1688":   "② Kiểm tra cổng KMS đã cấu hình trên localhost…",
	"Fetch_Services":   "③ Quét dịch vụ hệ thống…",
	"Fetch_Tasks":      "④ Quét tác vụ định kỳ…",
	"Fetch_Files":      "⑤ Quét đường dẫn công cụ đã biết…",
	"Fetch_Procs":      "⑥ Quét tiến trình đang chạy…",
	"Fetch_ActChannel": "⑦ Kiểm tra kênh kích hoạt và loại khóa (WMI)…",
	"Fetch_Expiry":     "⑧ Phân tích ngày hết hạn kích hoạt (WMI)…",
	"Fetch_SppStore":   "⑨ Kiểm tra dấu thời gian tệp kho SPP…",
	"Fetch_SppEvents":  "⑩ Kiểm tra nhật ký sự kiện kích hoạt SPP…",

	// ── Tùy chọn 7, kết quả quét ──────────────────────────────────────────
	"P7_KmsLocal":          "KMS GIẢ LẬP CỤC BỘ, Máy chủ KMS trỏ đến localhost/127.x.x.x!",
	"P7_KmsLocal2":         "Có KMS giả (KMSpico, vlmcsd, KMSAuto) đang chạy cục bộ trên máy.",
	"P7_KmsName":           "Máy chủ KMS đã cấu hình:",
	"P7_KmsNone":           "Không có máy chủ KMS nào được cấu hình.",
	"P7_KmsCloudPiracy":    "PHÁT HIỆN DỊCH VỤ KMS LẬU TRÊN CLOUD, đây là máy chủ KMS công cộng trên internet và KHÔNG do Microsoft vận hành! Microsoft không cung cấp máy chủ KMS công cộng. Đây là dịch vụ kích hoạt trái phép của bên thứ ba.",
	"P7_KmsKnownPiracy":    "TÊN MIỀN KMS LẬU ĐÃ BIẾT, đây là dịch vụ kích hoạt bên thứ ba đã được nhận dạng, không phải máy chủ của Microsoft!",
	"P7_KmsMsOfficial":     "Điểm cuối KMS Azure của Microsoft, đây là máy chủ hợp lệ do Microsoft vận hành.",
	"P7_KmsMsOfficialNote": "Lưu ý: KMS Azure (kms.core.windows.net / azkms.core.windows.net) chỉ hợp lệ trong máy ảo Microsoft Azure. Trên máy vật lý hoặc máy không phải Azure, cấu hình này bất thường và cần kiểm tra.",
	"P7_KmsCorporate":      "Máy chủ KMS trên địa chỉ mạng nội bộ, phù hợp với triển khai doanh nghiệp hợp lệ.",
	"P7_PortOpen":          "Cổng %d ĐANG MỞ trên localhost, có dịch vụ KMS cục bộ đang chạy!",
	"P7_PortOpenServer":    "Cổng %d đang mở, nhưng máy là Windows Server nên có thể là KMS host chính hãng (không kết luận lậu).",
	"P7_PortClosed":        "Cổng %d trên localhost đã đóng, không có dịch vụ KMS cục bộ.",
	"P7_KmsBogusIp":        "PHÁT HIỆN IP KMS GIẢ, Máy chủ KMS được đặt thành 10.0.0.10, một IP không thể định tuyến được MAS Online KMS sử dụng khi không cài tác vụ gia hạn. Điều này ngăn thông báo kích hoạt Office nhưng không thực sự kích hoạt Windows hợp lệ.",
	"P7_OfficeKmsFound":    "Máy chủ KMS Office đã cấu hình: %s, bị gắn cờ đáng ngờ (tên miền lậu hoặc host bên ngoài)",

	// ── Tùy chọn 7, lớp 7: GVLK + kênh kích hoạt ──────────────────────────
	"P7_GvlkExplain":   "Kiểm tra xem khóa Windows đã cài đặt có phải là Khóa Cấp phép Số lượng Lớn Chung (GVLK) hoặc khóa HWID placeholder đã biết công khai hay không. GVLK kết hợp kích hoạt vĩnh viễn (không có đếm ngược gia hạn KMS) cho thấy TSforge, KMS38 hoặc kích hoạt HWID lậu. Máy KMS doanh nghiệp hợp lệ luôn có chu kỳ gia hạn 180 ngày.",
	"P7_GvlkPermanent": "CÓ KHẢ NĂNG LẬU, Khóa GVLK/placeholder '%s' được cài đặt với kích hoạt VĨNH VIỄN (không có đếm ngược gia hạn KMS). KMS doanh nghiệp hợp lệ luôn hiển thị đếm ngược 180 ngày. Mẫu này khớp với TSforge, KMS38 hoặc kích hoạt HWID qua MAS.",
	"P7_GvlkWithKms":   "Phát hiện khóa GVLK '%s' với gia hạn KMS đang hoạt động, phù hợp với kích hoạt KMS doanh nghiệp hợp lệ. Xác minh máy chủ KMS ở trên.",
	"P7_NoGvlk":        "Khóa đã cài đặt (kết thúc: %s) KHÔNG phải là GVLK hoặc khóa placeholder đã biết.",
	"P7_PhoneChannel":  "KÊNH KÍCH HOẠT QUA ĐIỆN THOẠI BẤT THƯỜNG, Windows báo cáo kích hoạt qua Điện thoại trên máy không có lịch sử kích hoạt qua điện thoại. Đây là dấu hiệu đặc trưng của phương thức con TSforge ZeroCID, giả mạo ID xác nhận kích hoạt qua điện thoại vào kho SPP.",
	"P7_NoLicensedKey": "Không tìm thấy khóa Windows đã cấp phép qua WMI.",

	// ── Tùy chọn 7, lớp 8: phân tích hết hạn ──────────────────────────────
	"P7_ExpiryExplain":   "Phân tích ngày hết hạn kích hoạt / thời gian ân hạn còn lại qua WMI. Ngày hết hạn bất thường là dấu hiệu mạnh của các phương thức kích hoạt lậu cụ thể.",
	"P7_Kms38Expiry":     "PHÁT HIỆN KÍCH HOẠT KMS38 CŨ, Ngày hết hạn kích hoạt được đặt thành năm %d (≈ 2038-01-19, dấu thời gian 32-bit tối đa). KMS38 hiện đã được Microsoft vá (cập nhật tháng 11/2025 KB5068861) nhưng máy chưa vá vẫn có thể hiển thị ngày hết hạn này.",
	"P7_TsforgeExpiry":   "PHÁT HIỆN KÍCH HOẠT TSFORGE KMS4K, Ngày hết hạn kích hoạt được đặt thành năm %d (hàng nghìn năm trong tương lai). Đây là phương thức con 'KMS4k' của TSforge, giả mạo hợp đồng thuê KMS có hiệu lực 4000+ năm trực tiếp vào kho tin cậy SPP.",
	"P7_OnlineKms180":    "CHU KỲ KMS TRỰC TUYẾN 180 NGÀY, Kích hoạt hết hạn sau khoảng 180 ngày, phù hợp với chu kỳ gia hạn Online KMS. Kết hợp với máy chủ KMS bên ngoài được cấu hình ở trên, điều này cho thấy rõ MAS Online KMS hoặc dịch vụ tương tự.",
	"P7_ExpiryNormal":    "Ngày hết hạn kích hoạt có vẻ bình thường.",
	"P7_ExpiryPermanent": "Windows báo cáo kích hoạt vĩnh viễn (không có đếm ngược hết hạn).",
	"P7_ExpiryDate":      "Ngày hết hạn:",

	// ── Tùy chọn 7, lớp 9: dấu thời gian kho SPP ──────────────────────────
	"P7_SppStoreExplain":  "TSforge sửa đổi trực tiếp các tệp kho tin cậy SPP Windows (data.dat). Dấu LastWriteTime trên các tệp này không tương ứng với bất kỳ sự kiện Windows Update nào là dấu hiệu ĐỘ TIN CẬY THẤP.",
	"P7_SppStoreModified": "[ĐỘ TIN CẬY THẤP] Tệp kho SPP đã được sửa đổi ngoài ngữ cảnh Windows Update (LastWriteTime: %s). Điều này CÓ THỂ cho thấy kích hoạt TSforge, nhưng Windows Update và khắc phục sự cố hợp lệ cũng có thể sửa đổi tệp này. Xem báo cáo bản quyền mở rộng để điều tra thêm.",
	"P7_SppStoreOk":       "Dấu thời gian tệp kho SPP tương ứng với sự kiện Windows Update gần đây, không phát hiện bất thường.",
	"P7_SppStoreNotFound": "Không tìm thấy tệp kho SPP tại đường dẫn dự kiến, không thể kiểm tra.",
	"P7_InstallDate":      "Ngày cài đặt Windows:",

	// ── Tùy chọn 7, lớp 10: nhật ký sự kiện SPP ───────────────────────────
	"P7_SppEventNone":      "Không tìm thấy sự kiện bảo mật kích hoạt SPP trong nhật ký Hệ thống.",
	"P7_SppEventFound":     "Tìm thấy %d sự kiện bảo mật SPP trong nhật ký Hệ thống.",
	"P7_SppEventExternal":  "Sự kiện SPP 12290: yêu cầu KMS tới máy chủ bên ngoài: %s",
	"P7_SppEventExternal2": "Điều này xác nhận kích hoạt qua dịch vụ KMS công cộng trái phép.",
	"P7_SppEventClean":     "Có sự kiện SPP, không tìm thấy địa chỉ máy chủ KMS bên ngoài trong dữ liệu sự kiện.",

	// ── Tùy chọn 7, DNS / internet ────────────────────────────────────────
	"P7_KmsDomainCount":  "Tên miền KMS lậu trong danh sách quét: %d (mặc định tích hợp sẵn)",
	"P7_GvlkCount":       "Số hậu tố GVLK đang dùng để đối chiếu: %d",
	"P7_CheckDns":        "Đang kiểm tra kết nối internet và phân giải tên miền qua DNS…",
	"P7_KmsDnsResolved":  "Phân giải thành: ",
	"P7_KmsDnsPublic":    "Xác nhận đang hoạt động: tên miền phân giải thành địa chỉ IP công cộng.",
	"P7_KmsDnsPrivate":   "Phân giải thành IP nội bộ/riêng tư, bất thường với một tên miền KMS trên cloud.",
	"P7_KmsDnsNoResolve": "Không thể phân giải tên miền, dịch vụ có thể ngoại tuyến hoặc bị chặn DNS.",
	"P7_NoInternet":      "Không có kết nối internet, bỏ qua bước xác minh DNS.",

	// ── Tùy chọn 7, kết quả các bước ──────────────────────────────────────
	"P7_ServiceFound": "Phát hiện dịch vụ đáng ngờ:",
	"P7_NoServices":   "Không phát hiện dịch vụ đáng ngờ.",
	"P7_TaskFound":    "Phát hiện tác vụ định kỳ đáng ngờ:",
	"P7_NoTasks":      "Không phát hiện tác vụ đáng ngờ.",
	"P7_FileFound":    "Phát hiện đường dẫn công cụ kích hoạt:",
	"P7_NoFiles":      "Không phát hiện tập tin công cụ.",
	"P7_ProcFound":    "Phát hiện tiến trình đáng ngờ:",
	"P7_NoProcs":      "Không phát hiện tiến trình đáng ngờ.",

	// ── Tùy chọn 7, tổng kết ──────────────────────────────────────────────
	"P7_Clean":         "Không phát hiện dấu hiệu kích hoạt bên thứ ba, hệ thống có vẻ sạch.",
	"P7_Suspicious":    "Phát hiện một hoặc nhiều dấu hiệu đáng ngờ, xem kết quả ở trên.",
	"P7_Critical":      "NGHIÊM TRỌNG: Phát hiện kích hoạt KMS lậu (giả lập cục bộ hoặc dịch vụ cloud trái phép). Windows gần như chắc chắn đang dùng kích hoạt không hợp lệ.",
	"P7_TotalFlagged":  "Tổng số dấu hiệu bị gắn cờ: %d",
	"P7_SummaryHeader": "Kết quả",

	// ── Tùy chọn 7, thông báo pháp lý ─────────────────────────────────────
	"P7_LegalHeader":    "══ KIỂM TRA KÍCH HOẠT, THÔNG BÁO PHÁP LÝ ══",
	"P7_LegalLine1":     "Sử dụng Windows không có bản quyền chính hãng mua từ Microsoft hoặc",
	"P7_LegalLine2":     "đại lý được ủy quyền vi phạm Điều khoản dịch vụ của Microsoft (EULA §4).",
	"P7_LegalLine3":     "Người dùng doanh nghiệp / OEM: xác minh bản quyền với bộ phận IT hoặc OEM.",
	"P7_LegalLine4":     "Kiểm tra trạng thái bản quyền chính hãng: https://aka.ms/MyAccount",
	"P7_LegalScanLimit": "GIỚI HẠN QUÉT: HWID qua MAS tạo bản quyền MS thật (không phát hiện được). Công cụ bị gỡ sau khi dùng không để lại dấu vết. KMS doanh nghiệp có thể kích hoạt một số cảnh báo GVLK.",

	// ── Dashboard phán quyết: kết luận ─────────────────────────────────────
	"V_CleanTitle":        "KHÔNG PHÁT HIỆN KÍCH HOẠT LẬU",
	"V_CleanSummary":      "Không tìm thấy dấu hiệu của công cụ kích hoạt bên thứ ba trên máy này.",
	"V_SuspiciousTitle":   "⚠ NGHI VẤN KÍCH HOẠT LẬU",
	"V_SuspiciousSummary": "Phát hiện %d dấu hiệu kích hoạt lậu, KHÔNG nên xem là Windows bản quyền. Cần xử lý / thay bằng key chính hãng.",
	"V_CriticalTitle":     "PHÁT HIỆN KÍCH HOẠT LẬU",
	"V_CriticalSummary":   "Windows gần như chắc chắn đang được kích hoạt bằng phương thức không hợp lệ.",

	// ── Bảng tình trạng kiểm tra: tên mục ──────────────────────────────────
	"V_ChkTitle":      "BẢNG TÌNH TRẠNG KIỂM TRA",
	"V_ChkColName":    "Mục kiểm tra",
	"V_ChkColStatus":  "Kết quả",
	"V_ChkColDetail":  "Chi tiết",
	"V_ChkKms":        "Máy chủ KMS",
	"V_ChkPort":       "Cổng KMS trên máy",
	"V_ChkService":    "Dịch vụ hệ thống",
	"V_ChkTask":       "Tác vụ định kỳ",
	"V_ChkFile":       "Tập tin / thư mục công cụ",
	"V_ChkProc":       "Tiến trình đang chạy",
	"V_ChkSppHook":    "Hook vá dịch vụ SPP",
	"V_ChkGvlk":       "Khóa GVLK & kênh kích hoạt",
	"V_ChkInstallKey": "Key cài đặt chung",
	"V_ChkExpiry":     "Hạn kích hoạt",
	"V_ChkSppStore":   "Kho tin cậy SPP",
	"V_ChkSppEvent":   "Nhật ký sự kiện SPP",

	// ── Bảng tình trạng: nhãn trạng thái ───────────────────────────────────
	"V_StOK":       "Không thấy dấu hiệu",
	"V_StDetected": "PHÁT HIỆN CRACK",
	"V_StWarn":     "Đáng ngờ",
	"V_StSkipped":  "Không kiểm được",
	"V_StInfo":     "Thông tin",

	// ── Bảng tình trạng: chi tiết từng mục ─────────────────────────────────
	"V_ChkNoData":              "Không có dữ liệu để phân tích",
	"V_ChkNoLicense":           "Không đọc được bản quyền Windows",
	"V_ChkKmsNone":             "Không có máy chủ KMS nào được cấu hình",
	"V_ChkKmsLocal":            "Trỏ về chính máy này (%s), KMS giả lập",
	"V_ChkKmsBogus":            "IP giả 10.0.0.10 của MAS Online KMS",
	"V_ChkKmsPiracy":           "Tên miền lậu đã biết: %s",
	"V_ChkKmsCloud":            "KMS công cộng trên internet: %s",
	"V_ChkKmsAzure":            "Azure KMS của Microsoft: %s (chỉ hợp lệ trong Azure VM)",
	"V_ChkKmsCorp":             "Máy chủ nội bộ doanh nghiệp: %s",
	"V_ChkPortClosed":          "Đã thử %d cổng trên máy, tất cả đều đóng",
	"V_ChkPortOpen":            "Cổng %d đang mở, có KMS giả lập đang chạy",
	"V_ChkPortServer":          "Cổng %d mở trên Windows Server (có thể là KMS host chính hãng)",
	"V_ChkServiceNone":         "Đã đối chiếu %d từ khóa, không có dịch vụ nào khớp",
	"V_ChkServiceFound":        "Tìm thấy %d dịch vụ đáng ngờ",
	"V_ChkTaskNone":            "Đã đối chiếu %d từ khóa, không có tác vụ nào khớp",
	"V_ChkTaskFound":           "Tìm thấy %d tác vụ đáng ngờ",
	"V_ChkFileNone":            "Đã kiểm %d đường dẫn, không có dấu vết",
	"V_ChkFileFound":           "Tìm thấy %d đường dẫn công cụ kích hoạt",
	"V_ChkProcNone":            "Đã đối chiếu %d từ khóa, không có tiến trình nào khớp",
	"V_ChkProcFound":           "Tìm thấy %d tiến trình đáng ngờ",
	"V_ChkGvlkNone":            "Key đang dùng (%s) không phải GVLK/placeholder",
	"V_ChkGvlkPerm":            "GVLK %s + kích hoạt vĩnh viễn, mẫu của KMS38/TSforge/HWID",
	"V_ChkGvlkKms":             "GVLK %s nhưng còn đếm ngược gia hạn KMS (hợp lệ)",
	"V_ChkInstallKeyNo":        "Key đang dùng (%s) là key bản quyền thật, không phải key cài đặt chung",
	"V_ChkInstallKeyActivated": "Key %s KHÔNG có tác dụng bản quyền (chỉ để mồi cài đặt), CẦN THAY bằng key bản quyền thật",
	"V_ChkInstallKeyNotAct":    "Key %s KHÔNG có tác dụng bản quyền và máy CHƯA kích hoạt, CẦN THAY bằng key bản quyền thật",
	"V_ChkExpiryPerm":          "Kích hoạt vĩnh viễn, không có đếm ngược",
	"V_ChkExpiryNormal":        "Hết hạn %s, bình thường",
	"V_ChkExpiry180":           "Còn ~%d ngày, trùng chu kỳ gia hạn Online KMS",
	"V_ChkExpiryKms38":         "Hết hạn năm %d, kiểu KMS38",
	"V_ChkExpiryTsforge":       "Hết hạn năm %d, TSforge KMS4k",
	"V_ChkSppStoreOk":          "Dấu thời gian khớp ngữ cảnh Windows Update",
	"V_ChkSppStoreMod":         "Sửa ngày %s ngoài ngữ cảnh Windows Update (độ tin cậy thấp)",
	"V_ChkSppStoreMissing":     "Không tìm thấy tệp kho SPP",
	"V_ChkSppEventNone":        "Không có sự kiện kích hoạt SPP nào",
	"V_ChkSppEventClean":       "%d sự kiện SPP, không có máy chủ KMS bên ngoài",
	"V_ChkSppEventExt":         "Có yêu cầu KMS tới máy chủ bên ngoài",

	// ── Key cài đặt chung ──────────────────────────────────────────────────
	"P7_InstallOnlyKey":        "Key đang dùng (%s) là KEY CÀI ĐẶT CHUNG của %s, chỉ dùng để mồi cài đặt, bản thân nó không kích hoạt được. CẦN THAY bằng key bản quyền thật.",
	"V_IndInstallOnlyKey":      "Key cài đặt chung '%s' nhưng máy chưa kích hoạt, key này không thể kích hoạt bản quyền",
	"V_IndInstallOnlyLicensed": "Máy dùng key cài đặt chung '%s' nhưng vẫn 'đã kích hoạt', dấu vân tay của kích hoạt kiểu KMS/HWID; cần xác minh license có chính hãng không",
	"V_IndSppHook":             "Nhị phân dịch vụ bản quyền bị VÁ bằng hook IFEO: %s (dấu hiệu KMSpico/KMS_VL_ALL)",
	"V_ChkSppHookFound":        "Phát hiện hook IFEO trên dịch vụ SPP: %s",
	"V_ChkSppHookNone":         "Không có hook IFEO nào trên SppExtComObj/sppsvc/osppsvc",
	"P7_SppHookExplain":        "Kiểm tra Image File Execution Options: các bộ kích hoạt gắn VerifierDlls/Debugger vào nhị phân SPP để trả lời KMS ngay trong tiến trình của Microsoft.",
	"P7_SppHookFound":          "PHÁT HIỆN hook vá dịch vụ SPP: %s",
	"P7_SppHookNone":           "Không có hook vá nào trên nhị phân dịch vụ bản quyền (SPP).",

	// ── Khuyến nghị (callout nổi bật trên dashboard) ────────────────────────
	"V_RecTitle":               "CẦN THAY KEY BẢN QUYỀN",
	"V_RecInstallKeyActivated": "Key đang cài trên máy là %s, đây là KEY CÀI ĐẶT CHUNG (%s) được chia sẻ rộng rãi trên internet, chỉ dùng để mồi Windows cài đúng ấn bản. Bản thân key này KHÔNG có tác dụng bản quyền: nhập vào mục Activation sẽ báo lỗi. Máy hiện vẫn 'đã kích hoạt' là nhờ Digital Entitlement (bản quyền số gắn phần cứng) chứ không phải nhờ key này. Bạn nên THAY bằng key bản quyền thật mua từ Microsoft hoặc đại lý ủy quyền.",
	"V_RecInstallKeyNotAct":    "Key đang cài trên máy là %s, đây là KEY CÀI ĐẶT CHUNG (%s), KHÔNG có tác dụng bản quyền và máy hiện CHƯA được kích hoạt. Bạn cần THAY bằng key bản quyền thật mua từ Microsoft hoặc đại lý ủy quyền thì Windows mới kích hoạt được.",

	// ── Menu công cụ (tổ chức lại, bỏ nhóm chỉ đọc) ───────────────────────
	"V_ToolsHeader":     "Công cụ nâng cao",
	"V_ToolsChangeHead": "THAY ĐỔI KEY BẢN QUYỀN",
	"V_ToolInstallKey":  "Cài / thay key bản quyền mới",
	"V_ToolInstallDesc": "Nhập và cài một key bản quyền khác cho Windows",
	"V_ToolRemoveKey":   "Gỡ key bản quyền hiện tại",
	"V_ToolRemoveDesc":  "Xóa key đang cài, Windows sẽ về trạng thái chưa kích hoạt",
	"V_ToolsActHead":    "KÍCH HOẠT",
	"V_ToolRearm":       "Đặt lại bộ đếm kích hoạt (Rearm)",
	"V_ToolRearmDesc":   "Reset thời gian ân hạn kích hoạt, cần khởi động lại máy",
	"V_ToolsCleanHead":      "DỌN SẠCH CRACK",
	"V_ToolClean":           "Dọn sạch crack Windows (gỡ key + xóa công cụ)",
	"V_ToolCleanDesc":       "Gỡ key kích hoạt lậu, xóa hook/dịch vụ/tác vụ/tệp công cụ crack; Windows về CHƯA kích hoạt",
	"V_ToolCleanOffice":     "Gỡ sạch key Office lậu",
	"V_ToolCleanOfficeDesc": "Xóa máy chủ KMS và gỡ sạch key Office lậu (2010 - 2024, 365)",
	"V_ToolsScanHead":   "QUÉT DẤU HIỆU CRACK",
	"V_ToolRescan":      "Quét lại toàn bộ",
	"V_ToolScanSet":     "Cài đặt danh sách quét",
	"V_ToolScanSetDesc": "Thêm cổng / dịch vụ / tiến trình tùy chỉnh cho lần quét",
	"V_ToolsOptHead":    "TÙY CHỌN",
	"V_OptFullKey":      "Hiển thị đầy đủ key khi thao tác",
	"V_OptDlv":          "Kèm báo cáo mở rộng khi xem chi tiết",
	"V_OptAutoRemove":   "Tự xóa key dự phòng lệch (nếu có)",
	"V_OptRestart":      "Tự khởi động lại sau khi Rearm",

	// ── Khu vực key bản quyền của máy ──────────────────────────────────────
	"V_KeysTitle":          "KEY WINDOWS TRÊN MÁY",
	"V_KeyInstalled":       "Key đang cài",
	"V_KeyOem":             "Key OEM nhúng trong BIOS/UEFI",
	"V_KeyBackup":          "Key dự phòng trong Registry",
	"V_KeyNone":            "Không có",
	"V_KeyMaskedNote":      "Windows chỉ cho đọc 5 ký tự cuối của key đang kích hoạt",
	"V_KeyFullNote":        "Key đang cài được giải mã ĐẦY ĐỦ từ DigitalProductId trong Registry, 5 ký tự cuối khớp với license đang kích hoạt. Với Windows 8 trở lên, 20 ký tự đầu có thể do Windows tự sinh. Key dự phòng là bản sao Windows lưu lại, có thể khác key hiện tại.",
	"V_KeyInstallOnly":     "Key cài đặt chung, KHÔNG có tác dụng bản quyền",
	"V_KeyGenericNote":     "Key chung/placeholder, kích hoạt thật nằm ở Digital Entitlement",
	"V_KeyRealNote":        "Key bản quyền",
	"V_KeyBackupNote":      "Bản sao key Windows tự lưu trong Registry (SPP) từ lần cài/nhập key gần nhất",
	"V_KeyBackupDifferent": "Key CŨ/khác đang lưu lại trong Registry (5 ký tự cuối khác key đang kích hoạt), không phản ánh bản quyền hiện tại, chỉ là dấu vết còn sót",

	// ── Dashboard: trả lời "lậu KIỂU GÌ" ───────────────────────────────────
	"V_TypeLabel":    "Kiểu",
	"V_ActivatedBy":  "Kích hoạt bằng",
	"V_SystemInfo":   "THÔNG TIN HỆ THỐNG",
	"V_TabAudit":     "Kiểm định bản quyền",
	"V_TabSystem":    "Thông tin hệ thống",
	"V_TabHardware":  "Phần cứng",
	"V_TypeLocalKms": "KMS giả lập ngay trên máy (KMSpico / vlmcsd / KMSAuto / AAct)",
	"V_TypeCloudKms": "Dịch vụ KMS lậu trên internet",
	"V_TypeTsforge":  "TSforge (KMS4k), giả mạo hợp đồng KMS hàng nghìn năm",
	"V_TypeKms38":    "KMS38, kích hoạt kéo dài tới năm 2038",
	"V_TypeGvlkPerm": "Khóa GVLK kích hoạt vĩnh viễn, dấu hiệu KMS38 / TSforge / HWID",
	"V_TypePhone":    "Kênh điện thoại bất thường (TSforge ZeroCID)",
	"V_TypeOther":    "Công cụ kích hoạt bên thứ ba",
	"V_TypeSuspect":  "Nghi vấn key kích hoạt lậu, %d điểm cần xử lý",

	// ── Dashboard: nhãn thông tin cốt lõi ──────────────────────────────────
	"V_FactEdition":       "Ấn bản Windows",
	"V_FactChannel":       "Kênh phân phối",
	"V_FactStatus":        "Trạng thái kích hoạt",
	"V_FactMethod":        "Phương thức kích hoạt",
	"V_FactKey":           "Key đang dùng (5 ký tự cuối)",
	"V_FactStatusFlagged": "Windows báo đã kích hoạt, nhưng NGHI VẤN LẬU, không phải bản quyền hợp lệ",

	// ── Dashboard: thông tin phần cứng (kiểu CPU-Z) ────────────────────────
	"V_HwTitle":        "THÔNG TIN PHẦN CỨNG",
	"V_HwGroupCpu":     "Bộ xử lý (CPU)",
	"V_HwGroupBoard":   "Hệ thống & Bo mạch chủ",
	"V_HwGroupMem":     "Bộ nhớ (RAM)",
	"V_HwGroupGpu":     "Đồ họa (GPU)",
	"V_HwGroupDisk":    "Ổ đĩa",
	"V_HwCpuName":      "Tên CPU",
	"V_HwCpuCores":     "Nhân / Luồng",
	"V_HwCpuClock":     "Xung nhịp tối đa",
	"V_HwCoresThreads": "%d nhân · %d luồng",
	"V_HwSystem":       "Nhà sản xuất máy",
	"V_HwComputerName": "Tên máy tính",
	"V_HwBoard":        "Bo mạch chủ",
	"V_HwBios":         "BIOS/UEFI",
	"V_HwRamTotal":     "Tổng dung lượng",
	"V_HwRamSlot":      "Khe RAM",
	"V_HwRamAt":        " @ %d MHz",
	"V_HwGpuN":         "GPU %d",
	"V_HwVram":         " · %s VRAM",
	"V_HwDriver":       "driver %s",
	"V_HwDiskN":        "Ổ %d",

	// ── Dashboard: nhãn phương thức kích hoạt ──────────────────────────────
	"V_MethodDE":       "Digital Entitlement (bản quyền số gắn phần cứng)",
	"V_MethodKMS":      "KMS (bản quyền doanh nghiệp)",
	"V_MethodStandard": "MAK / Retail / OEM (kích hoạt tiêu chuẩn)",
	"V_MethodUnknown":  "Không xác định",

	// ── Dashboard: giao diện ───────────────────────────────────────────────
	"V_Scanning":        "Đang kiểm tra bản quyền Windows…",
	"V_Rescan":          "Quét lại",
	"V_ShowDetails":     "Xem chi tiết kỹ thuật",
	"V_HideDetails":     "Ẩn chi tiết kỹ thuật",
	"V_IndicatorsTitle": "Dấu hiệu phát hiện được",
	"V_NoIndicators":    "Không phát hiện dấu hiệu nào của công cụ kích hoạt bên thứ ba.",
	"V_AdvancedTools":   "Công cụ nâng cao",
	"V_Limits":          "Lưu ý: kích hoạt bằng HWID (MAS) tạo ra bản quyền số THẬT do Microsoft cấp nên không thể phát hiện; công cụ đã gỡ sạch cũng không để lại dấu vết.",

	// ── Dashboard: mô tả từng dấu hiệu ─────────────────────────────────────
	"V_IndKmsLocal":        "Máy chủ KMS trỏ về chính máy này (%s), có KMS giả lập đang chạy",
	"V_IndKmsBogus":        "Máy chủ KMS bị đặt thành IP giả 10.0.0.10, thủ thuật của MAS Online KMS",
	"V_IndKmsPiracyDomain": "Máy chủ KMS là tên miền lậu đã biết: %s",
	"V_IndKmsCloud":        "Máy chủ KMS là dịch vụ công cộng trên internet: %s (Microsoft không cung cấp KMS công cộng)",
	"V_IndPortOpen":        "Cổng KMS %d đang mở trên máy, có dịch vụ KMS giả lập đang chạy",
	"V_IndService":         "Dịch vụ của công cụ kích hoạt đang được cài: %s",
	"V_IndTask":            "Tác vụ tự kích hoạt lại định kỳ: %s",
	"V_IndFile":            "Dấu vết công cụ kích hoạt: %s (%s)",
	"V_IndProcess":         "Tiến trình công cụ kích hoạt đang chạy: %s (PID %d)",
	"V_IndPhone":           "Kênh kích hoạt qua điện thoại bất thường, dấu hiệu đặc trưng của TSforge ZeroCID",
	"V_IndGvlkPermanent":   "Khóa GVLK '%s' kích hoạt vĩnh viễn, mẫu của TSforge / KMS38 / HWID lậu",
	"V_IndOfficeKms":       "Máy chủ KMS của Office đáng ngờ: %s",
	"V_IndTsforge":         "Hạn kích hoạt năm %d, TSforge KMS4k (giả mạo hợp đồng KMS hàng nghìn năm)",
	"V_IndKms38":           "Hạn kích hoạt năm %d, kích hoạt kiểu KMS38",
	"V_IndOnline180":       "Hạn kích hoạt còn ~%d ngày, đúng chu kỳ gia hạn của Online KMS",
	"V_IndSppStore":        "Kho SPP bị sửa ngoài ngữ cảnh Windows Update (%s), độ tin cậy thấp",
	"V_IndSppEvent":        "Nhật ký SPP ghi nhận yêu cầu KMS tới máy chủ bên ngoài: %s",

	// ── Giới thiệu ─────────────────────────────────────────────────────────
	"About_Title":  "Giới thiệu, WinCheck",
	"About_Author": "Tác giả",
	"About_Repo":   "Kho mã nguồn",
	"About_Close":  "Đóng",
	"About_Desc":   "Công cụ quản lý bản quyền Windows với giao diện đồ họa, hỗ trợ xem Key Bản Quyền, trạng thái kích hoạt, Key OEM BIOS, và quản lý dịch vụ cấp phép Windows. Phát hành riêng cho thị trường Việt Nam.",
	"About_AuthorName": "Lê Thế Tuấn",
	"About_Phone":      "0352 194 195",
	"About_Email":      "lethetuanit.com@gmail.com",
	"About_Website":    "https://lethetuanpc.blogspot.com/",
}

// T trả về chuỗi tiếng Việt theo khóa. Nếu không tìm thấy, trả về chính khóa đó
// để lỗi dễ phát hiện thay vì trả về chuỗi rỗng.
func T(key string) string {
	if v, ok := M[key]; ok {
		return v
	}
	return key
}

// Tf trả về chuỗi theo khóa rồi định dạng với các tham số (fmt.Sprintf).
func Tf(key string, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}
