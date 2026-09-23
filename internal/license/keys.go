// Package license chứa logic thuần liên quan tới key bản quyền Windows: che key,
// kiểm tra định dạng, nhận diện ấn bản từ khóa chung, ánh xạ trạng thái cấp phép,
// và suy luận phương thức kích hoạt. Không phụ thuộc Windows nên kiểm thử được
// hoàn toàn.
package license

import (
	"regexp"
	"strings"

	"github.com/vinhwincheck/wincheck/internal/i18n"
)

// keyFormat khớp key 25 ký tự dạng XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
var keyFormat = regexp.MustCompile(`^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$`)

// GenericKeys ánh xạ 5 ký tự cuối của các khóa chung/placeholder tới tên ấn bản.
// Đây là bảng dùng trong GUI gốc để nhận diện ấn bản và suy luận Digital
// Entitlement (khác với danh sách hậu tố GVLK đầy đủ ở gói config).
var GenericKeys = map[string]string{
	"3V66T": "Windows 10/11 Pro  (VK7JG-NPHTM-C97JM-9MPGT-3V66T)",
	"3TTL4": "Windows 10/11 Home  (YTMG3-N6KGA-8B33D-XXYF2-3TTL4)",
	"WXCHW": "Windows 10/11 Home Single Language  (4CPRK-NM3K3-X6XXQ-RXX86-WXCHW)",
	"PR4Y7": "Windows Pro Education  (8PTT6-RNW4C-X6V77-D23ST-PR4Y7)",
	"2YV77": "Windows Pro Workstations  (DXG7C-N36C4-C4HTG-X4T3X-2YV77)",
	"8DEC2": "Windows Enterprise  (XGVPP-NMH47-7TTHJ-W3FW7-8DEC2)",
	"28UTV": "Windows Enterprise  (NPPR9-FWDCX-D2C8J-H8P65-28UTV)",
	"7CFBY": "Windows Education  (YNMGQ-8RYV3-4PGQ3-C8XTP-7CFBY)",
	// Key cài đặt chung (Generic/Install key) của Windows 11/10 Pro, được chia sẻ
	// rộng rãi trên internet. Chỉ dùng để MỒI CÀI ĐẶT (giúp Setup nhận đúng ấn bản);
	// bản thân nó KHÔNG kích hoạt được — nhập vào Activation sẽ báo lỗi.
	"Y4G6T": "Windows 11/10 Pro — Key cài đặt chung (WGV3M-N8DXW-4HB4P-V6263-Y4G6T / WBQN7-4C2JG-MW3TT-7QFM3-Y4G6T)",
}

// InstallOnlyKeys là các key CÀI ĐẶT CHUNG: chỉ để mồi Setup nhận đúng ấn bản,
// không có khả năng kích hoạt. Nếu máy đang "đã kích hoạt" mà key cài là một
// trong số này thì kích hoạt thật đến từ nơi khác (Digital Entitlement / KMS…).
var InstallOnlyKeys = map[string]string{
	"Y4G6T": "Windows 11/10 Pro",
}

// IsInstallOnlyKey cho biết 5 ký tự cuối có phải key cài đặt chung (không kích
// hoạt được) hay không.
func IsInstallOnlyKey(last5 string) bool {
	_, ok := InstallOnlyKeys[strings.ToUpper(last5)]
	return ok
}

// NormalizeKey chuẩn hóa key người dùng nhập: cắt khoảng trắng và viết hoa.
func NormalizeKey(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

// ValidKeyFormat kiểm tra key có đúng định dạng 25 ký tự hay không. Key phải đã
// được chuẩn hóa (viết hoa) trước khi gọi.
func ValidKeyFormat(key string) bool {
	return keyFormat.MatchString(key)
}

// MaskKey che key, chỉ để lộ 5 ký tự cuối: XXXXX-XXXXX-XXXXX-XXXXX-<đuôi>.
func MaskKey(key string) string {
	parts := strings.Split(key, "-")
	if len(parts) == 5 {
		return "XXXXX-XXXXX-XXXXX-XXXXX-" + parts[4]
	}
	if len(key) >= 5 {
		return "XXXXX-XXXXX-XXXXX-XXXXX-" + key[len(key)-5:]
	}
	return "XXXXX-XXXXX-XXXXX-XXXXX-" + key
}

// Last5 trả về 5 ký tự cuối (phần cuối sau dấu '-') của một key.
func Last5(key string) string {
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

// EditionFromGenericKey trả về tên ấn bản nếu 5 ký tự cuối của key khớp bảng
// GenericKeys. Đây là phần thuần của việc nhận diện ấn bản; phần dự phòng qua
// WMI được xử lý ở tầng điều phối.
func EditionFromGenericKey(fullKey string) (string, bool) {
	last5 := Last5(fullKey)
	name, ok := GenericKeys[last5]
	return name, ok
}

// IsGenericKeySuffix cho biết 5 ký tự có nằm trong bảng GenericKeys hay không.
func IsGenericKeySuffix(last5 string) bool {
	_, ok := GenericKeys[strings.ToUpper(last5)]
	return ok
}

// StatusText ánh xạ mã LicenseStatus của WMI sang mô tả tiếng Việt.
func StatusText(status uint32) string {
	switch status {
	case 0:
		return i18n.T("LS_0")
	case 1:
		return i18n.T("LS_1")
	case 2:
		return i18n.T("LS_2")
	case 3:
		return i18n.T("LS_3")
	case 4:
		return i18n.T("LS_4")
	case 5:
		return i18n.T("LS_5")
	case 6:
		return i18n.T("LS_6")
	default:
		return i18n.T("LS_Unknown")
	}
}

// ActivationMethod là phương thức kích hoạt suy luận được của Windows.
type ActivationMethod int

const (
	MethodUnknown  ActivationMethod = iota
	MethodDE                        // Digital Entitlement (gắn phần cứng)
	MethodKMS                       // KMS (bản quyền doanh nghiệp)
	MethodStandard                  // MAK / Retail / OEM
)

// DetectActivationMethod suy luận phương thức kích hoạt theo chiến lược "kênh
// trước": chỉ kênh VOLUME mới có thể là KMS; kênh khác không thể là KMS, khi đó
// khóa chung hoặc lệch key dự phòng là dấu hiệu Digital Entitlement.
//
//   - description: trường Description của WMI SoftwareLicensingProduct.
//   - partialKey:  PartialProductKey (5 ký tự cuối) của bản quyền đang hoạt động.
//   - regKey:      Key dự phòng đọc từ Registry (BackupProductKeyDefault).
//   - kmsName:     DiscoveredKeyManagementServiceMachineName.
//   - kmsCount:    KeyManagementServiceCurrentCount.
func DetectActivationMethod(description, partialKey, regKey, kmsName string, kmsCount uint32) ActivationMethod {
	desc := strings.ToUpper(description)

	// Chỉ kênh VOLUME: có thể là KMS hoặc MAK.
	if strings.Contains(desc, "VOLUME") {
		if kmsName != "" || kmsCount > 0 {
			return MethodKMS
		}
		return MethodStandard
	}

	// Kênh không phải VOLUME (RETAIL, OEM…): không thể là KMS.
	if partialKey != "" && IsGenericKeySuffix(partialKey) {
		return MethodDE // khóa chung = chắc chắn DE
	}

	// Key RETAIL thật (không phải khóa chung): đuôi key dự phòng khác đuôi key
	// đang dùng → Microsoft đã cấp key mới trên cloud = DE.
	if regKey != "" && partialKey != "" && !strings.EqualFold(suffixOf(regKey), partialKey) {
		return MethodDE
	}

	return MethodStandard
}

// suffixOf trả về 5 ký tự cuối của một chuỗi key (an toàn với chuỗi ngắn).
func suffixOf(key string) string {
	if len(key) >= 5 {
		return key[len(key)-5:]
	}
	return key
}
