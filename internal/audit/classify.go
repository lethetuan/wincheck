// Package audit chứa logic của Tùy chọn 7 — Kiểm Tra Kích Hoạt Bên Thứ Ba.
//
// classify.go là phần thuần: phân loại máy chủ KMS, phân tích ngày hết hạn kích
// hoạt, và các phép kiểm tra IP nội bộ/công cộng. audit.go điều phối 10 lớp quét
// dựa trên các hàm này và một sysinfo.Provider.
package audit

import (
	"net"
	"regexp"
	"strings"
	"time"
)

// KmsClass phân loại một máy chủ KMS đã cấu hình.
type KmsClass int

const (
	// KmsLocal: trỏ về localhost/127.x — KMS giả lập cục bộ (nghiêm trọng).
	KmsLocal KmsClass = iota
	// KmsBogusPlaceholder: 10.0.0.10 — IP giả của MAS Online KMS (nghiêm trọng).
	KmsBogusPlaceholder
	// KmsKnownPiracy: khớp tên miền KMS lậu đã biết (nghiêm trọng).
	KmsKnownPiracy
	// KmsMsOfficial: điểm cuối Azure KMS của Microsoft (hợp lệ trong Azure VM).
	KmsMsOfficial
	// KmsCorporate: IP/hostname nội bộ — triển khai doanh nghiệp hợp lệ.
	KmsCorporate
	// KmsCloudPiracy: host công cộng, tên miền lạ — dịch vụ KMS lậu trên cloud.
	KmsCloudPiracy
)

var reKmsPrivateIP = regexp.MustCompile(`^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.`)

// ClassifyKmsHost phân loại máy chủ KMS theo đúng thứ tự ưu tiên:
// local → IP giả → tên miền lậu đã biết → Azure chính hãng → nội bộ → cloud lậu.
func ClassifyKmsHost(host string, piracyDomains []string) KmsClass {
	h := strings.TrimSpace(host)
	lower := strings.ToLower(h)

	isLocal := lower == "localhost" ||
		strings.HasPrefix(h, "127.") ||
		strings.HasPrefix(h, "::1") ||
		h == "0.0.0.0"
	if isLocal {
		return KmsLocal
	}
	if h == "10.0.0.10" {
		return KmsBogusPlaceholder
	}

	for _, d := range piracyDomains {
		if d != "" && strings.Contains(lower, strings.ToLower(d)) {
			return KmsKnownPiracy
		}
	}

	if strings.HasSuffix(lower, ".microsoft.com") || strings.HasSuffix(lower, ".windows.net") {
		return KmsMsOfficial
	}

	isPrivateIP := reKmsPrivateIP.MatchString(h)
	isPrivateHost := !isPrivateIP &&
		net.ParseIP(h) == nil &&
		(strings.HasSuffix(lower, ".local") ||
			strings.HasSuffix(lower, ".internal") ||
			strings.HasSuffix(lower, ".corp") ||
			strings.HasSuffix(lower, ".lan") ||
			strings.HasSuffix(lower, ".intranet") ||
			!strings.Contains(h, "."))
	if isPrivateIP || isPrivateHost {
		return KmsCorporate
	}

	return KmsCloudPiracy
}

// IsOfficeKmsSuspicious cho biết máy chủ KMS Office có đáng ngờ hay không: hoặc
// khớp tên miền lậu, hoặc là host bên ngoài (không nội bộ, không localhost).
func IsOfficeKmsSuspicious(host string, piracyDomains []string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	for _, d := range piracyDomains {
		if d != "" && strings.Contains(lower, strings.ToLower(d)) {
			return true
		}
	}
	external := !reKmsPrivateIP.MatchString(host) &&
		!strings.HasPrefix(host, "127.") &&
		lower != "localhost"
	return external
}

// ExpiryClass phân loại ngày hết hạn kích hoạt.
type ExpiryClass int

const (
	ExpiryNone      ExpiryClass = iota // không có dữ liệu để phân tích
	ExpiryPermanent                    // kích hoạt vĩnh viễn (không đếm ngược)
	ExpiryTsforge                      // năm ≥ 2100 — TSforge KMS4k
	ExpiryKms38                        // năm ≥ 2037 — KMS38
	ExpiryOnline180                    // còn ~165–195 ngày — Online KMS
	ExpiryNormal                       // bình thường
)

// ExpiryResult là kết quả phân tích ngày hết hạn.
type ExpiryResult struct {
	Class    ExpiryClass
	Expiry   time.Time
	Year     int
	DaysLeft float64
}

// AnalyzeExpiry phân tích thời gian ân hạn còn lại (phút) để phát hiện các mẫu
// kích hoạt lậu đặc trưng theo ngày hết hạn.
func AnalyzeExpiry(graceMins uint32, isLicensed bool, now time.Time) ExpiryResult {
	if graceMins == 0 && isLicensed {
		return ExpiryResult{Class: ExpiryPermanent}
	}
	if graceMins == 0 {
		return ExpiryResult{Class: ExpiryNone}
	}
	expiry := now.Add(time.Duration(graceMins) * time.Minute)
	year := expiry.Year()
	res := ExpiryResult{Expiry: expiry, Year: year}
	switch {
	case year >= 2100:
		res.Class = ExpiryTsforge
	case year >= 2037:
		res.Class = ExpiryKms38
	default:
		daysLeft := expiry.Sub(now).Hours() / 24
		res.DaysLeft = daysLeft
		if daysLeft >= 165 && daysLeft <= 195 {
			res.Class = ExpiryOnline180
		} else {
			res.Class = ExpiryNormal
		}
	}
	return res
}

var reEventPrivate172 = regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])\.`)

// IsPrivateOrLoopbackIP dùng khi phân tích địa chỉ máy chủ trong nhật ký sự kiện
// SPP: coi các dải RFC 1918, loopback, localhost và 0.0.0.0 là nội bộ.
func IsPrivateOrLoopbackIP(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	return strings.HasPrefix(a, "10.") ||
		strings.HasPrefix(a, "192.168.") ||
		reEventPrivate172.MatchString(a) ||
		a == "127.0.0.1" ||
		a == "::1" ||
		a == "localhost" ||
		a == "0.0.0.0"
}

var reDNSPrivate = regexp.MustCompile(`^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)`)

// HasPublicResolution cho biết trong danh sách IP có địa chỉ định tuyến công cộng
// (không thuộc dải riêng tư/loopback) hay không — dùng khi phân giải DNS host KMS.
func HasPublicResolution(ips []string) bool {
	for _, ip := range ips {
		if !reDNSPrivate.MatchString(strings.TrimSpace(ip)) {
			return true
		}
	}
	return false
}
