package audit

import (
	"testing"
	"time"

	"github.com/vinhwincheck/wincheck/internal/config"
)

func TestClassifyKmsHost(t *testing.T) {
	dom := config.DefaultKmsPiracyDomains
	cases := []struct {
		host string
		want KmsClass
	}{
		{"127.0.0.1", KmsLocal},
		{"localhost", KmsLocal},
		{"::1", KmsLocal},
		{"0.0.0.0", KmsLocal},
		{"10.0.0.10", KmsBogusPlaceholder},
		{"km8.msguides.com", KmsKnownPiracy},
		{"kms.loli.beer", KmsKnownPiracy},
		{"azkms.core.windows.net", KmsMsOfficial},
		{"kms.microsoft.com", KmsMsOfficial},
		{"10.20.30.40", KmsCorporate},
		{"192.168.1.50", KmsCorporate},
		{"172.16.0.1", KmsCorporate},
		{"kms.corp.local", KmsCorporate},
		{"kmshost", KmsCorporate}, // không có dấu chấm = nội bộ
		{"kms.somerandomhost.com", KmsCloudPiracy},
		{"203.0.113.9", KmsCloudPiracy},
	}
	for _, c := range cases {
		if got := ClassifyKmsHost(c.host, dom); got != c.want {
			t.Errorf("ClassifyKmsHost(%q) = %v, muốn %v", c.host, got, c.want)
		}
	}
}

func TestIsOfficeKmsSuspicious(t *testing.T) {
	dom := config.DefaultKmsPiracyDomains
	if !IsOfficeKmsSuspicious("kms.somepublic.com", dom) {
		t.Errorf("host công cộng phải bị coi là đáng ngờ")
	}
	if !IsOfficeKmsSuspicious("km8.msguides.com", dom) {
		t.Errorf("tên miền lậu phải bị coi là đáng ngờ")
	}
	if IsOfficeKmsSuspicious("192.168.1.10", dom) {
		t.Errorf("host nội bộ không nên bị coi là đáng ngờ")
	}
	if IsOfficeKmsSuspicious("localhost", dom) {
		t.Errorf("localhost không nên bị coi là đáng ngờ")
	}
}

func TestAnalyzeExpiry(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	if r := AnalyzeExpiry(0, true, now); r.Class != ExpiryPermanent {
		t.Errorf("grace=0 licensed phải là Permanent, được %v", r.Class)
	}
	if r := AnalyzeExpiry(0, false, now); r.Class != ExpiryNone {
		t.Errorf("grace=0 chưa cấp phép phải là None, được %v", r.Class)
	}

	// KMS38 (~2038)
	minsTo2038 := uint32(time.Date(2038, 3, 1, 0, 0, 0, 0, time.UTC).Sub(now).Minutes())
	if r := AnalyzeExpiry(minsTo2038, false, now); r.Class != ExpiryKms38 {
		t.Errorf("hết hạn 2038 phải là KMS38, được %v (năm %d)", r.Class, r.Year)
	}

	// TSforge (>=2100)
	minsTo2200 := uint32(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC).Sub(now).Minutes())
	if r := AnalyzeExpiry(minsTo2200, false, now); r.Class != ExpiryTsforge {
		t.Errorf("hết hạn 2200 phải là TSforge, được %v", r.Class)
	}

	// Online KMS 180 ngày
	mins180 := uint32(180 * 24 * 60)
	if r := AnalyzeExpiry(mins180, false, now); r.Class != ExpiryOnline180 {
		t.Errorf("hết hạn ~180 ngày phải là Online180, được %v (còn %.0f ngày)", r.Class, r.DaysLeft)
	}

	// Bình thường (30 ngày)
	mins30 := uint32(30 * 24 * 60)
	if r := AnalyzeExpiry(mins30, false, now); r.Class != ExpiryNormal {
		t.Errorf("hết hạn 30 ngày phải là Normal, được %v", r.Class)
	}
}

func TestIsPrivateOrLoopbackIP(t *testing.T) {
	priv := []string{"10.1.2.3", "192.168.0.1", "172.16.5.5", "172.31.9.9", "127.0.0.1", "::1", "0.0.0.0", "localhost"}
	for _, ip := range priv {
		if !IsPrivateOrLoopbackIP(ip) {
			t.Errorf("%q phải là IP nội bộ/loopback", ip)
		}
	}
	pub := []string{"8.8.8.8", "203.0.113.1", "172.15.0.1", "172.32.0.1"}
	for _, ip := range pub {
		if IsPrivateOrLoopbackIP(ip) {
			t.Errorf("%q phải là IP công cộng", ip)
		}
	}
}

func TestHasPublicResolution(t *testing.T) {
	if !HasPublicResolution([]string{"192.168.1.1", "203.0.113.9"}) {
		t.Errorf("có IP công cộng trong danh sách")
	}
	if HasPublicResolution([]string{"10.0.0.1", "127.0.0.1", "::1"}) {
		t.Errorf("toàn IP nội bộ, không nên báo công cộng")
	}
}
