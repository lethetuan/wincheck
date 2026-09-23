package i18n

import (
	"strings"
	"testing"
)

func TestTKnownKey(t *testing.T) {
	if T("AppTitle") == "AppTitle" {
		t.Errorf("AppTitle phải có bản dịch")
	}
}

func TestTUnknownKeyReturnsKey(t *testing.T) {
	if T("__khong_ton_tai__") != "__khong_ton_tai__" {
		t.Errorf("khóa lạ phải trả về chính khóa để dễ phát hiện")
	}
}

func TestTf(t *testing.T) {
	got := Tf("P7_PortOpen", 1688)
	if !strings.Contains(got, "1688") {
		t.Errorf("Tf phải chèn tham số, được %q", got)
	}
}

// TestNoEmptyValues bảo đảm không có mục nào trong bảng bị rỗng.
func TestNoEmptyValues(t *testing.T) {
	for k, v := range M {
		if strings.TrimSpace(v) == "" {
			t.Errorf("khóa %q có giá trị rỗng", k)
		}
	}
}

// TestCriticalKeysExist kiểm tra các khóa quan trọng mà tầng điều phối dùng.
func TestCriticalKeysExist(t *testing.T) {
	keys := []string{
		"Act1", "Act2", "Act3", "Act4", "Act5", "Act6", "Act7",
		"P7_Clean", "P7_Critical", "P7_Suspicious", "P7_KmsLocal",
		"P7_GvlkPermanent", "P7_PortOpen", "O4_BadFormat", "O5_Done",
		"LS_1", "DE_Confirmed", "KMS_Detected", "MAK_Detected",
	}
	for _, k := range keys {
		if _, ok := M[k]; !ok {
			t.Errorf("thiếu khóa quan trọng %q", k)
		}
	}
}
