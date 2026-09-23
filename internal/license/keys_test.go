package license

import (
	"strings"
	"testing"
)

func TestNormalizeKey(t *testing.T) {
	if got := NormalizeKey("  vk7jg-nphtm  "); got != "VK7JG-NPHTM" {
		t.Errorf("NormalizeKey = %q", got)
	}
}

func TestValidKeyFormat(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"VK7JG-NPHTM-C97JM-9MPGT-3V66T", true},
		{"12345-ABCDE-67890-FGHIJ-KLMNO", true},
		{"VK7JG-NPHTM-C97JM-9MPGT-3V66", false},     // đoạn cuối 4 ký tự
		{"VK7JGNPHTMC97JM9MPGT3V66T", false},        // thiếu dấu gạch
		{"vk7jg-nphtm-c97jm-9mpgt-3v66t", false},    // chưa viết hoa
		{"VK7JG-NPHTM-C97JM-9MPGT-3V66T-XX", false}, // thừa nhóm
		{"", false},
	}
	for _, c := range cases {
		if got := ValidKeyFormat(c.key); got != c.want {
			t.Errorf("ValidKeyFormat(%q) = %v, muốn %v", c.key, got, c.want)
		}
	}
}

func TestMaskKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"VK7JG-NPHTM-C97JM-9MPGT-3V66T", "XXXXX-XXXXX-XXXXX-XXXXX-3V66T"},
		{"ABCDE", "XXXXX-XXXXX-XXXXX-XXXXX-ABCDE"},
		{"XYZ", "XXXXX-XXXXX-XXXXX-XXXXX-XYZ"},
	}
	for _, c := range cases {
		if got := MaskKey(c.in); got != c.want {
			t.Errorf("MaskKey(%q) = %q, muốn %q", c.in, got, c.want)
		}
	}
}

func TestLast5(t *testing.T) {
	if got := Last5("VK7JG-NPHTM-C97JM-9MPGT-3V66T"); got != "3V66T" {
		t.Errorf("Last5 = %q", got)
	}
	if got := Last5("3V66T"); got != "3V66T" {
		t.Errorf("Last5 bare = %q", got)
	}
}

func TestEditionFromGenericKey(t *testing.T) {
	if ed, ok := EditionFromGenericKey("VK7JG-NPHTM-C97JM-9MPGT-3V66T"); !ok || ed == "" {
		t.Errorf("mong đợi khớp ấn bản Pro, được ok=%v ed=%q", ok, ed)
	}
	if _, ok := EditionFromGenericKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"); ok {
		t.Errorf("không nên khớp key lạ")
	}
}

func TestIsGenericKeySuffix(t *testing.T) {
	if !IsGenericKeySuffix("3v66t") {
		t.Errorf("3V66T phải là hậu tố khóa chung (không phân biệt hoa thường)")
	}
	if IsGenericKeySuffix("ZZZZZ") {
		t.Errorf("ZZZZZ không phải khóa chung")
	}
}

func TestStatusText(t *testing.T) {
	for s := uint32(0); s <= 6; s++ {
		if txt := StatusText(s); txt == "" || strings.HasPrefix(txt, "LS_") {
			t.Errorf("StatusText(%d) phải trả về chuỗi tiếng Việt, được %q", s, txt)
		}
	}
	if StatusText(99) == "" {
		t.Errorf("StatusText mã lạ phải có mô tả")
	}
}

func TestDetectActivationMethod(t *testing.T) {
	cases := []struct {
		name     string
		desc     string
		partial  string
		reg      string
		kmsName  string
		kmsCount uint32
		want     ActivationMethod
	}{
		{"KMS volume có máy chủ", "VOLUME_KMSCLIENT channel", "T83GX", "", "kms.corp.local", 0, MethodKMS},
		{"KMS volume có đếm", "VOLUME channel", "T83GX", "", "", 25, MethodKMS},
		{"MAK volume không KMS", "VOLUME_MAK channel", "ABCDE", "", "", 0, MethodStandard},
		{"DE khóa chung", "RETAIL channel", "3V66T", "", "", 0, MethodDE},
		{"DE lệch key dự phòng", "RETAIL channel", "ABCDE", "VK7JG-NPHTM-C97JM-9MPGT-ZZZZZ", "", 0, MethodDE},
		{"Standard retail khớp", "RETAIL channel", "ABCDE", "VK7JG-NPHTM-C97JM-9MPGT-ABCDE", "", 0, MethodStandard},
		{"Standard không có reg", "OEM channel", "ABCDE", "", "", 0, MethodStandard},
	}
	for _, c := range cases {
		if got := DetectActivationMethod(c.desc, c.partial, c.reg, c.kmsName, c.kmsCount); got != c.want {
			t.Errorf("%s: DetectActivationMethod = %v, muốn %v", c.name, got, c.want)
		}
	}
}
