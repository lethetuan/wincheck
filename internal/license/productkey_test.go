package license

import "testing"

// realDigitalProductId là khối DigitalProductId THẬT lấy từ máy kiểm thử (Windows
// 10 Pro). Giải mã kỳ vọng: C8NKQ-QCJWK-YPTDH-KC2FQ-Y4G6T — 5 ký tự cuối "Y4G6T"
// khớp PartialProductKey mà WMI báo cáo, xác nhận thuật toán đúng đầu-cuối.
var realDigitalProductId = []byte{
	164, 0, 0, 0, 3, 0, 0, 0, 48, 48, 51, 51, 48, 45, 56, 48,
	49, 50, 48, 45, 52, 53, 54, 57, 48, 45, 65, 65, 57, 49, 51, 0,
	236, 12, 0, 0, 91, 84, 72, 93, 88, 49, 57, 45, 57, 56, 56, 52,
	51, 0, 0, 0, 236, 12, 160, 215, 124, 11, 244, 174, 205, 168, 12, 171,
	205, 136, 8, 0, 0, 0, 0, 0, 19, 79, 49, 106, 137, 248, 74, 114,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	207, 222, 65, 210,
}

func TestDecodeDigitalProductIDReal(t *testing.T) {
	const want = "C8NKQ-QCJWK-YPTDH-KC2FQ-Y4G6T"
	got := DecodeDigitalProductID(realDigitalProductId)
	if got != want {
		t.Fatalf("DecodeDigitalProductID = %q, muốn %q", got, want)
	}
	// 5 ký tự cuối phải khớp PartialProductKey của license đang kích hoạt.
	if Last5(got) != "Y4G6T" {
		t.Errorf("Last5(giải mã) = %q, muốn Y4G6T", Last5(got))
	}
	// Kết quả phải là khóa 25 ký tự đúng định dạng.
	if !ValidKeyFormat(got) {
		t.Errorf("khóa giải mã %q không đúng định dạng 5x5", got)
	}
}

func TestDecodeDigitalProductIDInvalid(t *testing.T) {
	cases := map[string][]byte{
		"nil":    nil,
		"rỗng":   {},
		"ngắn":   make([]byte, 50), // < 67 byte
		"66byte": make([]byte, 66),
	}
	for name, in := range cases {
		if got := DecodeDigitalProductID(in); got != "" {
			t.Errorf("%s: khối không hợp lệ phải trả \"\", được %q", name, got)
		}
	}
}
