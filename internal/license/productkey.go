package license

// DecodeDigitalProductID giải mã khối nhị phân DigitalProductId (đọc từ Registry
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId) thành khóa
// sản phẩm Windows 25 ký tự dạng XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
//
// Đây là cùng thuật toán mà ShowKeyPlus/ProduKey dùng: 15 byte khóa (offset
// 52..66) được giải mã cơ số 24. Với Windows 8 trở lên, một bit cờ cho biết khóa
// có chứa ký tự 'N' và cần chèn lại vào đúng vị trí.
//
// Lưu ý: với Windows 8+, 5 ký tự cuối luôn khớp PartialProductKey của license đang
// kích hoạt (nên gọi Last5 để đối chiếu), còn 20 ký tự đầu có thể là giá trị Windows
// tự sinh chứ không phải khóa gốc đã nhập. Trả về "" nếu khối không hợp lệ.
func DecodeDigitalProductID(id []byte) string {
	// Cần đủ byte để lấy 15 byte khóa tại offset 52..66.
	if len(id) < 67 {
		return ""
	}

	const digits = "BCDFGHJKMPQRTVWXY2346789" // 24 ký tự, bỏ các ký tự dễ nhầm
	const base = 24
	const keyLen = 15
	const outLen = 25

	// Sao chép 15 byte khóa để không sửa đầu vào.
	key := make([]byte, keyLen)
	copy(key, id[52:52+keyLen])

	// Cờ Windows 8+: bit 3 của byte cuối cho biết khóa có ký tự 'N'.
	isWin8 := (int(key[keyLen-1]) >> 3) & 1
	key[keyLen-1] = byte((int(key[keyLen-1]) & 0xF7) | ((isWin8 & 2) << 2))

	out := make([]byte, outLen)
	last := 0
	for i := outLen - 1; i >= 0; i-- {
		cur := 0
		for j := keyLen - 1; j >= 0; j-- {
			cur = cur*256 + int(key[j])
			key[j] = byte(cur / base)
			cur = cur % base
		}
		out[i] = digits[cur]
		last = cur
	}

	s := string(out)
	if isWin8 == 1 {
		// Bỏ ký tự đầu (thừa) rồi chèn 'N' vào vị trí đã tính.
		s = s[1:]
		if last > len(s) {
			last = len(s)
		}
		s = s[:last] + "N" + s[last:]
	}

	// Chèn dấu gạch mỗi 5 ký tự: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
	if len(s) != 25 {
		return ""
	}
	return s[0:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20] + "-" + s[20:25]
}
