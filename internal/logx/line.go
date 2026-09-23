// Package logx định nghĩa mô hình dòng nhật ký (log line) độc lập với giao diện.
//
// Toàn bộ logic nghiệp vụ (kiểm tra bản quyền, quét bên thứ ba…) chỉ phát ra các
// đối tượng Line mang ý nghĩa ngữ nghĩa (Kind) chứ không tự tô màu. Tầng giao diện
// (GUI Walk) mới ánh xạ Kind sang màu sắc và biểu tượng để hiển thị. Nhờ vậy phần
// logic có thể kiểm thử hoàn toàn mà không cần GUI hay Windows.
package logx

// Kind phân loại ngữ nghĩa của một dòng nhật ký.
type Kind int

const (
	KindSep    Kind = iota // đường phân cách "────"
	KindSep2               // đường phân cách đậm "===="
	KindBlank              // dòng trống
	KindAction             // tiêu đề hành động (ví dụ "Tùy chọn 1 …")
	KindCmd                // lệnh được chạy (ví dụ "$ cscript …")
	KindFetch              // đang truy vấn/đọc dữ liệu ("… đang lấy …")
	KindInfo               // thông tin trung tính
	KindOk                 // kết quả tốt / an toàn
	KindWarn               // cảnh báo
	KindError              // lỗi / dấu hiệu nghiêm trọng
	KindKey                // hiển thị khóa bản quyền
	KindDiag               // dòng chẩn đoán/giải thích (thụt lề)
	KindHelp               // liên kết tài liệu tham khảo
	KindDE                 // thông báo Digital Entitlement
	KindData               // cặp nhãn : giá trị
)

// Line là một dòng nhật ký. Với KindData, Label và Value được dùng để canh cột;
// với các Kind còn lại chỉ Text được dùng.
type Line struct {
	Kind  Kind
	Text  string
	Label string
	Value string
}

// Emitter thu thập các Line do logic nghiệp vụ phát ra.
//
// Trong GUI, một Emitter chuyển tiếp mỗi Line tới khung nhật ký. Trong kiểm thử,
// một Emitter lưu lại toàn bộ Line để khẳng định kết quả.
type Emitter struct {
	lines       []Line
	sink        func(Line)
	firstAction bool
}

// New tạo Emitter lưu các Line vào bộ nhớ (dùng cho kiểm thử).
func New() *Emitter { return &Emitter{firstAction: true} }

// NewWithSink tạo Emitter chuyển tiếp mỗi Line tới sink đồng thời vẫn lưu lại.
// Truyền nil để chỉ lưu vào bộ nhớ.
func NewWithSink(sink func(Line)) *Emitter { return &Emitter{sink: sink, firstAction: true} }

// Lines trả về toàn bộ Line đã phát ra theo thứ tự.
func (e *Emitter) Lines() []Line { return e.lines }

// Len trả về số Line đã phát.
func (e *Emitter) Len() int { return len(e.lines) }

func (e *Emitter) emit(l Line) {
	e.lines = append(e.lines, l)
	if e.sink != nil {
		e.sink(l)
	}
}

// Count đếm số Line có Kind cho trước.
func (e *Emitter) Count(k Kind) int {
	n := 0
	for _, l := range e.lines {
		if l.Kind == k {
			n++
		}
	}
	return n
}

// --- Các hàm tiện ích phát Line ------------------------------------------------

func (e *Emitter) Sep()   { e.emit(Line{Kind: KindSep}) }
func (e *Emitter) Sep2()  { e.emit(Line{Kind: KindSep2}) }
func (e *Emitter) Blank() { e.emit(Line{Kind: KindBlank}) }

// Action phát tiêu đề một hành động, đóng khung bằng đường phân cách (và một dòng
// trống phía trên nếu không phải hành động đầu tiên) — giống hành vi LogAction quen thuộc.
func (e *Emitter) Action(s string) {
	if !e.firstAction {
		e.emit(Line{Kind: KindBlank})
	}
	e.firstAction = false
	e.emit(Line{Kind: KindSep})
	e.emit(Line{Kind: KindAction, Text: s})
	e.emit(Line{Kind: KindSep})
}

// ResetFirstAction đặt lại trạng thái "hành động đầu tiên" (dùng khi xóa nhật ký).
func (e *Emitter) ResetFirstAction() { e.firstAction = true }

// SetFirstAction đặt trạng thái "hành động đầu tiên". Khi false, Action tiếp theo
// sẽ chèn một dòng trống phía trên để ngăn cách với nội dung nhật ký đã có.
func (e *Emitter) SetFirstAction(v bool) { e.firstAction = v }
func (e *Emitter) Cmd(s string)          { e.emit(Line{Kind: KindCmd, Text: s}) }
func (e *Emitter) Fetch(s string)        { e.emit(Line{Kind: KindFetch, Text: s}) }
func (e *Emitter) Info(s string)         { e.emit(Line{Kind: KindInfo, Text: s}) }
func (e *Emitter) Ok(s string)           { e.emit(Line{Kind: KindOk, Text: s}) }
func (e *Emitter) Warn(s string)         { e.emit(Line{Kind: KindWarn, Text: s}) }
func (e *Emitter) Error(s string)        { e.emit(Line{Kind: KindError, Text: s}) }
func (e *Emitter) Key(s string)          { e.emit(Line{Kind: KindKey, Text: s}) }
func (e *Emitter) Diag(s string)         { e.emit(Line{Kind: KindDiag, Text: s}) }
func (e *Emitter) Help(s string)         { e.emit(Line{Kind: KindHelp, Text: s}) }
func (e *Emitter) DE(s string)           { e.emit(Line{Kind: KindDE, Text: s}) }

// Data phát một dòng cặp nhãn : giá trị.
func (e *Emitter) Data(label, value string) {
	e.emit(Line{Kind: KindData, Label: label, Value: value})
}

// Text phát một dòng với Kind tùy ý (dùng khi cần Kind không có hàm tiện ích riêng,
// ví dụ tiêu đề in đậm mang màu KindAction/KindWarn).
func (e *Emitter) Text(kind Kind, s string) {
	e.emit(Line{Kind: kind, Text: s})
}
