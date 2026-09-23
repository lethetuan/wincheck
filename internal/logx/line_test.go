package logx

import "testing"

func TestEmitterBasic(t *testing.T) {
	e := New()
	e.Info("xin chào")
	e.Ok("tốt")
	e.Warn("cẩn thận")
	e.Error("hỏng")
	if e.Len() != 4 {
		t.Errorf("Len = %d, muốn 4", e.Len())
	}
	if e.Count(KindOk) != 1 || e.Count(KindError) != 1 {
		t.Errorf("đếm Kind sai")
	}
	if e.Lines()[0].Text != "xin chào" {
		t.Errorf("nội dung dòng đầu sai: %q", e.Lines()[0].Text)
	}
}

func TestData(t *testing.T) {
	e := New()
	e.Data("Nhãn:", "giá trị")
	l := e.Lines()[0]
	if l.Kind != KindData || l.Label != "Nhãn:" || l.Value != "giá trị" {
		t.Errorf("Data sai: %+v", l)
	}
}

func TestActionFraming(t *testing.T) {
	e := New()
	// Hành động đầu tiên: sep + header + sep (không có dòng trống phía trên).
	e.Action("Tùy chọn 1")
	lines := e.Lines()
	if len(lines) != 3 {
		t.Fatalf("hành động đầu tiên phải phát 3 dòng, được %d", len(lines))
	}
	if lines[0].Kind != KindSep || lines[1].Kind != KindAction || lines[2].Kind != KindSep {
		t.Errorf("khung hành động sai: %v %v %v", lines[0].Kind, lines[1].Kind, lines[2].Kind)
	}

	// Hành động thứ hai: có thêm dòng trống phía trên.
	e.Action("Tùy chọn 2")
	lines = e.Lines()
	if lines[3].Kind != KindBlank {
		t.Errorf("hành động thứ hai phải bắt đầu bằng dòng trống, được %v", lines[3].Kind)
	}
}

func TestSink(t *testing.T) {
	var got []Line
	e := NewWithSink(func(l Line) { got = append(got, l) })
	e.Ok("a")
	e.Info("b")
	if len(got) != 2 {
		t.Errorf("sink phải nhận 2 dòng, được %d", len(got))
	}
	if e.Len() != 2 {
		t.Errorf("Emitter cũng phải lưu lại các dòng")
	}
}

func TestSetFirstAction(t *testing.T) {
	e := New()
	e.SetFirstAction(false)
	e.Action("X")
	if e.Lines()[0].Kind != KindBlank {
		t.Errorf("SetFirstAction(false) phải chèn dòng trống trước")
	}
}

func TestAllHelpers(t *testing.T) {
	e := New()
	e.Sep()
	e.Sep2()
	e.Blank()
	e.Cmd("cmd")
	e.Fetch("fetch")
	e.Info("info")
	e.Ok("ok")
	e.Warn("warn")
	e.Error("err")
	e.Key("key")
	e.Diag("diag")
	e.Help("help")
	e.DE("de")
	e.Text(KindAction, "text")
	e.Data("nhãn", "giá trị")

	want := []Kind{
		KindSep, KindSep2, KindBlank, KindCmd, KindFetch, KindInfo, KindOk,
		KindWarn, KindError, KindKey, KindDiag, KindHelp, KindDE, KindAction, KindData,
	}
	if e.Len() != len(want) {
		t.Fatalf("Len = %d, muốn %d", e.Len(), len(want))
	}
	for i, k := range want {
		if e.Lines()[i].Kind != k {
			t.Errorf("dòng %d Kind = %v, muốn %v", i, e.Lines()[i].Kind, k)
		}
	}
}

func TestResetFirstAction(t *testing.T) {
	e := New()
	e.Action("A") // đặt firstAction=false
	e.ResetFirstAction()
	before := e.Len()
	e.Action("B")
	// Sau reset, hành động B lại là "đầu tiên" → không có dòng trống dẫn đầu.
	if e.Lines()[before].Kind != KindSep {
		t.Errorf("sau ResetFirstAction, hành động phải bắt đầu bằng Sep, được %v", e.Lines()[before].Kind)
	}
}
