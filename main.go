// Command wincheck là ứng dụng desktop quản lý bản quyền Windows cho thị trường
// Việt Nam. Giao diện dùng Wails (backend Go + frontend React) đóng gói thành một
// ứng dụng native duy nhất chạy trên WebView2.
//
// Toàn bộ logic nghiệp vụ nằm ở các gói internal/ (không phụ thuộc Wails), được
// bao bọc bởi App (app.go) và phơi ra cho React qua cơ chế bind của Wails.
package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"github.com/vinhwincheck/wincheck/internal/sysinfo"
)

//go:embed all:frontend/dist
var assets embed.FS

// relaunchedFlag đánh dấu tiến trình đã được khởi chạy lại để nâng quyền — dùng
// để chống lặp vô hạn nếu lần nâng quyền vẫn không có quyền Admin.
const relaunchedFlag = "--relaunched"

func main() {
	provider := sysinfo.NewWindows()
	admin := provider.IsAdmin()

	// Yêu cầu quyền Admin ngay khi mở app: nếu chưa đủ quyền và chưa từng thử
	// nâng quyền, khởi chạy lại ứng dụng với UAC. Nếu người dùng chấp nhận, phiên
	// Admin mới mở và phiên hiện tại đóng lại. Nếu từ chối UAC, app vẫn mở ở chế độ
	// giới hạn (các nút 4/5/6 sẽ hướng dẫn bấm '⚡ Chạy lại với quyền Admin').
	if !admin && !hasFlag(relaunchedFlag) {
		if relaunchAsAdmin() {
			return
		}
	}

	app := NewApp(provider, admin)

	err := wails.Run(&options.App{
		Title: "WinCheck - Trình Quản Lý Bản Quyền Windows",
		// Kích thước khi người dùng thu nhỏ cửa sổ (lúc mở luôn phóng to). Đủ rộng cho
		// "rail" nội dung 1100px mà vẫn vừa màn hình 1280x720.
		Width:     1180,
		Height:    700,
		MinWidth:  900,
		MinHeight: 560,
		// Mở full màn hình (phóng to) ngay khi khởi động. Vừa đặt WindowStartState,
		// vừa gọi WindowMaximise trong domReady để chắc chắn phóng to trên mọi máy.
		WindowStartState: options.Maximised,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 248, G: 247, B: 254, A: 1},
		OnStartup:        app.startup,
		OnDomReady:       app.domReady,
		Bind:             []interface{}{app},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		println("Lỗi khởi động WinCheck:", err.Error())
	}
}

// hasFlag kiểm tra tham số dòng lệnh có chứa cờ cho trước hay không.
func hasFlag(flag string) bool {
	for _, a := range os.Args[1:] {
		if a == flag {
			return true
		}
	}
	return false
}

// relaunchAsAdmin khởi chạy lại chính ứng dụng với quyền Admin qua UAC bằng API
// Shell của Windows (ShellExecute với động từ "runas") — không dùng tiến trình
// trung gian nào. Trả về true nếu tiến trình Admin đã được khởi chạy; false nếu
// người dùng từ chối UAC hoặc có lỗi.
func relaunchAsAdmin() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return elevateSelf(exe, relaunchedFlag) == nil
}
