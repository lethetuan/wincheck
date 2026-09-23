package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// elevateSelf khởi chạy exe với quyền Admin qua UAC bằng ShellExecute — API Shell
// cấp cao của Windows (động từ "runas"). Không dùng PowerShell hay tiến trình
// trung gian nào.
//
// Trả về nil nếu tiến trình nâng quyền đã được khởi chạy; trả về lỗi nếu người
// dùng bấm "Không" trên hộp thoại UAC (ERROR_CANCELLED) hoặc có lỗi khác.
func elevateSelf(exe string, args ...string) error {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	var argPtr *uint16
	if len(args) > 0 {
		argPtr, err = syscall.UTF16PtrFromString(joinArgs(args))
		if err != nil {
			return err
		}
	}
	return windows.ShellExecute(0, verb, file, argPtr, nil, windows.SW_SHOWNORMAL)
}

// joinArgs nối các tham số dòng lệnh bằng khoảng trắng.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
