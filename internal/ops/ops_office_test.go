package ops

import (
	"testing"

	"github.com/vinhwincheck/wincheck/internal/logx"
	"github.com/vinhwincheck/wincheck/internal/testprovider"
)

func TestExtractOfficeKeys(t *testing.T) {
	sampleOutput := `
---Processing--------------------------
---------------------------------------
PRODUCT ID: 00339-10000-00000-AA953
SKU ID: d450596f-894d-49e0-966a-fd50b4d4cde0
LICENSE NAME: Office 16, Office16ProPlusVL_KMS_Client edition
LICENSE DESCRIPTION: Office 16, VOLUME_KMSCLIENT channel
BETA EXPIRATION: 1/1/1601
LICENSE STATUS:  ---LICENSED--- 
ERROR CODE: 0x4004F040
KEY MANAGEMENT SERVICE MACHINE NAME: kms8.msguides.com:1688
Last 5 characters of installed product key: WFG99
---------------------------------------
PRODUCT ID: 00339-10000-00000-AA954
SKU ID: d450596f-894d-49e0-966a-fd50b4d4cde1
LICENSE NAME: Office 19, Office19ProPlus2019VL_KMS_Client_AE edition
LICENSE STATUS:  ---LICENSED--- 
Last 5 characters of installed product key: 27GG4
---------------------------------------
`
	keys := ExtractOfficeKeys(sampleOutput)
	if len(keys) != 2 {
		t.Fatalf("kỳ vọng tìm thấy 2 key, thực tế: %d (%v)", len(keys), keys)
	}
	if keys[0] != "WFG99" || keys[1] != "27GG4" {
		t.Errorf("danh sách key không khớp: %v", keys)
	}

	// Kiểm tra loại bỏ trùng lặp
	dupOutput := sampleOutput + "\nLast 5 characters of installed product key: WFG99\n"
	dupKeys := ExtractOfficeKeys(dupOutput)
	if len(dupKeys) != 2 {
		t.Errorf("kỳ vọng loại bỏ key trùng lặp, thực tế: %d", len(dupKeys))
	}

	// Kiểm tra mẫu fallback (chỉ có ': XXXXX' ở cuối dòng)
	fallbackOutput := `
Custom output line:
Installed Key: AB12C
`
	fbKeys := ExtractOfficeKeys(fallbackOutput)
	if len(fbKeys) != 1 || fbKeys[0] != "AB12C" {
		t.Errorf("kỳ vọng tìm được key AB12C từ fallback regex, thực tế: %v", fbKeys)
	}
}

func TestCleanOfficeKeys_Cancelled(t *testing.T) {
	f := testprovider.New()
	f.OfficeDirs = []string{`C:\Program Files\Microsoft Office\root\Office16`}
	ui := &testprovider.FakeUI{ConfirmDefault: false}
	e := logx.New()

	CleanOfficeKeys(f, ui, e)

	if len(f.OsppCalls) != 0 {
		t.Errorf("người dùng hủy xác nhận thì không được chạy lệnh ospp nào")
	}
	if !has(e, logx.KindInfo, "Đã hủy") {
		t.Errorf("phải thông báo đã hủy")
	}
}

func TestCleanOfficeKeys_NoOfficeFound(t *testing.T) {
	f := testprovider.New()
	f.OfficeDirs = nil // không tìm thấy thư mục nào
	ui := &testprovider.FakeUI{ConfirmDefault: true}
	e := logx.New()

	CleanOfficeKeys(f, ui, e)

	if !has(e, logx.KindError, "Không tìm thấy file ospp.vbs") {
		t.Errorf("phải báo lỗi không tìm thấy file ospp.vbs")
	}
}

func TestCleanOfficeKeys_Success(t *testing.T) {
	dir := `C:\Program Files\Microsoft Office\root\Office16`
	f := testprovider.New()
	f.OfficeDirs = []string{dir}

	initialDstatus := `
---Processing--------------------------
LICENSE NAME: Office 16, Office16ProPlusVL_KMS_Client edition
LICENSE STATUS:  ---LICENSED--- 
Last 5 characters of installed product key: WFG99
---------------------------------------
LICENSE NAME: Office 19, Office19ProPlus2019VL_KMS_Client edition
LICENSE STATUS:  ---LICENSED--- 
Last 5 characters of installed product key: 27GG4
---------------------------------------
`
	checkDstatus := `
---Processing--------------------------
---------------------------------------
No keys found.
`

	dstatusCount := 0
	f.OsppHook = func(dir string, args ...string) (string, error) {
		argStr := args[0]
		switch {
		case argStr == "/remhst":
			return "KMS host removed", nil
		case argStr == "/dstatus":
			dstatusCount++
			if dstatusCount == 1 {
				return initialDstatus, nil
			}
			return checkDstatus, nil
		case argStr == "/unpkey:WFG99" || argStr == "/unpkey:27GG4":
			return "<Product key uninstall successful>", nil
		default:
			return "", nil
		}
	}

	ui := &testprovider.FakeUI{ConfirmDefault: true}
	e := logx.New()

	CleanOfficeKeys(f, ui, e)

	// Kiểm tra các lệnh đã gọi
	expectedCalls := []string{
		dir + ":/remhst",
		dir + ":/dstatus",
		dir + ":/unpkey:WFG99",
		dir + ":/unpkey:27GG4",
		dir + ":/dstatus",
	}

	if len(f.OsppCalls) != len(expectedCalls) {
		t.Fatalf("kỳ vọng %d lệnh được gọi, thực tế: %d (%v)", len(expectedCalls), len(f.OsppCalls), f.OsppCalls)
	}

	for i, want := range expectedCalls {
		if f.OsppCalls[i] != want {
			t.Errorf("lệnh thứ %d không đúng: muốn %s, được %s", i, want, f.OsppCalls[i])
		}
	}

	// Kiểm tra log ghi nhận thành công
	if !has(e, logx.KindOk, "Đã xóa thành công key WFG99") {
		t.Errorf("phải ghi log xóa thành công key WFG99")
	}
	if !has(e, logx.KindOk, "Đã xóa thành công key 27GG4") {
		t.Errorf("phải ghi log xóa thành công key 27GG4")
	}
	if !has(e, logx.KindOk, "Tổng kết") {
		t.Errorf("phải có thông báo tổng kết")
	}
}
