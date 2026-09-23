package config

import (
	"path/filepath"
	"strings"
	"testing"
)

const sampleIni = `
# Bình luận đầu tệp
[GvlkKeys]
W269N-WFGWX-YVC9B-4J6C9-T83GX = Windows 11/10 Pro
MH37W-N47XK-V7XM9-C7227-GCQG9 = Windows 11/10 Pro N

[KmsPiracyDomains]
msguides         ; km8.msguides.com
example.piracy

[DefaultPorts]
1688
1689

[DefaultServices]
CustomKmsSvc

[DefaultProcesses]
customproc

[DefaultTaskKeywords]
CustomTask

[DefaultFilePaths]
C:\Windows\System32\spp\store\2.0\data.dat

# ═══ USER BLOCK ═══
[UserGvlkKeys]
AB1CD-EF2GH-IJ3KL-MN4OP-QR5ST = Khóa riêng

[UserKmsPiracyDomains]
my.piracy.example

[ExtraPorts]
8080
notaport

[ExtraServices]
MyKmsService

[ExtraTaskKeywords]
MyTask

[ExtraProcesses]
myproc.exe

[ExtraFilePaths]
C:\Tools\KMSTool
`

func TestParseSections(t *testing.T) {
	s := Parse(sampleIni)

	if len(s.DefaultGvlkSuffixes) != 2 {
		t.Errorf("DefaultGvlkSuffixes = %v, muốn 2", s.DefaultGvlkSuffixes)
	}
	if s.DefaultGvlkSuffixes[0] != "T83GX" {
		t.Errorf("hậu tố GVLK đầu = %q, muốn T83GX", s.DefaultGvlkSuffixes[0])
	}
	if len(s.DefaultIniKmsPiracyDomains) != 2 || s.DefaultIniKmsPiracyDomains[0] != "msguides" {
		t.Errorf("KmsPiracyDomains parse sai (bình luận nội dòng?): %v", s.DefaultIniKmsPiracyDomains)
	}
	if len(s.DefaultIniPorts) != 2 {
		t.Errorf("DefaultIniPorts = %v, muốn [1688 1689]", s.DefaultIniPorts)
	}
	if len(s.UserGvlkSuffixes) != 1 || s.UserGvlkSuffixes[0] != "QR5ST" {
		t.Errorf("UserGvlkSuffixes = %v, muốn [QR5ST]", s.UserGvlkSuffixes)
	}
	if len(s.ExtraKmsPiracyDomains) != 1 || s.ExtraKmsPiracyDomains[0] != "my.piracy.example" {
		t.Errorf("ExtraKmsPiracyDomains = %v", s.ExtraKmsPiracyDomains)
	}
	if len(s.ExtraPorts) != 1 || s.ExtraPorts[0] != 8080 {
		t.Errorf("ExtraPorts = %v, muốn [8080] (bỏ 'notaport')", s.ExtraPorts)
	}
	if len(s.ExtraServices) != 1 || s.ExtraServices[0] != "MyKmsService" {
		t.Errorf("ExtraServices = %v", s.ExtraServices)
	}
	if len(s.ExtraFilePaths) != 1 || s.ExtraFilePaths[0] != `C:\Tools\KMSTool` {
		t.Errorf("ExtraFilePaths = %v", s.ExtraFilePaths)
	}
}

func TestSectionNormalization(t *testing.T) {
	// [EXTRA_PORTS] và [ExtraPorts] phải cùng ánh xạ.
	s := Parse("[EXTRA_PORTS]\n7000\n[Extra Ports]\n7001\n")
	if len(s.ExtraPorts) != 2 {
		t.Errorf("chuẩn hóa section sai: %v", s.ExtraPorts)
	}
}

func TestKeySuffixExtraction(t *testing.T) {
	s := Parse("[GvlkKeys]\nvk7jg-nphtm-c97jm-9mpgt-3v66t = pro\n")
	if len(s.DefaultGvlkSuffixes) != 1 || s.DefaultGvlkSuffixes[0] != "3V66T" {
		t.Errorf("trích hậu tố sai: %v", s.DefaultGvlkSuffixes)
	}
}

func TestMergedViews(t *testing.T) {
	s := Parse(sampleIni)

	ports := s.AllPorts()
	if !containsInt(ports, 1688) || !containsInt(ports, 1689) || !containsInt(ports, 8080) {
		t.Errorf("AllPorts thiếu cổng: %v", ports)
	}

	svcs := s.AllServices()
	if !containsStr(svcs, "KMSpico") || !containsStr(svcs, "CustomKmsSvc") || !containsStr(svcs, "MyKmsService") {
		t.Errorf("AllServices thiếu mục: %v", svcs)
	}

	gvlk := s.AllGvlkSuffixes()
	if !containsStr(gvlk, "T83GX") || !containsStr(gvlk, "QR5ST") || !containsStr(gvlk, "3V66T") {
		t.Errorf("AllGvlkSuffixes thiếu mục: %v", gvlk)
	}

	dom := s.AllKmsPiracyDomains()
	if !containsStr(dom, "msguides") || !containsStr(dom, "my.piracy.example") {
		t.Errorf("AllKmsPiracyDomains thiếu mục: %v", dom)
	}
}

func TestDedupeCaseInsensitive(t *testing.T) {
	// "KMSpico" có sẵn trong mặc định; thêm "kmspico" không được nhân đôi.
	s := Parse("[ExtraServices]\nkmspico\n")
	svcs := s.AllServices()
	count := 0
	for _, v := range svcs {
		if strings.EqualFold(v, "kmspico") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("dedupe không phân biệt hoa thường thất bại: %d bản 'kmspico'", count)
	}
}

func TestMissingFileGivesDefaults(t *testing.T) {
	s := Load(filepath.Join(t.TempDir(), "khong-ton-tai.ini"))
	if len(s.ExtraPorts) != 0 {
		t.Errorf("tệp thiếu phải cho danh sách bổ sung rỗng")
	}
	if !containsInt(s.AllPorts(), 1688) {
		t.Errorf("vẫn phải có cổng mặc định 1688")
	}
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
