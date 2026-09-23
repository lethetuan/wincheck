// Command genicon vẽ biểu tượng ứng dụng WinCheck ra build/appicon.png.
//
// Toàn bộ hình vẽ là NGUYÊN GỐC (không dùng ảnh/icon có bản quyền của bên thứ ba):
// một huy hiệu khiên xác thực nền xanh dương với dấu tích — chủ đề "kiểm định bản
// quyền". Vẽ ở độ phân giải cao rồi thu nhỏ để khử răng cưa (anti-aliasing).
//
// Chạy từ thư mục gốc dự án:  go run ./tools/genicon
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

type pt struct{ x, y float64 }

const (
	out = 1024     // kích thước ảnh cuối
	ss  = 3        // hệ số siêu lấy mẫu (khử răng cưa)
	big = out * ss // kích thước khi vẽ
)

func main() {
	img := image.NewRGBA(image.Rect(0, 0, big, big))
	s := float64(ss)

	// 1) Nền: hình vuông bo góc, chuyển sắc dọc xanh dương (không dùng màu tím).
	bg := roundedRect(20*s, 20*s, (out-20)*s, (out-20)*s, 190*s)
	top := color.RGBA{59, 130, 246, 255} // #3B82F6 (blue-500)
	bot := color.RGBA{29, 64, 175, 255}  // #1D40AF (blue-800)
	fillPoly(img, bg, func(_, y int) color.RGBA {
		return lerp(top, bot, float64(y)/float64(big))
	})

	// 2) Khiên trắng ở giữa.
	white := color.RGBA{255, 255, 255, 255}
	fillPoly(img, scalePts(shieldOutline(), s), func(_, _ int) color.RGBA { return white })

	// 3) Dấu tích xanh lá bên trong khiên.
	drawCheck(img, s, color.RGBA{22, 163, 74, 255}) // #16A34A (green-600)

	// 4) Thu nhỏ big→out, trung bình có trọng số alpha (viền mượt, không bị tối).
	final := downsample(img)

	f, err := os.Create("build/appicon.png")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, final); err != nil {
		panic(err)
	}
}

// ── Hình học ─────────────────────────────────────────────────────────────────

func roundedRect(x0, y0, x1, y1, r float64) []pt {
	var p []pt
	p = append(p, arc(x0+r, y0+r, r, math.Pi, 1.5*math.Pi, 20)...)   // trên-trái
	p = append(p, arc(x1-r, y0+r, r, 1.5*math.Pi, 2*math.Pi, 20)...) // trên-phải
	p = append(p, arc(x1-r, y1-r, r, 0, 0.5*math.Pi, 20)...)         // dưới-phải
	p = append(p, arc(x0+r, y1-r, r, 0.5*math.Pi, math.Pi, 20)...)   // dưới-trái
	return p
}

// shieldOutline dựng đường bao khiên trong hệ tọa độ 1024 (y hướng xuống).
func shieldOutline() []pt {
	const cx, t, hw, rc, sh, by = 512.0, 226.0, 246.0, 52.0, 556.0, 812.0
	xl, xr := cx-hw, cx+hw
	var p []pt
	p = append(p, arc(xl+rc, t+rc, rc, math.Pi, 1.5*math.Pi, 16)...)   // góc trên-trái
	p = append(p, arc(xr-rc, t+rc, rc, 1.5*math.Pi, 2*math.Pi, 16)...) // góc trên-phải
	p = append(p, pt{xr, sh})                                          // cạnh phải xuống
	p = append(p, bezier(pt{xr, sh}, pt{xr, sh + 150}, pt{cx + 150, by}, pt{cx, by}, 26)...)
	p = append(p, bezier(pt{cx, by}, pt{cx - 150, by}, pt{xl, sh + 150}, pt{xl, sh}, 26)...)
	return p // cạnh trái đóng ngầm từ (xl,sh) về điểm đầu (xl, t+rc)
}

func drawCheck(img *image.RGBA, s float64, col color.RGBA) {
	p1, p2, p3 := pt{398, 520}, pt{470, 600}, pt{654, 402}
	const hw = 28.0
	fill := func(pts []pt) { fillPoly(img, scalePts(pts, s), func(_, _ int) color.RGBA { return col }) }
	fill(segQuad(p1, p2, hw))
	fill(segQuad(p2, p3, hw))
	for _, c := range []pt{p1, p2, p3} { // bo tròn đầu/khớp nối
		fill(circle(c, hw, 32))
	}
}

func arc(cx, cy, r, a0, a1 float64, n int) []pt {
	p := make([]pt, 0, n+1)
	for i := 0; i <= n; i++ {
		a := a0 + (a1-a0)*float64(i)/float64(n)
		p = append(p, pt{cx + r*math.Cos(a), cy + r*math.Sin(a)})
	}
	return p
}

func bezier(p0, p1, p2, p3 pt, n int) []pt {
	p := make([]pt, 0, n+1)
	for i := 0; i <= n; i++ {
		t := float64(i) / float64(n)
		m := 1 - t
		x := m*m*m*p0.x + 3*m*m*t*p1.x + 3*m*t*t*p2.x + t*t*t*p3.x
		y := m*m*m*p0.y + 3*m*m*t*p1.y + 3*m*t*t*p2.y + t*t*t*p3.y
		p = append(p, pt{x, y})
	}
	return p
}

func circle(c pt, r float64, n int) []pt {
	p := make([]pt, 0, n)
	for i := 0; i < n; i++ {
		a := 2 * math.Pi * float64(i) / float64(n)
		p = append(p, pt{c.x + r*math.Cos(a), c.y + r*math.Sin(a)})
	}
	return p
}

func segQuad(a, b pt, hw float64) []pt {
	dx, dy := b.x-a.x, b.y-a.y
	l := math.Hypot(dx, dy)
	nx, ny := -dy/l*hw, dx/l*hw
	return []pt{{a.x + nx, a.y + ny}, {b.x + nx, b.y + ny}, {b.x - nx, b.y - ny}, {a.x - nx, a.y - ny}}
}

func scalePts(p []pt, s float64) []pt {
	q := make([]pt, len(p))
	for i, v := range p {
		q[i] = pt{v.x * s, v.y * s}
	}
	return q
}

// ── Tô đa giác (quét dòng, quy tắc even-odd) ─────────────────────────────────

func fillPoly(img *image.RGBA, pts []pt, col func(x, y int) color.RGBA) {
	if len(pts) < 3 {
		return
	}
	yMin, yMax := pts[0].y, pts[0].y
	for _, p := range pts {
		yMin = math.Min(yMin, p.y)
		yMax = math.Max(yMax, p.y)
	}
	y0 := int(math.Floor(yMin))
	y1 := int(math.Ceil(yMax))
	if y0 < 0 {
		y0 = 0
	}
	if y1 >= big {
		y1 = big - 1
	}
	for y := y0; y <= y1; y++ {
		ys := float64(y) + 0.5
		var xs []float64
		for i := 0; i < len(pts); i++ {
			a := pts[i]
			b := pts[(i+1)%len(pts)]
			if (a.y <= ys && b.y > ys) || (b.y <= ys && a.y > ys) {
				t := (ys - a.y) / (b.y - a.y)
				xs = append(xs, a.x+t*(b.x-a.x))
			}
		}
		if len(xs) < 2 {
			continue
		}
		sortFloats(xs)
		for i := 0; i+1 < len(xs); i += 2 {
			xa := int(math.Ceil(xs[i] - 0.5))
			xb := int(math.Floor(xs[i+1] - 0.5))
			if xa < 0 {
				xa = 0
			}
			if xb >= big {
				xb = big - 1
			}
			for x := xa; x <= xb; x++ {
				img.SetRGBA(x, y, col(x, y))
			}
		}
	}
}

func sortFloats(a []float64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

func lerp(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{
		uint8(float64(a.R) + (float64(b.R)-float64(a.R))*t),
		uint8(float64(a.G) + (float64(b.G)-float64(a.G))*t),
		uint8(float64(a.B) + (float64(b.B)-float64(a.B))*t),
		255,
	}
}

func downsample(src *image.RGBA) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, out, out))
	for y := 0; y < out; y++ {
		for x := 0; x < out; x++ {
			var rSum, gSum, bSum, aSum float64
			for dy := 0; dy < ss; dy++ {
				for dx := 0; dx < ss; dx++ {
					c := src.RGBAAt(x*ss+dx, y*ss+dy)
					a := float64(c.A)
					rSum += float64(c.R) * a
					gSum += float64(c.G) * a
					bSum += float64(c.B) * a
					aSum += a
				}
			}
			var o color.RGBA
			o.A = uint8(aSum/float64(ss*ss) + 0.5)
			if aSum > 0 {
				o.R = uint8(rSum/aSum + 0.5)
				o.G = uint8(gSum/aSum + 0.5)
				o.B = uint8(bSum/aSum + 0.5)
			}
			dst.SetRGBA(x, y, o)
		}
	}
	return dst
}
