package l3fec

import "encoding/binary"

const (
	headerSize = 9 // group u32, index u8, k u8, r u8, len u16
	maxK       = 32
	maxR       = 16
	maxLen     = 1600
)

// ParityCount is the number of parity packets for a group of k data packets.
// A short group gets 8 parity packets so one lost ACK is still recoverable.
func ParityCount(k int) int {
	if k <= 0 {
		return 0
	}
	if k > maxK {
		k = maxK
	}
	if k < 8 {
		return 8
	}
	r := k / 2
	if r > maxR {
		r = maxR
	}
	return r
}

// Encode builds systematic data chunks plus Cauchy parity chunks.
// Each returned blob is self-describing. Data blobs carry the original
// packet. Parity blobs cover a length-prefixed, zero-padded symbol so a
// recovered packet can be trimmed back to its real size.
func Encode(group uint32, pkts [][]byte) [][]byte {
	k := len(pkts)
	if k == 0 || k > maxK {
		return nil
	}
	width := 0
	for _, p := range pkts {
		if len(p) > width {
			width = len(p)
		}
	}
	if width == 0 || width > maxLen {
		return nil
	}
	symWidth := width + 2
	r := ParityCount(k)
	symbols := make([][]byte, k)
	for i, p := range pkts {
		symbols[i] = make([]byte, symWidth)
		binary.BigEndian.PutUint16(symbols[i][0:2], uint16(len(p)))
		copy(symbols[i][2:], p)
	}
	par := make([][]byte, r)
	for j := 0; j < r; j++ {
		par[j] = make([]byte, symWidth)
		for i := 0; i < k; i++ {
			xorMul(par[j], symbols[i], coeff(i, j))
		}
	}
	out := make([][]byte, 0, k+r)
	for i := 0; i < k; i++ {
		out = append(out, pack(group, i, k, r, pkts[i]))
	}
	for j := 0; j < r; j++ {
		out = append(out, pack(group, k+j, k, r, par[j]))
	}
	return out
}

// Chunk is one fragment of a group.
type Chunk struct {
	Group   uint32
	Index   int
	K       int
	R       int
	Payload []byte
}

// Unpack parses one encoded blob.
func Unpack(b []byte) (Chunk, bool) {
	if len(b) < headerSize {
		return Chunk{}, false
	}
	c := Chunk{
		Group: binary.BigEndian.Uint32(b[0:4]),
		Index: int(b[4]),
		K:     int(b[5]),
		R:     int(b[6]),
	}
	n := int(binary.BigEndian.Uint16(b[7:9]))
	if c.K <= 0 || c.K > maxK || c.R < 0 || c.R > maxR || n > maxLen+2 || headerSize+n > len(b) {
		return Chunk{}, false
	}
	if c.Index >= c.K+c.R {
		return Chunk{}, false
	}
	c.Payload = b[headerSize : headerSize+n]
	return c, true
}

func pack(group uint32, index, k, r int, payload []byte) []byte {
	b := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint32(b[0:4], group)
	b[4] = byte(index)
	b[5] = byte(k)
	b[6] = byte(r)
	binary.BigEndian.PutUint16(b[7:9], uint16(len(payload)))
	copy(b[headerSize:], payload)
	return b
}

// Recover returns the k data payloads in index order.
// data keys are 0..k-1 (original packets). parity keys are 0..r-1.
func Recover(k int, data map[int][]byte, parity map[int][]byte) ([][]byte, bool) {
	if k <= 0 || k > maxK {
		return nil, false
	}
	out := make([][]byte, k)
	missing := make([]int, 0)
	for i := 0; i < k; i++ {
		if p, ok := data[i]; ok {
			out[i] = append([]byte(nil), p...)
		} else {
			missing = append(missing, i)
		}
	}
	if len(missing) == 0 {
		return out, true
	}
	use := make([]int, 0, len(missing))
	for j := 0; j < maxR; j++ {
		if _, ok := parity[j]; ok {
			use = append(use, j)
			if len(use) == len(missing) {
				break
			}
		}
	}
	if len(use) < len(missing) {
		return nil, false
	}
	width := 0
	for _, p := range parity {
		if len(p) > width {
			width = len(p)
		}
	}
	if width < 2 {
		return nil, false
	}
	m := len(missing)
	a := make([][]byte, m)
	for row := 0; row < m; row++ {
		a[row] = make([]byte, m)
		for col := 0; col < m; col++ {
			a[row][col] = coeff(missing[col], use[row])
		}
	}
	invA, ok := invert(a)
	if !ok {
		return nil, false
	}
	// Rebuild every symbol (known data included) at the parity width, then
	// solve only the missing columns. Known symbols are length-prefixed.
	known := make(map[int][]byte, k-m)
	for i := 0; i < k; i++ {
		if _, gone := find(missing, i); gone {
			continue
		}
		sym := make([]byte, width)
		binary.BigEndian.PutUint16(sym[0:2], uint16(len(data[i])))
		copy(sym[2:], data[i])
		known[i] = sym
	}
	rhs := make([][]byte, m)
	for row := 0; row < m; row++ {
		rhs[row] = pad(parity[use[row]], width)
		for i, sym := range known {
			xorMul(rhs[row], sym, coeff(i, use[row]))
		}
	}
	for col := 0; col < m; col++ {
		rec := make([]byte, width)
		for row := 0; row < m; row++ {
			xorMul(rec, rhs[row], invA[col][row])
		}
		n := int(binary.BigEndian.Uint16(rec[0:2]))
		if n > width-2 || n > maxLen {
			return nil, false
		}
		out[missing[col]] = append([]byte(nil), rec[2:2+n]...)
	}
	return out, true
}

func find(xs []int, v int) (int, bool) {
	for i, x := range xs {
		if x == v {
			return i, true
		}
	}
	return 0, false
}

func pad(p []byte, n int) []byte {
	if len(p) == n {
		b := make([]byte, n)
		copy(b, p)
		return b
	}
	b := make([]byte, n)
	copy(b, p)
	return b
}

func xorMul(dst, src []byte, c byte) {
	n := len(src)
	if len(dst) < n {
		n = len(dst)
	}
	if c == 0 {
		return
	}
	if c == 1 {
		for i := 0; i < n; i++ {
			dst[i] ^= src[i]
		}
		return
	}
	for i := 0; i < n; i++ {
		dst[i] ^= mul(src[i], c)
	}
}

func invert(a [][]byte) ([][]byte, bool) {
	n := len(a)
	m := make([][]byte, n)
	for i := 0; i < n; i++ {
		m[i] = make([]byte, 2*n)
		copy(m[i], a[i])
		m[i][n+i] = 1
	}
	for col := 0; col < n; col++ {
		piv := -1
		for row := col; row < n; row++ {
			if m[row][col] != 0 {
				piv = row
				break
			}
		}
		if piv < 0 {
			return nil, false
		}
		m[col], m[piv] = m[piv], m[col]
		s := inv(m[col][col])
		for c := 0; c < 2*n; c++ {
			m[col][c] = mul(m[col][c], s)
		}
		for row := 0; row < n; row++ {
			if row == col || m[row][col] == 0 {
				continue
			}
			f := m[row][col]
			for c := 0; c < 2*n; c++ {
				m[row][c] ^= mul(m[col][c], f)
			}
		}
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = append([]byte(nil), m[i][n:]...)
	}
	return out, true
}
