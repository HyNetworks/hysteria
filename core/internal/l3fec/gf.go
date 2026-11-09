package l3fec

// GF(256) with polynomial 0x11d.
var (
	exp [512]byte
	log [256]int
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		exp[i] = x
		log[x] = i
		var n byte
		if x&0x80 != 0 {
			n = (x << 1) ^ 0x1d
		} else {
			n = x << 1
		}
		x = n
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
}

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return exp[log[a]+log[b]]
}

func inv(a byte) byte {
	if a == 0 {
		return 0
	}
	return exp[255-log[a]]
}

// coeff is the Cauchy matrix entry for data index i and parity index j.
func coeff(i, j int) byte {
	return inv(byte(i) ^ byte(128+j))
}
