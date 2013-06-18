package md5crypt

import (
	"bytes"
	"testing"
)

var cryptTests = []struct {
	input  string
	expect string
}{
	{" ", "$1$yiiZbNIH$YiCsHZjcTkYd31wkgW8JF."},
	{"pass", "$1$YeNsbWdH$wvOF8JdqsoiLix754LTW90"},
	{"____fifteen____", "$1$s9lUWACI$Kk1jtIVVdmT01p0z3b/hw1"},
	{"____sixteen_____", "$1$dL3xbVZI$kkgqhCanLdxODGq14g/tW1"},
	{"____seventeen____", "$1$NaH5na7J$j7y8Iss0hcRbu3kzoJs5V."},
	{"__________thirty-three___________", "$1$HO7Q6vzJ$yGwp2wbL5D7eOVzOmxpsy."},
	{"apache", "$apr1$J.w5a/..$IW9y6DR0oO/ADuhlMF5/X1"},
	{"GNU libc manual", "$1$/iSaq7rB$EoUw5jJPPvAPECNaaWzMK/"},
}

func TestCryptVerify(t *testing.T) {
	for _, tt := range cryptTests {
		input := []byte(tt.input)
		expect := []byte(tt.expect)
		got, _ := Crypt(input, expect)
		if !bytes.Equal(got, expect) {
			t.Errorf("md5crypt(%s) failed: got=%s expected=%s", string(input), got, tt.expect)
		}
	}
}

func TestCryptSalt(t *testing.T) {

	p := []byte("pass")
	s := []byte("$1$YeNsbWdH")
	expected := []byte("$1$YeNsbWdH$wvOF8JdqsoiLix754LTW90")

	got, _ := Crypt(p, s)

	if !bytes.Equal(got, expected) {
		t.Errorf("md5crypt gen (%s) failed: got=%s expected=%s", string(p), got, expected)
	}
}
