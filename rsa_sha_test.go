package jwt_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	defaultRSAPrivateKeyBlock, _ = pem.Decode([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----`))
	defaultRSAPublicKeyBlock, _ = pem.Decode([]byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----`))

	defaultRSAPrivateKey, rsaPrivKeyErr = x509.ParsePKCS1PrivateKey(defaultRSAPrivateKeyBlock.Bytes)
	rsaPKIXPublicKey, rsaPublicKeyErr   = x509.ParsePKIXPublicKey(defaultRSAPublicKeyBlock.Bytes)
	defaultRSAPublicKey, _              = rsaPKIXPublicKey.(*rsa.PublicKey)

	defaultRSAHeaders = testTable{
		jwt.SHA256: []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"),
		jwt.SHA384: []byte("eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"),
		jwt.SHA512: []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9"),
	}
	defaultRSAPSSHeaders = testTable{
		jwt.SHA256: []byte("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9"),
		jwt.SHA384: []byte("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9"),
		jwt.SHA512: []byte(""),
	}
	defaultRSASignatures = testTable{
		jwt.SHA256: []byte("FThNm4IGfWKNfZxrVjrzqUz3p7l5lm3b-HpbhqZhukNylQWx643ulhGznn4JdZqL8eYwp9Vevk2IB5Jm_VoUWODK9mKOnlzd9wVHwuJ1I8YcQuDBqe1ySOhZwqWSQWhnLEtpk6MrDCV8qQDqmDFFvN0nvzdqoyQlJzrud32RdykvjrkJGgiNhTCCPSJUHnDv2GP2E7930IHPEU2HvQvhqYgXeO6e_xhC0KlAMUSlG5yaaVxOTMXlEgjKy9l_U0Mrg3W0Q5DcYLIrIkRjnxI_SE2OKAdKxre0Zj-HbU9aJqvSAIOgjDDfJ-ddV7VgF_llZlvOze87HfvTRB5VwIGHkA"),
		jwt.SHA384: []byte("ZgPcDksMp8w-iWlwxdrdGf9txmw4YBxzUAinXtVIA0shRciVykoFa1J-aHjm_H9OFQSld_krDQ6iBiEG1YIb6h9R_75GfadbbHvbmnup-mjHlVC0jCOkH6MghbdGe4z9dUl6IwP1yJR1kcwtacLszpsDuc1Gp-puPTgntXdKlNiOKzIynbKQyuVVAmSUrSABv-Yo9W_2ojW4NFzxQAlemb4ymSS-_h-SBf6BZauwRppo2XoiKN6J2ZOJ8JSEBAb9VvNIkU6n6WSUOvRdQSCmYwKjL6a30fn_OcvHPl38U-gT9mIdz7AO5-I-u706JX_43_x6p-ORIcgP_Wwrozuu6Q"),
		jwt.SHA512: []byte("AMTub1RBhhGtZYonOP_29EJTr1KIzBYELSqGhkbo9vid3nYzgMBdouJ0EOKSOd8gidz4nJJ-A6ZuowN_jg7YwlxuXNw_rWViFkjAkNaLd0R8ZNmIyKz5jEgU4VH8dJDvbQco_kqIQgX_sr6N44LZLUsD1LcaYCo4DsSWJ_1JU0N2gWFaqjOP5gu-VMbcscnErzPkstUQC7cnHVs7rCckPbOub3wkelUJcJtQmfCZWuf2iNRLSBPkIpoSAbjW26VSRDFoaaMIGF9-TKWTY8j03ESd0nRUNK8Uj_kMDwxDKkAwD4HWxYQsuf9ixWm08bDefH2xC3qU8nWifmC1TyAhqA"),
	}
	defaultRSAPSSSignatures = testTable{
		jwt.SHA256: []byte("HZp_yZcBc3QGCVFGS6OHgXnpxe7B_pGYmW-hN-ydOebmpBbo_qNI4UC9utcqYT5RmVK64icqE3tcfF5G_ZoA_XYJiQ92LAoMi81i5giChrVbv0I4YdFK6aL5cJ-U-DOSxkKbcm-WsfTR-dMkK_U3OrDzNiXjA7LF_czRwOWGmB4eblOHrZHl_H0Of_2oYbb_dlH6nc1bgOwQ9qX2ZoM481oYDj7RjnaHnuUfQEo7faaYa0yv558WuiWt34LvPSTInzkX9hd4dlH3f8BTPCX1b91lkO8jvBh7Ktu5TShZ1Dd5Zc_l2KwSeG3Fihw6ZJw2FL66zg-MkkGKRkci7xQwPA"),
		jwt.SHA384: []byte("f3dRjQcjcWTVuBc-K4Wwb0QTKMj3pdBJPHXKtuaBI5_-sLhSq9cihZcQ4VN3foUfOum4qSRAWVyhxtE9QslUsuaGPav8M_l0noflNszRXjEoDid1xrPE2jc2uFjBjgruge22_WIJUIZo69B_VojWZb8tqegIYOF5lTn-bZkaSBWAgTLsYI2aqBbgP1loHX7I70XeV8k4lDLDrNz6IP-sH8YMSPfCwv2cdCXqAyk4D2kkosZ9_KPZr9VT7wB39gdXnSEPsVexnD-VT6rluuGcgazdGOW4yhhjOxrKSRkkHq_Q4MhrvwXUtzM8fijFiOY4kbKe5PQk7HMoRRS2Ypb5Tg"),
		jwt.SHA512: []byte(""),
	}
)

func TestRSASign(t *testing.T) {
	if rsaPrivKeyErr != nil {
		t.Fatal(rsaPrivKeyErr)
	}
	ds, err := decodeSigs(defaultRSASignatures)
	if err != nil {
		t.Fatal(err)
	}
	// dsPSS, err := decodeSigs(defaultRSAPSSSignatures)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	testCases := []struct {
		r             *jwt.RSA
		headerPayload []byte
		want          []byte
		err           error
	}{
		{
			jwt.NewRSA(jwt.SHA256, defaultRSAPrivateKey, nil),
			claims(defaultRSAHeaders[jwt.SHA256], defaultPayload),
			ds[jwt.SHA256],
			nil,
		},
		// PSS signatures are random
		// {
		// 	jwt.NewRSA(jwt.SHA256, defaultRSAPrivateKey, nil).PSS(),
		// 	claims(defaultRSAPSSHeaders[jwt.SHA256], defaultPayload),
		// 	dsPSS[jwt.SHA256],
		// 	nil,
		// },
		{
			jwt.NewRSA(jwt.SHA384, defaultRSAPrivateKey, nil),
			claims(defaultRSAHeaders[jwt.SHA384], defaultPayload),
			ds[jwt.SHA384],
			nil,
		},
		// {
		// 	jwt.NewRSA(jwt.SHA384, defaultRSAPrivateKey, nil).PSS(),
		// 	claims(defaultRSAPSSHeaders[jwt.SHA384], defaultPayload),
		// 	dsPSS[jwt.SHA384],
		// 	nil,
		// },
		{
			jwt.NewRSA(jwt.SHA512, defaultRSAPrivateKey, nil),
			claims(defaultRSAHeaders[jwt.SHA512], defaultPayload),
			ds[jwt.SHA512],
			nil,
		},
		// {
		// 	jwt.NewRSA(jwt.SHA512, defaultRSAPrivateKey, nil).PSS(),
		// 	claims(defaultRSAHeaders[jwt.SHA512], defaultPayload),
		// 	dsPSS[jwt.SHA512],
		// 	nil,
		// },
	}
	for _, tc := range testCases {
		t.Run(tc.r.String(), func(t *testing.T) {
			sig, err := tc.r.Sign(tc.headerPayload)
			if want, got := tc.want, sig; string(want) != string(got) {
				t.Errorf("want %x, got %x", want, got)
			}
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}

func TestRSASize(t *testing.T) {
	testCases := []struct {
		h    *jwt.RSA
		want int
	}{
		{jwt.NewRSA(jwt.SHA256, defaultRSAPrivateKey, nil), defaultRSAPublicKey.Size()},
		{jwt.NewRSA(jwt.SHA384, defaultRSAPrivateKey, nil), defaultRSAPublicKey.Size()},
		{jwt.NewRSA(jwt.SHA512, defaultRSAPrivateKey, nil), defaultRSAPublicKey.Size()},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.want, tc.h.Size(); want != got {
				t.Errorf("want %d, got %d", want, got)
			}
		})
	}
}

func TestRSAString(t *testing.T) {
	testCases := []struct {
		h    *jwt.RSA
		want string
	}{
		{jwt.NewRSA(jwt.SHA256, defaultRSAPrivateKey, nil), jwt.MethodRS256},
		{jwt.NewRSA(jwt.SHA384, defaultRSAPrivateKey, nil), jwt.MethodRS384},
		{jwt.NewRSA(jwt.SHA512, defaultRSAPrivateKey, nil), jwt.MethodRS512},
		{jwt.NewRSA(jwt.Hash(0), defaultRSAPrivateKey, nil), jwt.MethodRS256},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.want, tc.h.String(); want != got {
				t.Errorf("want %s, got %s", want, got)
			}
		})
	}
}

func TestRSAVerify(t *testing.T) {
	if rsaPublicKeyErr != nil {
		t.Fatal(rsaPublicKeyErr)
	}
	testCases := []struct {
		r             *jwt.RSA
		headerPayload []byte
		sig           []byte
		err           error
	}{
		{
			jwt.NewRSA(jwt.SHA256, nil, defaultRSAPublicKey),
			claims(defaultRSAHeaders[jwt.SHA256], defaultPayload),
			defaultRSASignatures[jwt.SHA256],
			nil,
		},
		{
			jwt.NewRSA(jwt.SHA384, nil, defaultRSAPublicKey),
			claims(defaultRSAHeaders[jwt.SHA384], defaultPayload),
			defaultRSASignatures[jwt.SHA384],
			nil,
		},
		{
			jwt.NewRSA(jwt.SHA512, nil, defaultRSAPublicKey),
			claims(defaultRSAHeaders[jwt.SHA512], defaultPayload),
			defaultRSASignatures[jwt.SHA512],
			nil,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			err := tc.r.Verify(tc.headerPayload, tc.sig)
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}
