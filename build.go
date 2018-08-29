package jwt

func build(payload, sig []byte, s Signer) []byte {
	psize := len(payload)
	token := make([]byte, psize+1+hashSize(s))
	token[copy(token, payload)] = '.'
	enc.Encode(token[psize+1:], sig)
	return token
}
