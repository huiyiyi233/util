package util

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// Md5EncryptByte encrypts <data> using MD5 algorithms.
func Md5EncryptByte(data []byte, s, upper bool) (encrypt string, err error) {
	h := md5.New()
	if _, err = h.Write(data); err != nil {
		return "", err
	}
	t := hex.EncodeToString(h.Sum(nil))
	if !s && len(t) == 32 {
		t = t[8:24]
	}
	if upper {
		return strings.ToUpper(t), nil
	}
	return t, nil
}

// Md5MustEncryptByte encrypts <data> using MD5 algorithms.
func Md5MustEncryptByte(data []byte, s, upper bool) string {
	result, err := Md5EncryptByte(data, s, upper)
	if err != nil {
		return ""
	}
	return result
}

func Md5MustEncryptString(data string, s, upper bool) string {
	result, err := Md5EncryptByte(StringToBytes(data), s, upper)
	if err != nil {
		return ""
	}
	return result
}
