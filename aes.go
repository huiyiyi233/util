package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"strconv"
)

func Conversion10to10(cipherText string) []byte {
	if len(cipherText)%2 != 0 {
		return nil
	}
	a := make([]byte, len(cipherText)/2)
	b := 0
	for i := 0; i < len(cipherText); i += 2 {
		val := string(cipherText[i]) + string(cipherText[i+1])
		n, err := strconv.ParseUint(val, 16, 32)
		if err != nil {
			return nil
		}
		a[b] = byte(n)
		b++
	}
	return a
}

// Padding 对明文进行填充
func Padding(plainText []byte, blockSize int) []byte {
	//计算要填充的长度
	n := blockSize - len(plainText)%blockSize
	//对原来的明文填充n个n
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

// UnPadding 对密文删除填充
func UnPadding(cipherText []byte) []byte {
	//取出密文最后一个字节end
	end := cipherText[len(cipherText)-1]
	le := len(cipherText) - int(end)
	if le <= 0 || le > len(cipherText) {
		return cipherText
	}

	//删除填充
	cipherText = cipherText[:le]
	return cipherText
}

// AesCBCEncrypted AES加密
func AesCBCEncrypted(plaintext []byte, key []byte) ([]byte, error) {
	plaintext = Padding(plaintext, aes.BlockSize)
	if len(plaintext)%aes.BlockSize != 0 { //块大小在aes.BlockSize中定义
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key) //生成加密用的block
	if err != nil {
		return nil, err
	}

	// 对IV有随机性要求，但没有保密性要求，所以常见的做法是将IV包含在加密文本当中
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	//随机一个block大小作为IV
	//采用不同的IV时相同的秘钥将会产生不同的密文，可以理解为一次加密的session
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// 谨记密文需要认证(i.e. by using crypto/hmac)
	return ciphertext, nil
}

// AesCBCDecrypter Aes 解密
func AesCBCDecrypter(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks可以原地更新
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = UnPadding(ciphertext)

	return ciphertext, nil
}
