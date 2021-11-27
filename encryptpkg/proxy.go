package encryptpkg

import (
	"crypto/sha256"
	"fmt"
)

// 全部字节流加密字节流加密的外包装方法，内部支持其他加密方式 AES DES
func EncryptBytes(stream []byte, mode EncryptMode, cipherKey []byte) (string, error) {

	if mode == ENCRYPT_MODE_AES {
		aesEncryptBase64Str, err := aesEncryptBase64(stream, cipherKey)
		return aesEncryptBase64Str, err
	}
	//预留其他逻辑
	return "", nil

}

// 解密完整的字节流数据 EncryptBytes的解密
func DecryptBytes(ciphertext []byte, mode EncryptMode, cipherKey []byte) ([]byte, error) {

	// 解密字符
	if mode == ENCRYPT_MODE_AES {
		bytes, err := aesDecryptBase64(string(ciphertext), cipherKey)
		return bytes, err
	}
	return []byte{}, nil
}

// 计算字节流摘要
func BytesSum(fileByte []byte) (string, error) {
	hashAlgorithm := sha256.New()
	buf := make([]byte, 0)

	buf = append(buf, fileByte...)
	hashAlgorithm.Write(buf)

	return fmt.Sprintf("%x", hashAlgorithm.Sum(nil)), nil
}

// 获取加密key
func GetCipherKey() []byte {
	return AES_ENCRYPT_KEY
}

// 对一个字节流指定位置部分内容加密，默认加密字节流的前1024byte返回密文
func EncryptByPos(stream []byte, mode EncryptMode, cipherKey []byte) ([]byte, error) {

	streamRune := []rune(string(stream))
	streamSize := len(streamRune) //字节流大小

	if streamSize <= ENCRYPT_STREAM_SIZE {
		ciphertext, err := EncryptBytes(stream, mode, cipherKey)
		return []byte(ciphertext), err
	}

	// 字节流大于1024个，只加密字节流的前面1024个
	if mode == ENCRYPT_MODE_AES {
		buffer := make([]rune, 0)
		headStream := make([]rune, 0)
		headStream = streamRune[:ENCRYPT_STREAM_SIZE]
		headStreamBytes, err := EncryptBytes([]byte(string(headStream)), ENCRYPT_MODE_AES, cipherKey)
		if err != nil {
			return []byte{}, err
		}

		remainStream := streamRune[ENCRYPT_STREAM_SIZE:]
		buffer = append(buffer, []rune(headStreamBytes)...)
		buffer = append(buffer, remainStream...)

		return []byte(string(buffer)), err
	}
	return []byte{}, nil
}

func DecryptByPos(ciphertext []byte, mode EncryptMode, cipherKey []byte) ([]byte, error) {

	// offset大于加密串长度，只解密字节流的前面offset个
	if len(ciphertext) <= DECRYPT_CIPHER_SIZE {
		contBytes, err := DecryptBytes(ciphertext, mode, cipherKey)
		return contBytes, err
	}

	buffer := make([]rune, 0)
	headCipher := []rune(string(ciphertext[0:DECRYPT_CIPHER_SIZE]))
	headBytes, err := DecryptBytes([]byte(string(headCipher)), mode, cipherKey)
	if err != nil {
		return []byte{}, err
	}

	headStr := string(headBytes)
	headRune := []rune(headStr)
	remainStream := ciphertext[DECRYPT_CIPHER_SIZE:]
	buffer = append(buffer, headRune...)
	buffer = append(buffer, []rune(string(remainStream))...)

	return []byte(string(buffer)), nil
}
