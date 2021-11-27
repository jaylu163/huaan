package encryptpkg

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

//加密过程：
//  1、处理数据，对数据进行填充，采用PKCS7（当密钥长度不够时，缺几位补几个几）的方式。
//  2、对数据进行加密，采用AES加密方法中CBC加密模式
//  3、对得到的加密数据，进行base64加密，得到字符串
//  4、解密过程相反

//pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

//pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

//AesEncrypt 字节流加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密块的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

//AesDecrypt 字节流解密
func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//初始化解密数据接收切片
	crypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(crypted, data)
	//去除填充
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

//EncryptByAes Aes加密 后 base64编码
func aesEncryptBase64(data []byte, cipherKey []byte) (string, error) {
	res, err := AesEncrypt(data, cipherKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

//DecryptByAes  解密再解码
func aesDecryptBase64(data string, cipherKey []byte) ([]byte, error) {
	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return []byte{}, err
	}
	return AesDecrypt(dataByte, cipherKey)
}

// 文件加密，适用于小文件的内容加密 百兆文件内容
// EncryptFile 文件加密，filePath 需要加密的文件路径 ，fName加密后文件名
func EncryptFile(filePath, fName string, cipherKey []byte) (err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return errors.New("not found file")
	}
	defer f.Close()

	fInfo, _ := f.Stat()
	fSize := fInfo.Size()
	//fmt.Println("待处理文件大小:", fSize)
	maxLen := FILE_AES_SIZE //每100mb加密一次
	var forNum int64 = 0
	getLen := fSize

	if fSize > int64(maxLen) {
		getLen = int64(maxLen)
		forNum = fSize / int64(maxLen)
		//fmt.Println("需要加密次数：", forNum+1)
	}
	//加密后存储的文件
	ff, err := os.OpenFile(fName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return errors.New("write file errors")
	}
	defer ff.Close()
	//循环加密，并写入文件
	for i := 0; i < int(forNum+1); i++ {
		a := make([]byte, getLen)
		n, err := f.Read(a)
		if err != nil {
			return errors.New(fmt.Sprintf("file read error:%v", err))
		}
		encryptBytes, err := aesEncryptBase64(a[:n], cipherKey)
		if err != nil {
			fmt.Println("加密错误")
			return err
		}
		//换行处理，有点乱了，想到更好的再改
		getBytes := append([]byte(encryptBytes), []byte("\n")...)
		//写入
		buf := bufio.NewWriter(ff)
		buf.WriteString(string(getBytes[:]))
		buf.Flush()
	}
	ffInfo, _ := ff.Stat()
	fmt.Printf("文件加密成功，生成文件名为：%s，文件大小为：%v Byte \n", ffInfo.Name(), ffInfo.Size())
	return nil
}

//DecryptFile 文件解密
func DecryptFile(filePath, fName string, cipherKey []byte) (err error) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("未找到文件")
		return
	}
	defer f.Close()
	fInfo, _ := f.Stat()
	fmt.Println("待处理文件大小:", fInfo.Size())

	br := bufio.NewReader(f)
	ff, err := os.OpenFile(fName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("文件写入错误")
		return err
	}
	defer ff.Close()
	num := 0
	//逐行读取密文，进行解密，写入文件
	for {
		num = num + 1
		splitStr, err := br.ReadString('\n')
		if err != nil {
			break
		}
		decryptBytes, err := aesDecryptBase64(splitStr, cipherKey)
		if err != nil {
			fmt.Println("解密错误")
			return err
		}

		buf := bufio.NewWriter(ff)
		buf.Write(decryptBytes)
		buf.Flush()
	}
	//fmt.Println("解密次数：", num)
	ffInfo, _ := ff.Stat()
	fmt.Printf("文件解密成功，生成文件名为：%s，文件大小为：%v Byte \n", ffInfo.Name(), ffInfo.Size())
	return
}
