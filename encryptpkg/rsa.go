package encryptpkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// 生成私钥 也可以使用openssl bits 1024|2048|4096
// openssl genrsa -out rsa_private.pem 2048  https://blog.csdn.net/gengxiaoming7/article/details/78505107
func RSAGenPrivateKey(bits int, privateFile string, publicKeyFile string) error {
	//1,使用RSA 中的Generatekey 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//2,通过X509标准将得到的RAS私钥序列化为：ASN.1 的DER编码字符串
	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)

	//3,将私钥字符设置到pem中
	privateKeyPEM := pem.Block{
		Type:  "private Key",
		Bytes: privateStream,
	}
	//4,将blockPEM写到文件中
	priFile, err := os.Create(privateFile)
	if err != nil {
		return err
	}
	// 切记需要手动的关闭文件资源
	defer func() {
		err := priFile.Close()
		if err != nil {
			fmt.Println("close file error:", err)
		}
	}()
	//5,pem编码生成文件，不用手动写文件
	err = pem.Encode(priFile, &privateKeyPEM)

	// 使用私钥的key生成公钥
	publicKey := &privateKey.PublicKey
	publicKeyStream, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Errorf("x509 error:", err)
		return err
	}
	//数据块
	publicBlock := pem.Block{
		Type:  "public key",
		Bytes: publicKeyStream,
	}
	//创建文件
	pubFile, err := os.Create(publicKeyFile)
	if err != nil {
		return err
	}
	defer pubFile.Close()
	err = pem.Encode(pubFile, &publicBlock)
	return err
}

// RSA加密字符 使用公钥加密 此方法应该在客户端实现
func RSAEncryptBytes(stream []byte, cipherFile string) ([]byte, error) {

	// 读取本地的密钥
	localFile, err := os.Open(cipherFile)
	if err != nil {
		return []byte{}, err
	}
	defer localFile.Close()
	cipherInfo, _ := localFile.Stat()
	cipherBuf := make([]byte, cipherInfo.Size())
	_, err = localFile.Read(cipherBuf)

	// 字节解码
	block, _ := pem.Decode(cipherBuf)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return []byte{}, err
	}

	// 使用公钥加密
	if publicKey, ok := key.(*rsa.PublicKey); ok {
		encryptBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, stream)
		return encryptBytes, err
	}
	return []byte{}, errors.New("key.(*rsa.PublicKey) assert false")
}

// RSADecryptBytes 解密
func RSADecryptBytes(ciphertext []byte, cipherFile string) ([]byte, error) {

	// 获取密钥信息 文件｜可以从数据库｜配置中心获取
	localFile, err := os.Open(cipherFile)
	if err != nil {
		return []byte{}, err
	}
	fileInfo, err := localFile.Stat()
	if err != nil {
		return []byte{}, err
	}
	cipherBuffer := make([]byte, fileInfo.Size())
	_, err = localFile.Read(cipherBuffer)
	if err != nil {
		return []byte{}, err
	}

	// 解密的字符解码到块中
	block, rest := pem.Decode(cipherBuffer)
	fmt.Println("rest:", string(rest))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, err
	}
	bytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	return bytes, err
}
