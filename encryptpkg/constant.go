package encryptpkg

// 文件加密默认大小
const (
	FILE_AES_SIZE = 1024 * 1024 * 100 //文件加密 100mb  每100mb 进行加密一次

	ENCRYPT_MODE_AES    EncryptMode = "AES"
	ENCRYPT_MODE_DES    EncryptMode = "DES"
	ENCRYPT_MODE_RSA    EncryptMode = "RSA"
	ENCRYPT_MODE_SHA256 EncryptMode = "SHA256"
	ENCRYPT_MODE_SHA1   EncryptMode = "SHA1"

	ENCRYPT_STREAM_SIZE = 1024 // 默认加密文件字节长度 byte长度是1024,rune长度是383
	DECRYPT_CIPHER_SIZE = 3884 // 1024长度加密的长度是3884位
)

type EncryptMode string

//16,24,32位字符串的话，分别对应AES-128，AES-192，AES-256 加密方法
var AES_ENCRYPT_KEY = []byte("ABCDEFHGabcdefhg12345678!@#$%^&*") // 扩充写到配置中 随机默认是32位的加密串
