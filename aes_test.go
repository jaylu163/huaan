package main

import (
	"code.galaxy-future.com/dtexpress/encryptpkg/encryptpkg"
	"fmt"
	"os"
	"testing"
)

func main() {
	/*
		var str = []byte("Hi,hello，中国，❤️")

		// 加密
		aesEncryptBase64, err := encryptpkg.AesEncryptBase64(str)
		if err != nil {
			fmt.Println("加密失败 error:", err)
		}
		fmt.Println("加密密文是:", aesEncryptBase64)

		// 解密字符串
		bytes, err := encryptpkg.AesDecryptBase64(aesEncryptBase64)
		if err != nil {
			fmt.Println("解密 error:", err)
		}
		fmt.Println("明文是：", string(bytes))

		// 文件加密
		err = encryptpkg.EncryptFile("go.mod", "go.mod.encrypt")
		if err != nil {
			fmt.Println("file encrypt error:", err)
		}

		// 文件解密
		err = encryptpkg.DecryptFile("go.mod.encrypt", "go.mod1")
		if err != nil {
			fmt.Println("file decrypt file error:", err)
		}

	*/

	/*
		bytesSum, err := encryptpkg.BytesSum([]byte("aaa bbb"))
		bytesSum, err = encryptpkg.BytesSum([]byte("eee 111"))
		bytesSum, err = encryptpkg.BytesSum([]byte(",,a 234"))
		fmt.Println("sum 缓冲和:", bytesSum, err)
	*/

	/*	str := []byte("hello,阿里，123@qq.com ♥️")
		ciphertext, _ := encryptpkg.EncryptBytes(str, "AES", encryptpkg.GetCipherKey())
		fmt.Println("密文:", ciphertext, "长度：", len(ciphertext), len([]byte(ciphertext)))

		// 解密
		cont, _ := encryptpkg.DecryptBytes([]byte(ciphertext), "AES", encryptpkg.GetCipherKey())
		fmt.Println("解密后：", string(cont))
	*/
}

func TestEncryptBytes(t *testing.T) {
	str := []byte("中国🚩hello,阿里，123@qq.com ♥️")
	ciphertext, err := encryptpkg.EncryptBytes(str, "AES", encryptpkg.GetCipherKey())

	fmt.Println("密文:", ciphertext, "长度：", len(ciphertext), "byte len:", len([]byte(ciphertext)), "error:", err)

	bytes, err := encryptpkg.DecryptBytes([]byte(ciphertext), encryptpkg.ENCRYPT_MODE_AES, encryptpkg.GetCipherKey())

	fmt.Println("解密：", string(bytes), err)
}

func TestEncryptByPos(t *testing.T) {

	//str := []byte("中国🇨🇳qq:@你在哪？ 123@qq.com;👍")
	//fmt.Println("原始内容：", string(str))
	cFile, _ := os.Open("c.log")
	buf := make([]byte, 3528)
	cFile.Read(buf)

	encryptBytes, _ := encryptpkg.EncryptByPos(buf, encryptpkg.ENCRYPT_MODE_AES, encryptpkg.GetCipherKey())

	file, _ := os.OpenFile("a.txt", os.O_RDWR, os.ModePerm)
	bytes := []byte(string(encryptBytes))
	file.Write(bytes)

	//fmt.Println("密文：", string(encryptBytes))

	runes, _ := encryptpkg.DecryptByPos(encryptBytes, encryptpkg.ENCRYPT_MODE_AES, encryptpkg.GetCipherKey())
	//fmt.Println("解密：", string(runes))
	file1, err := os.OpenFile("b.txt", os.O_RDWR, os.ModePerm)
	file1.Write(runes)

	fmt.Println("file1 error:", err)
}

func TestAb(t *testing.T) {
	bytes := []byte("周一中国🇨🇳qq:@你在哪？ 123@qq.com;👍和朋友吃饭。snerer !erer @#$#%$%%$% 😊 可能比趴在笼子里距离自己的粪便只有五厘米要开心一点 🇨🇳 ？ 2334 🚩\n吃着吃着想买狗。\n当然不是因为吃饭想买狗！\n主要是聊到家母退休之后无事可做，自己又不能天天陪伴，不如请一条懂事的小狗，会卖萌，又听话，吃的比人少，还不愁找对象，肯定比我们讨家长欢心。\n说走就走，吃完饭直接去了狗市。\n不知道我们是不是天生就有招猫逗狗体质，一家家宠物店逛过去，只要我们一进门，那绝对是锣鼓喧天猫狗齐鸣，所有四条腿的都站起来，又蹭笼子又叫唤，闹得店主无心玩手机，不得不抬眼看看我们。\n苹果CEO库克宣布将为山西捐款，以此帮助灾区重建工作。\n今天午间，苹果CEO库克宣布将为山西捐款，以此帮助受影响的社区，支持救灾，帮助重建工作！\n库克表示，随着山西地区逐步复苏，我们想要尽自己的一份力量来支持救灾，帮助重建，Apple将捐款帮助受影响的社区。\n据悉，苹果向来对我们国内的发展十分的关注，尤其是经历困难的时候，苹果总能够及时站出来伸出援手，此前郑州灾情，库克同样表达了自己的担忧，并宣布了捐款。\n三十一、不求与人相比，但求超越自己。与其用泪水悔恨今天，不如用汗水拼搏今天。当眼泪流尽的时候，留下的应该是坚强。选择自己所爱的，爱自己所选择的。这一秒不放弃，下一秒就有希望。没有人陪你走一辈子，所以你要适应孤独，没有人会帮你一辈子，所以你要奋斗一生。\n\n三十二、生活中有太多事情，我们没有办法让它停留，也没办法让它离开。\n\n三十三、一个人身边的位置只有那么多，你能给的也只有那么多，在这个狭小的圈子里，有些人要进来，就有一些人不得不离开。\n\n三十四、年龄越大，越学会了顺其自然，不想再挽留什么，相信该在的不会走。\n\n三十五、有时候，失望到了一定的程度后，反而会开出一朵花来，那朵花的名字叫，无所谓。\n\n三十六、我会让你比我先走，帮你安葬，让你安心。把痛苦留给我，把寂寞留给我。这，就是我疼你的方式\n\n一、依赖的时候有多安逸，失去的时候就有多痛苦。\n\n二、哪怕我们没有结果，在这过程里我也会全力以赴，给你自由，给你我能给的，给你我能做到的，如果不幸你抛弃我了，那就给你一个后悔的念头，给我自己一个不后悔的理由。\n\n三、我爱的人如要离开，我定只会说两个字：好的。绝口不问你怎么这样对我。你不理我，我也不会多说；你若爱我，我便爱你更多。最好的爱情观就是深情而不纠缠。\n\n四、失去一切并不可怕，怕只怕我们抵抗不过回忆。\n\n五、你的世界没有童话镇里的美好，有的只是油盐柴米的平凡，可是我却很喜欢。\n\n二十四、心若没有了归宿，到哪里都是流浪。在某一刻，你有没有很想，回到某年某月的某天。有时候，我们不是放不下那个人，而是放不下那份回忆。有时候，我看起来没心没肺，但其实比谁都真心真意。\n\n二十五、你写出的每一句离别诗词全装在我心里，我用泪水浇灌，然后生根发芽，成长为漫山遍野的相思草>。")
	fmt.Println("len:", len(bytes), len([]rune(string(bytes))))
}
