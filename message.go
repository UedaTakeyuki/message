package message

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"os/exec"
)

type Message struct {
	key                []byte
	plainmessage       []byte
	transformedmessage []byte
	iv                 []byte
	aesctr             cipher.Stream
}

func (m *Message) SetKey(key []byte) {
	m.key = key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	if m.iv == nil {
		m.SetNewIV()
	}
	if err != nil {
		log.Println(err)
	}
	// https://xn--go-hh0g6u.com/pkg/crypto/cipher/#example_NewCTR
	m.aesctr = cipher.NewCTR(block, m.iv)
	if err != nil {
		log.Println(err)
	}
}

func (m *Message) SetNewIV() {
	var err error
	/* A 256 bit key */
	m.iv, err = get_randombytes(aes.BlockSize)
	if err != nil {
		log.Println(err)
	}
}

func (m *Message) SetPlainMessage(plainmessage []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	m.plainmessage = plainmessage
	m.transformedmessage = make([]byte, len(plainmessage))
	m.aesctr.XORKeyStream(m.transformedmessage, m.plainmessage)
}

func (m *Message) GetEncriptedMessage() (t []byte) {
	t = append(m.iv, m.transformedmessage...)
	return
}

func (m *Message) GetEncodedEncriptedMessage() (t []byte) {
	t = base64.URLEncoding.EncodeToString(m.GetEncriptedMessage())
	return
}

func (m *Message) SetEncriptedMessage(t []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	m.iv = t[:aes.BlockSize]
	m.SetPlainMessage(t[aes.BlockSize:])
}

func (m *Message) SetEncodedEncriptedMessage(t []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	messageEncriptedDecoded, err := base64.URLEncoding.DecodeString(t)
	if err != nil {
		log.Println(err)
	}
	m.SetEncriptedMessage(messageEncriptedDecoded)
}

func (m *Message) GetDecriptedMessage() (t []byte) {
	t = m.transformedmessage
	return
}

/*
func main() {
	params := get_params()
	//	paramMD5hash := md5.Sum(params)
	log.Println("params", string(params))

	// A 256 bit key
	nonce, _ := get_randombytes(aes.BlockSize)
	//	tag, _ := get_randombytes(16)
	key := []byte("01234567890123456789012345678901")

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	// https://xn--go-hh0g6u.com/pkg/crypto/cipher/#example_NewCTR
	aesctr := cipher.NewCTR(block, nonce)
	if err != nil {
		log.Println(err.Error())
	}
	ciphertext := make([]byte, len(params))
	aesctr.XORKeyStream(ciphertext, params)

	// base64 url
	messageEncriptedEncoded := base64.URLEncoding.EncodeToString(ciphertext)
	log.Println("messageEncriptedEncoded", messageEncriptedEncoded)

	// decode base64url message
	messageEncriptedDecoded, err := base64.URLEncoding.DecodeString(messageEncriptedEncoded)

	plaintext2 := make([]byte, len(messageEncriptedDecoded))
	aesctr = cipher.NewCTR(block, nonce) // 使いまわしはできない
	aesctr.XORKeyStream(plaintext2, messageEncriptedDecoded)
	log.Println(string(plaintext2))

	var dataInterface interface{}
	err = json.Unmarshal(plaintext2, &dataInterface)
	if err != nil {
		log.Println(err.Error())
	}
	data := dataInterface.(map[string]interface{})
	log.Println("cid", data["cid"].(string))
	log.Println("psn", data["psn"].(string))
	log.Println("now", int(data["now"].(float64)))
	log.Println("ips")
	for _, ip := range data["ips"].([]interface{}) {
		log.Println(ip.(string))
	}
}
*/

func get_randombytes(length int) (random []byte, err error) {
	/* refer http://hensa40.cutegirl.jp/archives/1034 */
	bs := fmt.Sprintf("bs=%d", length)
	//	random, err = exec.Command("dd", "if=/dev/urandom", "bs=12", "count=1").Output()
	random, err = exec.Command("dd", "if=/dev/urandom", bs, "count=1").Output()
	return
}
