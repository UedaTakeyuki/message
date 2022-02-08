// refer followings
//
//  https://xn--go-hh0g6u.com/pkg/crypto/aes/

package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
)

type AESCTR struct {
	key                []byte
	plainmessage       []byte
	transformedmessage []byte
	iv                 []byte
	aesctr             cipher.Stream
}

// Set encription key. This key is also used by AES CTR and hash function SHA-246 for HMAC
func (m *AESCTR) SetKey(key []byte) {
	l := len(key)
	if l != 16 && l != 24 && l != 32 {
		// refer https://xn--go-hh0g6u.com/pkg/crypto/aes/#NewCipher
		log.Println("key length should be 16 or 24 or 32 byte")
	}
	m.key = key
}

// Get randombyte from /dev/urandom for IV
func (m *AESCTR) SetNewIV() {
	var err error
	/* A 256 bit key */
	m.iv, err = get_randombytes(aes.BlockSize)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("SetNewIV", m.iv)
	}
}

// Set plain message to encript, get IV, and encript.
func (m *AESCTR) SetPlainMessage(plainmessage []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	m.plainmessage = plainmessage
	m.transformedmessage = make([]byte, len(plainmessage))

	block, err := aes.NewCipher(m.key)
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
	m.aesctr = cipher.NewCTR(block, m.iv) // 使いまわしはできない
	if err != nil {
		log.Println(err)
	}

	m.aesctr.XORKeyStream(m.transformedmessage, m.plainmessage)
	//	log.Println("SetPlainMessage", m.iv, m.plainmessage, m.transformedmessage)
}

func (m *AESCTR) GetPlainMessageMacAsByteArray() (mac []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	h := hmac.New(sha256.New, []byte(m.key))
	h.Write([]byte(m.plainmessage))
	mac = h.Sum(nil)
	return
}

func (m *AESCTR) GetPlainMessageMac() (mac string) {
	/*
		if m.key == nil {
			log.Println("set key first.")
		}
		h := hmac.New(sha256.New, []byte(m.key))
		h.Write([]byte(m.plainmessage))
		mac = hex.EncodeToString(h.Sum(nil))
	*/
	mac = hex.EncodeToString(m.GetPlainMessageMacAsByteArray())
	return
}

func (m *AESCTR) GetEncriptedMessage() (t []byte) {
	log.Println("GetEncriptedMessage", m.iv, m.transformedmessage)
	t = append(m.iv, m.transformedmessage...)
	return
}

func (m *AESCTR) GetEncodedEncriptedMessage() (t string) {
	t = base64.URLEncoding.EncodeToString(m.GetEncriptedMessage())
	return
}

func (m *AESCTR) SetEncriptedMessage(t []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	m.iv = t[:aes.BlockSize]
	m.SetPlainMessage(t[aes.BlockSize:])
	//	log.Println("SetEncriptedMessage", t, m.iv, m.plainmessage)
}

func (m *AESCTR) SetEncodedEncriptedMessage(t string) {
	if m.key == nil {
		log.Println("set key first.")
	}
	messageEncriptedDecoded, err := base64.URLEncoding.DecodeString(t)
	if err != nil {
		log.Println(err)
	}
	m.SetEncriptedMessage(messageEncriptedDecoded)
}

func (m *AESCTR) GetDecriptedMessage() (t []byte) {
	t = m.transformedmessage
	return
}

func (m *AESCTR) GetDecriptedMessageMacAsByteArray() (mac []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	h := hmac.New(sha256.New, []byte(m.key))
	h.Write([]byte(m.transformedmessage))
	mac = h.Sum(nil)
	return
}

func (m *AESCTR) GetDecriptedMessageMac() (mac string) {
	/*	if m.key == nil {
			log.Println("set key first.")
		}
		h := hmac.New(sha256.New, []byte(m.key))
		h.Write([]byte(m.transformedmessage))
		mac = hex.EncodeToString(h.Sum(nil))*/
	mac = hex.EncodeToString(m.GetDecriptedMessageMacAsByteArray())
	return
}

// https://xn--go-hh0g6u.com/pkg/crypto/hmac/#Equal
func (m *AESCTR) ConfirmMacFromByteArray(originalMac []byte) (result bool) {
	result = hmac.Equal(m.GetDecriptedMessageMacAsByteArray(), originalMac)
	return
}

func (m *AESCTR) ConfirmMacFromstring(originalMac string) (result bool, err error) {
	mac2, err := hex.DecodeString(originalMac)
	if err != nil {
		return
	}
	result = hmac.Equal(m.GetDecriptedMessageMacAsByteArray(), mac2)
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
