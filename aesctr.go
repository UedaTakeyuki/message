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
	"errors"
	"log"
)

type AESCTR struct {
	key                []byte
	plainmessage       []byte
	transformedmessage []byte
	iv                 []byte
	aesctr             cipher.Stream
}

///////////////////////
// Set key & iv
///////////////////////

// Set encription key. This key is also used by AES CTR and hash function SHA-246 for HMAC
func (m *AESCTR) SetKey(key []byte) (err error) {
	l := len(key)
	if l != 16 && l != 24 && l != 32 {
		err = errors.New("key length should be 16 or 24 or 32 byte")
		return
	}
	m.key = key

	return
}

// Get randombyte from /dev/urandom for IV
func (m *AESCTR) SetNewIV() (err error) {
	// aes.BlockSize = 16, refer https://pkg.go.dev/crypto/aes#pkg-constants
	m.iv, err = get_randombytes(aes.BlockSize)

	return
}

///////////////////////
// Set plain message
///////////////////////

// Set plain message to encript, get IV, and encript.
func (m *AESCTR) SetPlainMessage(plainmessage []byte) (err error) {
	if m.key == nil {
		errors.New(SET_KEY_FIRST)
		return
	}
	m.plainmessage = plainmessage
	m.transformedmessage = make([]byte, len(plainmessage))

	var block cipher.Block
	block, err = aes.NewCipher(m.key)

	// return if err
	if err != nil {
		return
	}

	// set new IV if nil
	if m.iv == nil {
		m.SetNewIV()
	}

	// https://xn--go-hh0g6u.com/pkg/crypto/cipher/#example_NewCTR
	m.aesctr = cipher.NewCTR(block, m.iv) // 使いまわしはできない

	// set stream
	m.aesctr.XORKeyStream(m.transformedmessage, m.plainmessage)

	return
}

///////////////////////
// Get hmac of plain message
///////////////////////

func (m *AESCTR) GetPlainMessageMacAsByteArray() (mac []byte, err error) {
	if m.key == nil {
		err = errors.New("set key first.")
		return
	}
	h := hmac.New(sha256.New, []byte(m.key))
	h.Write([]byte(m.plainmessage))
	mac = h.Sum(nil)

	return
}

func (m *AESCTR) GetPlainMessageMac() (mac string, err error) {
	var mac_byteArray []byte
	if mac_byteArray, err = m.GetPlainMessageMacAsByteArray(); err != nil {
		return
	}
	mac = hex.EncodeToString(mac_byteArray)
	return
}

///////////////////////
// Get enclipted message
///////////////////////

func (m *AESCTR) GetEncriptedMessage() (t []byte) {
	//	log.Println("GetEncriptedMessage", m.iv, m.transformedmessage)
	t = append(m.iv, m.transformedmessage...)
	return
}

func (m *AESCTR) GetEncodedEncriptedMessage() (t string) {
	t = base64.URLEncoding.EncodeToString(m.GetEncriptedMessage())
	return
}

///////////////////////
// Set enclipted message
///////////////////////

func (m *AESCTR) SetEncriptedMessage(t []byte) (err error) {
	if m.key == nil {
		errors.New("set key first.")
		return
	}
	m.iv = t[:aes.BlockSize]
	m.SetPlainMessage(t[aes.BlockSize:])
	//	log.Println("SetEncriptedMessage", t, m.iv, m.plainmessage)

	return
}

func (m *AESCTR) SetEncodedEncriptedMessage(t string) (err error) {
	if m.key == nil {
		errors.New("set key first.")
		return
	}
	messageEncriptedDecoded, err := base64.URLEncoding.DecodeString(t)
	if err != nil {
		log.Println(err)
	}
	m.SetEncriptedMessage(messageEncriptedDecoded)

	return
}

///////////////////////
// Get decripted message
///////////////////////

func (m *AESCTR) GetDecriptedMessage() (t []byte) {
	t = m.transformedmessage
	return
}

///////////////////////
// Get hmac of decripted message
///////////////////////

func (m *AESCTR) GetDecriptedMessageMacAsByteArray() (mac []byte, err error) {
	if m.key == nil {
		errors.New("set key first.")
		return
	}
	h := hmac.New(sha256.New, []byte(m.key))
	h.Write([]byte(m.transformedmessage))
	mac = h.Sum(nil)
	return
}

func (m *AESCTR) GetDecriptedMessageMac() (mac string, err error) {
	/*	if m.key == nil {
			log.Println("set key first.")
		}
		h := hmac.New(sha256.New, []byte(m.key))
		h.Write([]byte(m.transformedmessage))
		mac = hex.EncodeToString(h.Sum(nil))*/
	var mac_byteArray []byte
	if mac_byteArray, err = m.GetDecriptedMessageMacAsByteArray(); err != nil {
		return
	}
	mac = hex.EncodeToString(mac_byteArray)
	return
}

///////////////////////
// Confirm hmac
///////////////////////

// https://xn--go-hh0g6u.com/pkg/crypto/hmac/#Equal
func (m *AESCTR) ConfirmMacFromByteArray(originalMac []byte) (result bool, err error) {
	var mac_byteArray []byte
	if mac_byteArray, err = m.GetDecriptedMessageMacAsByteArray(); err != nil {
		return
	}
	result = hmac.Equal(mac_byteArray, originalMac)
	return
}

func (m *AESCTR) ConfirmMacFromString(originalMac string) (result bool, err error) {
	mac2, err := hex.DecodeString(originalMac)
	if err != nil {
		return
	}
	var mac_byteArray []byte
	if mac_byteArray, err = m.GetDecriptedMessageMacAsByteArray(); err != nil {
		return
	}
	result = hmac.Equal(mac_byteArray, mac2)
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
