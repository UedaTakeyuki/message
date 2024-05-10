// refer followings
//
//  https://xn--go-hh0g6u.com/pkg/crypto/aes/

package message

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"log"
)

type AESGCM struct {
	key                []byte
	plainmessage       []byte
	transformedmessage []byte
	iv                 []byte
	aesgcm             cipher.AEAD
}

///////////////////////
// Set key & iv
///////////////////////

// Set encription key. This key is also used by AES CTR and hash function SHA-246 for HMAC
func (m *AESGCM) SetKey(key []byte) {
	l := len(key)
	if l != 16 && l != 24 && l != 32 {
		// refer https://xn--go-hh0g6u.com/pkg/crypto/aes/#NewCipher
		log.Println("key length should be 16 or 24 or 32 byte")
	}
	m.key = key
}

// Get randombyte from /dev/urandom for IV
func (m *AESGCM) SetNewIV() {
	var err error
	/* A 256 bit key */
	m.iv, err = get_randombytes(12)
	if err != nil {
		log.Println(err)
	} else {
		//		log.Println("SetNewIV", m.iv)
	}
}

///////////////////////
// Set plain message
///////////////////////

// Set plain message to encript, get IV, and encript.
func (m *AESGCM) SetPlainMessage(plainmessage []byte, aad []byte) {
	if m.key == nil {
		log.Println("set key first.")
	}
	m.plainmessage = plainmessage
	//	m.transformedmessage = make([]byte, len(plainmessage))

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
	m.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
	}
	m.transformedmessage = m.aesgcm.Seal(nil, m.iv, m.plainmessage, aad)
	//	m.transformedmessage = append(m.iv, m.transformedmessage...)
}

///////////////////////
// Get enclipted message
///////////////////////

func (m *AESGCM) GetEncriptedMessage() (t []byte) {
	t = append(m.iv, m.transformedmessage...)
	return
}

func (m *AESGCM) GetEncodedEncriptedMessage() (t string) {
	t = base64.URLEncoding.EncodeToString(m.GetEncriptedMessage())
	return
}

///////////////////////
// Set enclipted message
///////////////////////

func (m *AESGCM) SetEncriptedMessage(t []byte, aad []byte) (err error) {
	if m.key == nil {
		log.Println("set key first.")
	}
	m.iv = t[:12]
	m.transformedmessage = t[12:]
	//	log.Println("SetEncriptedMessage", t, m.iv, m.plainmessage)

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
	m.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
	}
	m.plainmessage, err = m.aesgcm.Open(nil, m.iv, m.transformedmessage, aad)
	return
}

func (m *AESGCM) SetEncodedEncriptedMessage(t string, aad []byte) (err error) {
	if m.key == nil {
		log.Println("set key first.")
	}
	messageEncriptedDecoded, err := base64.URLEncoding.DecodeString(t)
	if err != nil {
		log.Println(err)
	}
	err = m.SetEncriptedMessage(messageEncriptedDecoded, aad)
	return
}

///////////////////////
// Get decripted message
///////////////////////

func (m *AESGCM) GetDecriptedMessage() (t []byte) {
	t = m.plainmessage
	return
}
