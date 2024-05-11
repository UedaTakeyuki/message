// refer followings
//
//  https://xn--go-hh0g6u.com/pkg/crypto/aes/

package message

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
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
func (m *AESGCM) SetKey(key []byte) (err error) {
	l := len(key)
	if l != 16 && l != 24 && l != 32 {
		// refer https://xn--go-hh0g6u.com/pkg/crypto/aes/#NewCipher
		errors.New(SHOULBE_16_24_32)
		return
	}
	m.key = key

	return
}

// Get randombyte from /dev/urandom for IV
func (m *AESGCM) SetNewIV() (err error) {
	m.iv, err = get_randombytes(12)
	return
}

///////////////////////
// Set plain message
///////////////////////

// Set plain message to encript, get IV, and encript.
func (m *AESGCM) SetPlainMessage(plainmessage []byte, aad []byte) (err error) {
	if m.key == nil {
		errors.New(SET_KEY_FIRST)
		return
	}
	m.plainmessage = plainmessage
	//	m.transformedmessage = make([]byte, len(plainmessage))

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return
	}
	if m.iv == nil {
		if err = m.SetNewIV(); err != nil {
			return
		}
	}
	m.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}
	m.transformedmessage = m.aesgcm.Seal(nil, m.iv, m.plainmessage, aad)
	//	m.transformedmessage = append(m.iv, m.transformedmessage...)

	return
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
		errors.New(SET_KEY_FIRST)
		return
	}
	m.iv = t[:12]
	m.transformedmessage = t[12:]
	//	log.Println("SetEncriptedMessage", t, m.iv, m.plainmessage)

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return
	}
	if m.iv == nil {
		if err = m.SetNewIV(); err != nil {
			return
		}
	}
	m.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}
	m.plainmessage, err = m.aesgcm.Open(nil, m.iv, m.transformedmessage, aad)
	return
}

func (m *AESGCM) SetEncodedEncriptedMessage(t string, aad []byte) (err error) {
	if m.key == nil {
		errors.New(SET_KEY_FIRST)
		return
	}
	messageEncriptedDecoded, err := base64.URLEncoding.DecodeString(t)
	if err != nil {
		return
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
