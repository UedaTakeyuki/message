package message

import (
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

///////////////////////
//
// Create AESGCM
//
///////////////////////

// Create AESGCM for Encript
func createAESGCMforEncript(key []byte, plainmessage []byte, aad []byte) (m *message.AESGCM, err error) {
	// new AESGCM
	m = new(message.AESGCM)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	// set plainmessage for encription
	if err = m.SetPlainMessage(plainmessage, aad); err != nil {
		return
	}

	return
}

// Create AESGCM for Decript
func createAESGCMforDecript(key []byte) (m *message.AESGCM, err error) {
	// new AESGCM
	m = new(message.AESGCM)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	return
}

///////////////////////
//
// Encript by AESGCM
//
///////////////////////

func encriptByteArrayByAESGCM(key []byte, plainmessage []byte, aad []byte) (crypticmessage []byte, err error) {
	// new AESGCM
	var m *message.AESGCM
	if m, err = createAESGCMforEncript(key, plainmessage, aad); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncriptedMessage()

	return
}

func encriptStringByAESGCM(key []byte, plainmessage string, aad []byte) (crypticmessage string, err error) {
	// new AESGCM
	var m *message.AESGCM
	if m, err = createAESGCMforEncript(key, []byte(plainmessage), aad); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	return
}

///////////////////////
//
// Decript by AESGCM
//
///////////////////////

///////////////////////
// ByteArray
///////////////////////

// core
func decriptByteArrayByAESGCMcore(key []byte, crypticmessage []byte, aad []byte) (decriptedmessage []byte, m *message.AESGCM, err error) {
	// new AESGCM
	if m, err = createAESGCMforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncriptedMessage(crypticmessage, aad); err != nil {
		return
	}

	decriptedmessage = m.GetDecriptedMessage()

	return
}

// decript
func decriptByteArrayByAESGCM(key []byte, crypticmessage []byte, aad []byte) (decriptedmessage []byte, err error) {
	decriptedmessage, _, err = decriptByteArrayByAESGCMcore(key, crypticmessage, aad)

	return
}

///////////////////////
// String
///////////////////////

// core
func decriptStringByAESGCMcore(key []byte, crypticmessage string, aad []byte) (decriptedmessage string, m *message.AESGCM, err error) {
	// new AESGCM
	if m, err = createAESGCMforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncodedEncriptedMessage(crypticmessage, aad); err != nil {
		return
	}

	decriptedmessage = string(m.GetDecriptedMessage())

	return
}

// decript
func decriptStringByAESGCM(key []byte, crypticmessage string, aad []byte) (decriptedmessage string, err error) {
	decriptedmessage, _, err = decriptStringByAESGCMcore(key, crypticmessage, aad)

	return
}

func decodeDecriptAESGCM(t *testing.T, crypticmessage string, key []byte, aad []byte, originalmessage string) (err error) {

	// get original message from cryptic message
	decreiptedMessage, err := decriptStringByAESGCM(key, crypticmessage, aad)
	cp.Compare(t, decreiptedMessage, string(originalmessage))
	cp.Compare(t, err, nil)

	return
}
