package message

import (
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

///////////////////////
//
// Create AESCTR
//
///////////////////////

// Create AESCTR for Encript
/*
func createAESCTRforEncript(key []byte, plainmessage []byte) (m *message.AESCTR, err error) {
	// new AESCTR
	m = new(message.AESCTR)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	// set plainmessage for encription
	if err = m.SetPlainMessage(plainmessage); err != nil {
		return
	}

	return
}

// Create AESCTR for Decript
func createAESCTRforDecript(key []byte) (m *message.AESCTR, err error) {
	// new AESCTR
	m = new(message.AESCTR)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	return
}
*/
///////////////////////
//
// Encript by AESCTR
//
///////////////////////

func encriptByteArrayByAESCTR(key []byte, plainmessage []byte) (crypticmessage []byte, mac []byte, err error) {
	// new AESCTR
	var m *message.AESCTR
	if m, err = message.CreateAESCTRforEncript(key, plainmessage); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncriptedMessage()

	// get hmac for authentication
	mac, err = m.GetPlainMessageMacAsByteArray()

	return
}

func encriptStringByAESCTR(key []byte, plainmessage string) (crypticmessage string, mac string, err error) {
	// new AESCTR
	var m *message.AESCTR
	if m, err = message.CreateAESCTRforEncript(key, []byte(plainmessage)); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	// get hmac for authentication
	mac, err = m.GetPlainMessageMac()

	return
}

///////////////////////
//
// Decript by AESCTR
//
///////////////////////

///////////////////////
// ByteArray
///////////////////////

// core
func decriptByteArrayByAESCTRcore(key []byte, crypticmessage []byte) (decriptedmessage []byte, m *message.AESCTR, err error) {
	// new AESCTR
	if m, err = message.CreateAESCTRforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncriptedMessage(crypticmessage); err != nil {
		return
	}

	decriptedmessage = m.GetDecriptedMessage()

	return
}

// decript
func decriptByteArrayByAESCTR(key []byte, crypticmessage []byte) (decriptedmessage []byte, err error) {
	decriptedmessage, _, err = decriptByteArrayByAESCTRcore(key, crypticmessage)

	return
}

// decript and auth
func decriptByteArrayByAESCTRwithAuth(key []byte, crypticmessage []byte, originalmac []byte) (decriptedmessage []byte, authresult bool, err error) {
	var m *message.AESCTR
	if decriptedmessage, m, err = decriptByteArrayByAESCTRcore(key, crypticmessage); err != nil {
		return
	}
	authresult, err = m.ConfirmMacFromByteArray(originalmac)
	return
}

///////////////////////
// String
///////////////////////

// core
func decriptStringByAESCTRcore(key []byte, crypticmessage string) (decriptedmessage string, m *message.AESCTR, err error) {
	// new AESCTR
	if m, err = message.CreateAESCTRforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncodedEncriptedMessage(crypticmessage); err != nil {
		return
	}

	decriptedmessage = string(m.GetDecriptedMessage())

	return
}

// decript
func decriptStringByAESCTR(key []byte, crypticmessage string) (decriptedmessage string, err error) {
	decriptedmessage, _, err = decriptStringByAESCTRcore(key, crypticmessage)

	return
}

// decript and auth
func decriptStringByAESCTRwithAuth(key []byte, crypticmessage string, originalmac string) (decriptedmessage string, authresult bool, err error) {
	var m *message.AESCTR
	if decriptedmessage, m, err = decriptStringByAESCTRcore(key, crypticmessage); err != nil {
		return
	}
	authresult, err = m.ConfirmMacFromString(originalmac)
	return
}

func decriptAuthConfByAESCTR() {}

func decodeDecriptAuthAESCTR(t *testing.T, crypticmessage string, key []byte, mac string, originalmessage string) (err error) {

	// get original message from cryptic message
	decreiptedMessage, authresult, err := decriptStringByAESCTRwithAuth(key, crypticmessage, mac)
	cp.Compare(t, decreiptedMessage, string(originalmessage))
	cp.Compare(t, err, nil)
	cp.Compare(t, authresult, true)

	return
}
