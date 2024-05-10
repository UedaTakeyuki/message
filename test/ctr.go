package message

import (
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

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

func encriptByteArrayByAESCTR(key []byte, plainmessage []byte) (crypticmessage []byte, mac []byte, err error) {
	// new AESCTR
	var m *message.AESCTR
	if m, err = createAESCTRforEncript(key, plainmessage); err != nil {
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
	if m, err = createAESCTRforEncript(key, []byte(plainmessage)); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	// get hmac for authentication
	mac, err = m.GetPlainMessageMac()

	return
}

func decriptByAESCTRtoByteArray() {}

func decriptAuthConfByAESCTR() {}

func decodeDecriptAuth(t *testing.T, crypticmessage string, key []byte, mac string, originalmessage string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	//	m.SetKey(key_256)
	m.SetKey(key)

	// set criptic message string
	m.SetEncodedEncriptedMessage(crypticmessage)

	// get original message from cryptic message
	decreiptedMessage := m.GetDecriptedMessage()
	cp.Compare(t, string(decreiptedMessage), originalmessage)

	// confirm Authentication Code
	result, err := m.ConfirmMacFromstring(mac)
	cp.Compare(t, err, nil)
	cp.Compare(t, result, true)
}
