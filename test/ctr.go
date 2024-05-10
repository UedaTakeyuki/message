package message

import (
	"log"
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

func createAESCTRforEncript(key []byte, plainmessage []byte) (m *message.AESCTR) {
	// new AESCTR
	m = new(message.AESCTR)

	// set key
	m.SetKey(key)

	// set plainmessage for encription
	m.SetPlainMessage(plainmessage)

	return
}

func encriptByteArrayByAESCTR(key []byte, plainmessage []byte) (crypticmessage []byte, mac []byte) {
	// new AESCTR
	m := createAESCTRforEncript(key, plainmessage)

	// get criptic message
	crypticmessage = m.GetEncriptedMessage()

	// get hmac for authentication
	mac = m.GetPlainMessageMacAsByteArray()

	return
}

func encriptStringByAESCTR(key []byte, plainmessage string) (crypticmessage string, mac string) {
	// new AESCTR
	m := createAESCTRforEncript(key, []byte(plainmessage))

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	// get hmac for authentication
	mac = m.GetPlainMessageMac()

	return
}

func encriptEncode(t *testing.T, plainmessage []byte, key []byte) (crypticmessage string, mac string) {

	crypticmessage, mac = encriptStringByAESCTR(key, string(plainmessage))
	log.Println("crypticmessage:", crypticmessage)
	log.Println("hmac of plaintext:", mac)

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
