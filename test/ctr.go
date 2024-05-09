package message

import (
	"log"
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

func encriptByAESCTR(key []byte, plainmessage []byte) (crypticmessage string, mac string) {
	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey(key)

	// set plainmessage for encription
	m.SetPlainMessage(plainmessage)

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	// get hmac for authentication
	mac = m.GetPlainMessageMac()

	return
}

func encriptEncode(t *testing.T, plainmessage []byte, key []byte) (crypticmessage string, mac string) {

	crypticmessage, mac = encriptByAESCTR(key, plainmessage)
	log.Println("crypticmessage:", crypticmessage)
	log.Println("hmac of plaintext:", mac)

	return
}

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
