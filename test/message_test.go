package message

import (
	"log"
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
	//	"github.com/UedaTakeyuki/message"
)

const originalMessage = "some plaintext"

var key_256 = []byte("01234567890123456789012345678901")

func encriptAndEncode(plainmessage []byte) (crypticmessage string, mac string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey(key_256)

	// set plainmessage for encription
	m.SetPlainMessage(plainmessage)

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()
	log.Println("crypticmessage:", crypticmessage)

	// get Authentication Code of this message
	mac = m.GetPlainMessageMac()
	log.Println("hmac of plaintext:", mac)

	return
}

func decodeAndDecript(crypticmessage string, mac string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey(key_256)

	// set criptic message string
	m.SetEncodedEncriptedMessage(crypticmessage)

	// get original message from cryptic message
	decreiptedMessage := m.GetDecriptedMessage()
	log.Println("decreiptedMessage:", string(decreiptedMessage))

	// confirm Authentication Code
	result, _ := m.ConfirmMacFromstring(mac)
	log.Println("Confrimation result is", result)
}

func Test_AESCTR(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	//	originalMessage := "some plaintext"

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey(key_256)

	// set plainmessage for encription
	m.SetPlainMessage([]byte(originalMessage))

	// get hmac of original message
	hmacOriginal := m.GetPlainMessageMac()
	log.Println("hmacOriginal", hmacOriginal)

	// get encripted message
	encriptedMessage := m.GetEncriptedMessage()
	log.Println("encriptedMessage", encriptedMessage)

	// get encoded encripted message
	encodedEncriptedMessage := m.GetEncodedEncriptedMessage()
	log.Println("encodedEncriptedMessage", string(encodedEncriptedMessage))

	// set encripted message for decription
	m.SetEncriptedMessage(encriptedMessage)

	// get decripted message
	decreiptedMessage := m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	cp.Compare(t, string(decreiptedMessage), originalMessage)

	// get decripted message mac
	hmacDecripted := m.GetDecriptedMessageMac()
	log.Println("hmacDecripted", hmacDecripted)

	// confirm hmac
	equal, err := m.ConfirmMacFromstring(hmacOriginal)
	cp.Compare(t, err, nil)
	cp.Compare(t, equal, true)

	// set encoded encripted message
	m.SetEncodedEncriptedMessage(encodedEncriptedMessage)
	decreiptedMessage = m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	cp.Compare(t, string(decreiptedMessage), originalMessage)

	crypticmessage, mac := encriptAndEncode([]byte(originalMessage))
	decodeAndDecript(crypticmessage, mac)
}

func Test_AESGCM(t *testing.T) {
	//	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	aad := []byte("Some AAD data")

	//	originalMessage := "some plaintext"

	// new AESGCM
	m := new(message.AESGCM)

	// set key
	m.SetKey(key_256)

	// set plainmessage for encription
	m.SetPlainMessage([]byte(originalMessage), aad)

	// get hmac of original message
	//	hmacOriginal := m.GetPlainMessageMac()
	//	log.Println("hmacOriginal", hmacOriginal)

	// get encripted message
	encriptedMessage := m.GetEncriptedMessage()
	log.Println("encriptedMessage", encriptedMessage)

	// get encoded encripted message
	encodedEncriptedMessage := m.GetEncodedEncriptedMessage()
	log.Println("encodedEncriptedMessage", string(encodedEncriptedMessage))

	// new AESGCM
	m = new(message.AESGCM)

	// set key
	m.SetKey(key_256)

	// set encripted message for decription
	m.SetEncriptedMessage(encriptedMessage, aad)

	// get decripted message
	decreiptedMessage := m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	if string(decreiptedMessage) != originalMessage {
		t.Errorf("got: %v\nwant: %v", string(decreiptedMessage), originalMessage)
	}

	// get decripted message mac
	//	hmacDecripted := m.GetDecriptedMessageMac()
	//	log.Println("hmacDecripted", hmacDecripted)

	// confirm hmac
	/*
		equal, err := m.ConfirmMacFromstring(hmacOriginal)
		if err != nil {
			log.Println(err)
		}
		if !equal {
			t.Errorf("original Mac: %v\nDecripted Mac: %v", hmacOriginal, hmacDecripted)
		}
	*/

	// new AESGCM
	m = new(message.AESGCM)

	// set key
	m.SetKey(key_256)

	// set encoded encripted message
	m.SetEncodedEncriptedMessage(encodedEncriptedMessage, aad)
	decreiptedMessage = m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	cp.Compare(t, string(decreiptedMessage), originalMessage)
}
