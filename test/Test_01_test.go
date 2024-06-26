package message

import (
	"log"
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
	//	"github.com/UedaTakeyuki/message"
)

///////////////////////////
// direct use of AES class
///////////////////////////

const originalMessage = "some plaintext"

var key_256 = []byte("01234567890123456789012345678901")
var key_192 = []byte("012345678901234567890123")
var key_128 = []byte("0123456789012345")

var aad = []byte("Some AAD data")

func Test_AESCTR_01(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	//	m.SetKey(key_256)
	m.SetKey(key_192)

	// set plainmessage for encription
	m.SetPlainMessage([]byte(originalMessage))

	// get hmac of original message
	var hmacOriginal string
	{
		hmacOriginal1, err := m.GetPlainMessageMac()
		cp.Compare(t, err, nil)
		log.Println("hmacOriginal", hmacOriginal1)
		hmacOriginal = hmacOriginal1
	}

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
	{
		hmacDecripted, err := m.GetDecriptedMessageMac()
		cp.Compare(t, err, nil)
		log.Println("hmacDecripted", hmacDecripted)
	}

	// confirm hmac
	{
		equal, err := m.ConfirmMacFromString(hmacOriginal)
		cp.Compare(t, err, nil)
		cp.Compare(t, equal, true)
	}

	// set encoded encripted message
	m.SetEncodedEncriptedMessage(encodedEncriptedMessage)
	decreiptedMessage = m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	cp.Compare(t, string(decreiptedMessage), originalMessage)

}

func Test_AESGCM_01(t *testing.T) {
	//	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	//aad := []byte("Some AAD data")

	//	originalMessage := "some plaintext"

	// new AESGCM
	m := new(message.AESGCM)

	// set key
	//	m.SetKey(key_256)
	m.SetKey(key_192)

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
	//	m.SetKey(key_256)
	m.SetKey(key_192)

	// set encripted message for decription
	m.SetEncriptedMessage(encriptedMessage, aad)

	// get decripted message
	decreiptedMessage := m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	if string(decreiptedMessage) != originalMessage {
		t.Errorf("got: %v\nwant: %v", string(decreiptedMessage), originalMessage)
	}

	// new AESGCM
	m = new(message.AESGCM)

	// set key
	//	m.SetKey(key_256)
	m.SetKey(key_192)

	// set encoded encripted message
	m.SetEncodedEncriptedMessage(encodedEncriptedMessage, aad)
	decreiptedMessage = m.GetDecriptedMessage()
	//log.Println(decreiptedMessage, string(decreiptedMessage))

	cp.Compare(t, string(decreiptedMessage), originalMessage)

}
