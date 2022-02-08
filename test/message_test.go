package message

import (
	"local.packages/message"
	"log"
	"testing"
	//	"github.com/UedaTakeyuki/message"
)

func Test_AESCTR(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	originalMessage := "some plaintext"

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey([]byte("01234567890123456789012345678901"))

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
	log.Println(decreiptedMessage, string(decreiptedMessage))

	if string(decreiptedMessage) != originalMessage {
		t.Errorf("got: %v\nwant: %v", string(decreiptedMessage), originalMessage)
	}

	// get decripted message mac
	hmacDecripted := m.GetDecriptedMessageMac()
	log.Println("hmacDecripted", hmacDecripted)

	// confirm hmac
	equal, err := m.ConfirmMacFromstring(hmacOriginal)
	if err != nil {
		log.Println(err)
	}
	if !equal {
		t.Errorf("original Mac: %v\nDecripted Mac: %v", hmacOriginal, hmacDecripted)
	}

	// set encoded encripted message
	m.SetEncodedEncriptedMessage(encodedEncriptedMessage)
	decreiptedMessage = m.GetDecriptedMessage()
	log.Println(decreiptedMessage, string(decreiptedMessage))

	if string(decreiptedMessage) != originalMessage {
		t.Errorf("got: %v\nwant: %v", string(decreiptedMessage), originalMessage)
	}

}
