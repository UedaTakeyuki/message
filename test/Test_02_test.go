package message

import (
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
	//	"github.com/UedaTakeyuki/message"
)

//////////////
// basic test
//////////////

func Test_AESCTR_01(t *testing.T) {
	// key length 256 bit
	{
		crypticmessage, mac, err := message.EncriptStringByAESCTR(key_256, originalMessage)
		cp.Compare(t, err, nil)
		decodeDecriptAuthAESCTR(t, crypticmessage, key_256, mac, originalMessage)
	}

	// key length 192 bit
	{
		crypticmessage, mac, err := message.EncriptStringByAESCTR(key_192, originalMessage)
		cp.Compare(t, err, nil)
		decodeDecriptAuthAESCTR(t, crypticmessage, key_192, mac, originalMessage)
	}

	// key length 128 bit
	{
		crypticmessage, mac, err := message.EncriptStringByAESCTR(key_128, originalMessage)
		cp.Compare(t, err, nil)
		decodeDecriptAuthAESCTR(t, crypticmessage, key_128, mac, originalMessage)
	}
}

func Test_AESGCM_01(t *testing.T) {
	// key length 256 bit
	{
		crypticmessage, err := encriptStringByAESGCM(key_256, originalMessage, aad)
		cp.Compare(t, err, nil)
		decodeDecriptAESGCM(t, crypticmessage, key_256, aad, originalMessage)
	}

	// key length 192 bit
	{
		crypticmessage, err := encriptStringByAESGCM(key_192, originalMessage, aad)
		cp.Compare(t, err, nil)
		decodeDecriptAESGCM(t, crypticmessage, key_192, aad, originalMessage)
	}

	// key length 128 bit
	{
		crypticmessage, err := encriptStringByAESGCM(key_128, originalMessage, aad)
		cp.Compare(t, err, nil)
		decodeDecriptAESGCM(t, crypticmessage, key_128, aad, originalMessage)
	}
}
