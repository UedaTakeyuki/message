package message

import (
	"log"
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
	//	"github.com/UedaTakeyuki/message"
)

/////////////////////
// without mac & aad
/////////////////////

//const originalMessage = "some plaintext"

//var key_256 = []byte("01234567890123456789012345678901")
//var key_192 = []byte("012345678901234567890123")
//var key_128 = []byte("0123456789012345")

func Test_AESCTR_03(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	// key length 256 bit
	{
		crypticmessage, _, err1 := message.EncriptStringByAESCTR(key_256, originalMessage)
		cp.Compare(t, err1, nil)
		decriptedmessage, err2 := message.DecriptStringByAESCTR(key_256, crypticmessage)
		cp.Compare(t, err2, nil)
		cp.Compare(t, decriptedmessage, originalMessage)
	}

	// key length 192 bit
	{
		crypticmessage, _, err1 := message.EncriptStringByAESCTR(key_192, originalMessage)
		cp.Compare(t, err1, nil)
		decriptedmessage, err2 := message.DecriptStringByAESCTR(key_192, crypticmessage)
		cp.Compare(t, err2, nil)
		cp.Compare(t, decriptedmessage, originalMessage)
	}

	// key length 128 bit
	{
		crypticmessage, _, err1 := message.EncriptStringByAESCTR(key_192, originalMessage)
		cp.Compare(t, err1, nil)
		decriptedmessage, err2 := message.DecriptStringByAESCTR(key_192, crypticmessage)
		cp.Compare(t, err2, nil)
		cp.Compare(t, decriptedmessage, originalMessage)
	}
}

func Test_AESGCM_03(t *testing.T) {
	// key length 256 bit
	{
		crypticmessage, err1 := message.EncriptStringByAESGCM(key_256, originalMessage, nil)
		cp.Compare(t, err1, nil)
		decriptedmessage, err2 := message.DecriptStringByAESGCM(key_256, crypticmessage, nil)
		cp.Compare(t, err2, nil)
		cp.Compare(t, decriptedmessage, originalMessage)
	}

	// key length 192 bit
	{
		crypticmessage, err1 := message.EncriptStringByAESGCM(key_192, originalMessage, nil)
		cp.Compare(t, err1, nil)
		decriptedmessage, err2 := message.DecriptStringByAESGCM(key_192, crypticmessage, nil)
		cp.Compare(t, err2, nil)
		cp.Compare(t, decriptedmessage, originalMessage)
	}

	// key length 128 bit
	{
		crypticmessage, err1 := message.EncriptStringByAESGCM(key_192, originalMessage, nil)
		cp.Compare(t, err1, nil)
		decriptedmessage, err2 := message.DecriptStringByAESGCM(key_192, crypticmessage, nil)
		cp.Compare(t, err2, nil)
		cp.Compare(t, decriptedmessage, originalMessage)
	}
}
