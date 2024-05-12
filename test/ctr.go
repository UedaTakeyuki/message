package message

import (
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

func decriptAuthConfByAESCTR() {}

func decodeDecriptAuthAESCTR(t *testing.T, crypticmessage string, key []byte, mac string, originalmessage string) (err error) {

	// get original message from cryptic message
	decreiptedMessage, authresult, err := message.DecriptStringByAESCTRwithAuth(key, crypticmessage, mac)
	cp.Compare(t, decreiptedMessage, string(originalmessage))
	cp.Compare(t, err, nil)
	cp.Compare(t, authresult, true)

	return
}
