package message

import (
	"testing"

	cp "github.com/UedaTakeyuki/compare"
	"local.packages/message"
)

func decodeDecriptAESGCM(t *testing.T, crypticmessage string, key []byte, aad []byte, originalmessage string) (err error) {

	// get original message from cryptic message
	decreiptedMessage, err := message.DecriptStringByAESGCM(key, crypticmessage, aad)
	cp.Compare(t, decreiptedMessage, string(originalmessage))
	cp.Compare(t, err, nil)

	return
}
