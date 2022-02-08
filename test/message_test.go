package message

import (
	"local.packages/message"
	"log"
	"testing"
	//	"github.com/UedaTakeyuki/message"
)

func Test_01(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	m := new(message.Message)
	m.SetKey([]byte("01234567890123456789012345678901"))
}
