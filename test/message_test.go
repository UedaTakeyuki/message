package message

import (
	"testing"
	"local.package/message"
)

func Test_01(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	m := new(message.Message)
}