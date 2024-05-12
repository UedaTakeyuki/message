package message

///////////////////////
//
// Create AESCTR
//
///////////////////////

// Create AESCTR for Encript
func CreateAESCTRforEncript(key []byte, plainmessage []byte) (m *AESCTR, err error) {
	// new AESCTR
	m = new(AESCTR)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	// set plainmessage for encription
	if err = m.SetPlainMessage(plainmessage); err != nil {
		return
	}

	return
}

// Create AESCTR for Decript
func CreateAESCTRforDecript(key []byte) (m *AESCTR, err error) {
	// new AESCTR
	m = new(AESCTR)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	return
}
