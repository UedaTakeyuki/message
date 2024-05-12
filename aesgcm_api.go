package message

///////////////////////
//
// Create AESGCM
//
///////////////////////

// Create AESGCM for Encript
func CreateAESGCMforEncript(key []byte, plainmessage []byte, aad []byte) (m *AESGCM, err error) {
	// new AESGCM
	m = new(AESGCM)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	// set plainmessage for encription
	if err = m.SetPlainMessage(plainmessage, aad); err != nil {
		return
	}

	return
}

// Create AESGCM for Decript
func CreateAESGCMforDecript(key []byte) (m *AESGCM, err error) {
	// new AESGCM
	m = new(AESGCM)

	// set key
	if err = m.SetKey(key); err != nil {
		return
	}

	return
}
