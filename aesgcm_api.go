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

///////////////////////
//
// Encript by AESGCM
//
///////////////////////

func EncriptByteArrayByAESGCM(key []byte, plainmessage []byte, aad []byte) (crypticmessage []byte, err error) {
	// new AESGCM
	var m *AESGCM
	if m, err = CreateAESGCMforEncript(key, plainmessage, aad); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncriptedMessage()

	return
}

func EncriptStringByAESGCM(key []byte, plainmessage string, aad []byte) (crypticmessage string, err error) {
	// new AESGCM
	var m *AESGCM
	if m, err = CreateAESGCMforEncript(key, []byte(plainmessage), aad); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	return
}

///////////////////////
//
// Decript by AESGCM
//
///////////////////////

///////////////////////
// ByteArray
///////////////////////

// core
func decriptByteArrayByAESGCMcore(key []byte, crypticmessage []byte, aad []byte) (decriptedmessage []byte, m *AESGCM, err error) {
	// new AESGCM
	if m, err = CreateAESGCMforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncriptedMessage(crypticmessage, aad); err != nil {
		return
	}

	decriptedmessage = m.GetDecriptedMessage()

	return
}

// decript
func DecriptByteArrayByAESGCM(key []byte, crypticmessage []byte, aad []byte) (decriptedmessage []byte, err error) {
	decriptedmessage, _, err = decriptByteArrayByAESGCMcore(key, crypticmessage, aad)

	return
}

///////////////////////
// String
///////////////////////

// core
func decriptStringByAESGCMcore(key []byte, crypticmessage string, aad []byte) (decriptedmessage string, m *AESGCM, err error) {
	// new AESGCM
	if m, err = CreateAESGCMforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncodedEncriptedMessage(crypticmessage, aad); err != nil {
		return
	}

	decriptedmessage = string(m.GetDecriptedMessage())

	return
}

// decript
func DecriptStringByAESGCM(key []byte, crypticmessage string, aad []byte) (decriptedmessage string, err error) {
	decriptedmessage, _, err = decriptStringByAESGCMcore(key, crypticmessage, aad)

	return
}
