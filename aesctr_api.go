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

///////////////////////
//
// Encript by AESCTR
//
///////////////////////

func EncriptByteArrayByAESCTR(key []byte, plainmessage []byte) (crypticmessage []byte, mac []byte, err error) {
	// new AESCTR
	var m *AESCTR
	if m, err = CreateAESCTRforEncript(key, plainmessage); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncriptedMessage()

	// get hmac for authentication
	mac, err = m.GetPlainMessageMacAsByteArray()

	return
}

func EncriptStringByAESCTR(key []byte, plainmessage string) (crypticmessage string, mac string, err error) {
	// new AESCTR
	var m *AESCTR
	if m, err = CreateAESCTRforEncript(key, []byte(plainmessage)); err != nil {
		return
	}

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()

	// get hmac for authentication
	mac, err = m.GetPlainMessageMac()

	return
}

///////////////////////
//
// Decript by AESCTR
//
///////////////////////

///////////////////////
// ByteArray
///////////////////////

// core
func decriptByteArrayByAESCTRcore(key []byte, crypticmessage []byte) (decriptedmessage []byte, m *AESCTR, err error) {
	// new AESCTR
	if m, err = CreateAESCTRforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncriptedMessage(crypticmessage); err != nil {
		return
	}

	decriptedmessage = m.GetDecriptedMessage()

	return
}

// decript
func DecriptByteArrayByAESCTR(key []byte, crypticmessage []byte) (decriptedmessage []byte, err error) {
	decriptedmessage, _, err = decriptByteArrayByAESCTRcore(key, crypticmessage)

	return
}

// decript and auth
func DecriptByteArrayByAESCTRwithAuth(key []byte, crypticmessage []byte, originalmac []byte) (decriptedmessage []byte, authresult bool, err error) {
	var m *AESCTR
	if decriptedmessage, m, err = decriptByteArrayByAESCTRcore(key, crypticmessage); err != nil {
		return
	}
	authresult, err = m.ConfirmMacFromByteArray(originalmac)
	return
}

///////////////////////
// String
///////////////////////

// core
func decriptStringByAESCTRcore(key []byte, crypticmessage string) (decriptedmessage string, m *AESCTR, err error) {
	// new AESCTR
	if m, err = CreateAESCTRforDecript(key); err != nil {
		return
	}
	// set criptic message byteArray
	if err = m.SetEncodedEncriptedMessage(crypticmessage); err != nil {
		return
	}

	decriptedmessage = string(m.GetDecriptedMessage())

	return
}

// decript
func DecriptStringByAESCTR(key []byte, crypticmessage string) (decriptedmessage string, err error) {
	decriptedmessage, _, err = decriptStringByAESCTRcore(key, crypticmessage)

	return
}

// decript and auth
func DecriptStringByAESCTRwithAuth(key []byte, crypticmessage string, originalmac string) (decriptedmessage string, authresult bool, err error) {
	var m *AESCTR
	if decriptedmessage, m, err = decriptStringByAESCTRcore(key, crypticmessage); err != nil {
		return
	}
	authresult, err = m.ConfirmMacFromString(originalmac)
	return
}
