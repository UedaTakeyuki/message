# message

An out-of-the-box cryptographic message communication.

## how to use

### Using high-level APIs
```
import(
	"github.com/UedaTakeyuki/message"
)
// original message 
const originalMessage = "some plaintext"

// an aad for AESGCM
var aad = []byte("Some AAD data")

// keys
var key_256 = []byte("01234567890123456789012345678901")
var key_192 = []byte("012345678901234567890123")
var key_128 = []byte("0123456789012345")

// encript by AESCTR with 256 bit key
crypticmessage, mac, err := message.EncriptStringByAESCTR(key_256, originalMessage)

// decript 
decriptedmessage, err2 := message.DecriptStringByAESCTR(key_256, crypticmessage)
```

### Direct use of AES classes
#### 1. encript & decript
```
import(
	"github.com/UedaTakeyuki/message"
)

func encriptAndEncode(plainmessage []byte) (crypticmessage string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey([]byte("01234567890123456789012345678901"))

	// set plainmessage for encription
	m.SetPlainMessage(plainmessage)

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()
	log.Println("crypticmessage:", crypticmessage)

	return
}

func decodeAndDecript(crypticmessage string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey([]byte("01234567890123456789012345678901"))

	// set criptic message string
	m.SetEncodedEncriptedMessage(crypticmessage)

	// get original message from cryptic message
	decreiptedMessage := m.GetDecriptedMessage()
	log.Println("decreiptedMessage:", string(decreiptedMessage))

}

func main(){
	crypticmessage, mac := encriptAndEncode([]byte(originalMessage))
	decodeAndDecript(crypticmessage, mac)
}
```

Output message:   

```
crypticmessage: L0z3LU3pmWNUvGr-w1eSzRLZpcuajcjy84Qa4Zq1
decreiptedMessage: some plaintext
```
#### 2. encript and authenticate & decript and authentication confirm
```
import(
	  "github.com/UedaTakeyuki/message"
)

func encriptAndEncode(plainmessage []byte) (crypticmessage string, mac string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey([]byte("01234567890123456789012345678901"))

	// set plainmessage for encription
	m.SetPlainMessage(plainmessage)

	// get criptic message
	crypticmessage = m.GetEncodedEncriptedMessage()
	log.Println("crypticmessage:", crypticmessage)

	// get Authentication Code of this message
	mac = m.GetPlainMessageMac()
	log.Println("hmac of plaintext:", mac)

	return
}

func decodeAndDecript(crypticmessage string, mac string) {

	// new AESCTR
	m := new(message.AESCTR)

	// set key
	m.SetKey([]byte("01234567890123456789012345678901"))

	// set criptic message string
	m.SetEncodedEncriptedMessage(crypticmessage)

	// get original message from cryptic message
	decreiptedMessage := m.GetDecriptedMessage()
	log.Println("decreiptedMessage:", string(decreiptedMessage))

	// confirm Authentication Code
	result, _ := m.ConfirmMacFromstring(mac)
	log.Println("Confrimation result is", result)
}

func main(){
	crypticmessage, mac := encriptAndEncode([]byte(originalMessage))
	decodeAndDecript(crypticmessage, mac)
}
```

Output message:   

```
crypticmessage: L0z3LU3pmWNUvGr-w1eSzRLZpcuajcjy84Qa4Zq1
hmac of plaintext: cdd1aba74001d40e980de7cee69dc10d8495a609936bc835da4b30cb33ab6f50
decreiptedMessage: some plaintext
Confrimation result is true
```

## supported algorithm
- [x] AES CTR + HMAC (encription: AES CTR, message authentication: HMAC)
- [x] AESGCM (both encription and message authentication are supported by AES GCM)
