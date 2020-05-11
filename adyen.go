package adyen

import (
    "crypto/aes"
    "encoding/base64"
    "encoding/json"
    "github.com/pion/dtls/v2/pkg/crypto/ccm"
    "math/rand"
    "reflect"
    "strings"
    "zhaojunlike/common/encrypt"
)

type Adyen struct {
    rsa     *encrypt.Rsa
    prefix  string
    version string

    rsaEncryptAesVal string
    //iv
    aesKey     []byte
    _tagSize   int
    _nonceSize int
    _debug     bool
    aesNonce   []byte
}

type Data struct {
    Activate            string `json:"activate"`
    CardType            string `json:"cardType"`
    Cvc                 string `json:"cvc"`
    Deactivate          string `json:"deactivate"`
    DfValue             string `json:"dfValue"`
    ExpiryMonth         string `json:"expiryMonth"`
    ExpiryYear          string `json:"expiryYear"`
    Generationtime      string `json:"generationtime"`
    HolderName          string `json:"holderName"`
    InitializeCount     string `json:"initializeCount"`
    LuhnCount           string `json:"luhnCount"`
    LuhnOkCount         string `json:"luhnOkCount"`
    LuhnSameLengthCount string `json:"luhnSameLengthCount"`
    Number              string `json:"number"`
    PaymentMethodID     string `json:"paymentMethodId"`
    Referrer            string `json:"referrer"`
    SjclStrength        string `json:"sjclStrength"`
}

func NewAdYen(publicKey string) *Adyen {
    yen := &Adyen{}

    yen.rsa = encrypt.NewRsa()
    yen.prefix = "adyenjs_"
    yen.version = "0_1_21"
    yen.aesKey = make([]byte, 32)
    yen._tagSize = 8
    yen._nonceSize = 12

    //如果密钥错误直接推出
    err := yen.rsa.SetPublicKey(publicKey, 10001)
    if err != nil {
        panic(err)
    }
    return yen
}

func (yen *Adyen) marshal(data interface{}) []byte {
    if reflect.TypeOf(data).String() == "string" {
        return []byte(data.(string))
    }
    bytes, _ := json.Marshal(data)
    return bytes
}

//validate order info
func (yen *Adyen) validate(data interface{}) error {
    return nil
}

//encrypt
func (yen *Adyen) Encrypt(data interface{}) (string, error) {
    bytes := yen.marshal(data)

    //1. aes
    yen.init()

    block, err := aes.NewCipher(yen.aesKey)
    if err != nil {
        return "", err
    }

    //iv
    cmer, err := ccm.NewCCM(block, yen._tagSize, len(yen.aesNonce))
    if err != nil {
        return "", err
    }

    // encode aes
    by := cmer.Seal(nil, yen.aesNonce, bytes, nil)
    cr := append(yen.aesNonce, by...)
    str := base64.StdEncoding.EncodeToString(cr)

    //rsa encrypt aes.key
    rsaCp, err := yen.rsa.Encrypt(str, "base64")
    if err != nil {
        return "", err
    }
    yen.rsaEncryptAesVal = rsaCp

    prefix := yen.prefix + yen.version + "$"

    arr := []string{prefix, yen.rsaEncryptAesVal, "$", str}
    return strings.Join(arr, ""), nil
}

func (yen *Adyen) debug() {
    yen._debug = true
    yen.aesKey = []byte{
        127, 224, 127, 167, 156, 169, 154, 41,
        81, 190, 144, 126, 73, 39, 196, 174,
        25, 36, 25, 57, 104, 217, 191, 197,
        123, 98, 128, 54, 227, 10, 209, 191,
    }
    yen.aesNonce = []byte{
        8, 36, 215, 7, 188,
        177, 45, 215, 149, 4,
        96, 248,
    }
}
func (yen *Adyen) init() {
    if yen._debug {
        return
    }
    yen.aesKey = yen.random(32)
    yen.aesNonce = yen.random(12)

}
func (yen *Adyen) random(len int) []byte {
    ak := make([]byte, len)
    _, _ = rand.Read(ak)
    return ak
}
