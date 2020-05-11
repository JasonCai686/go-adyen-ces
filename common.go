package adyen

func NewFingerprintString() string {
    fp := New()
    fp.random()
    return fp.String()
}
