package adyen

import (
    "testing"
    "zhaojunlike/logger"
)

func TestFingerprint_String(t *testing.T) {
    fp := New()
    logger.Info("fp: %v", fp.String())
}
