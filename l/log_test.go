package l

import (
	"testing"
)

func TestLog(t *testing.T) {
	ll := New()
	ll.Info("log without field")
	ll.Info("longer sample info log witch dummy text", String("field", "string value"))
	ll.Error("sample error log", String("val", "many fields"), Int("int", 12))
	t.Fail()
}
