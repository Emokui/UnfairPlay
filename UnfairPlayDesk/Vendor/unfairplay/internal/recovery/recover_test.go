package recovery

import "testing"

func TestEmbeddedRecoveryModelIsSanitized(t *testing.T) {
	if len(rawSourceModel) == 0 || len(rawSourceModel) > 2*1024*1024 {
		t.Fatalf("embedded recovery model size = %d", len(rawSourceModel))
	}
	value, err := loadModelBytes(rawSourceModel)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPrivateRecoveryState(value)
	page := value.pages[0x700000200000]
	if len(page) != int(pageSize) {
		t.Fatal("embedded recovery model lacks executable-path page")
	}
	for index, octet := range page {
		if octet != 0 {
			t.Fatalf("embedded recovery model retains executable-path byte %d", index)
		}
	}
}

func TestRecoverRequiresInputs(t *testing.T) {
	if _, err := Recover(Options{}); err == nil {
		t.Fatal("empty recovery input was accepted")
	}
}

func TestVectorOperationsSupportAliases(t *testing.T) {
	var value state
	value.setVectorLane(2, 0, 32, 3)
	value.setVectorLane(2, 1, 32, 4)
	value.setVectorLane(4, 0, 32, 5)
	value.setVectorLane(4, 1, 32, 6)
	value.vectorUnsignedMultiplyLong(4, 2, 4, 2, 32, false)
	if got := value.vectorLane(4, 0, 64); got != 15 {
		t.Fatalf("lane 0 = %d, want 15", got)
	}
	if got := value.vectorLane(4, 1, 64); got != 24 {
		t.Fatalf("lane 1 = %d, want 24", got)
	}
}
