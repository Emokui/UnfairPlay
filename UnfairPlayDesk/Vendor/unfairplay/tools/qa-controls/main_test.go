package main

import "testing"

func TestValidateManifest(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	manifest := qaManifest{Schema: qaSchema, Controls: []qaControl{{
		Name: "control", Capture: "/private/capture", ExpectedModelSHA256: hash,
	}}}
	if err := validateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Controls = []qaControl{{Name: "verify", IPA: "/private/App.ipa", Model: "/private/model.bin"}}
	if err := validateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Controls[0].Capture = "/private/capture"
	if err := validateManifest(manifest); err == nil {
		t.Fatal("accepted mixed recover and verify control")
	}
	manifest.Controls[0].Capture = ""
	manifest.Controls = append(manifest.Controls, manifest.Controls[0])
	if err := validateManifest(manifest); err == nil {
		t.Fatal("accepted duplicate QA control")
	}
}

func TestCheckControl(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	control := qaControl{
		Name: "control", ExpectedModelSHA256: hash, ExpectedIPASHA256: hash,
		ExpectedEvaluatorSHA256: hash, ExpectedReferenceSource: "embedded-profile",
		ExpectedImages: 2, ExpectedPages: 3,
	}
	result := recoveryResult{
		Success: true, DecryptedIPASHA256: hash, EvaluatorSourceSHA256: hash,
		ReferenceCodeSource: "embedded-profile", EncryptedImages: 2, DecryptedPages: 3,
	}
	if err := checkControl(control, result, hash); err != nil {
		t.Fatal(err)
	}
	result.DecryptedPages++
	if err := checkControl(control, result, hash); err == nil {
		t.Fatal("accepted changed QA result")
	}
}
