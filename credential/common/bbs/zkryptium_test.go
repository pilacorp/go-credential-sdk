package bbs

import "testing"

func TestZKryptiumSignerFromPrivateKeyHexAndEngineRoundTrip(t *testing.T) {
	signer, err := NewZKryptiumSignerFromPrivateKeyHex("66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if got, want := len(signer.PublicKey()), 96; got != want {
		t.Fatalf("public key length = %d, want %d", got, want)
	}

	engine := NewZKryptiumEngine()
	header := []byte("proof-header")
	messages := [][]byte{
		[]byte("msg-1"),
		[]byte("msg-2"),
		[]byte("msg-3"),
	}

	signature, err := signer.Sign(header, messages)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := engine.Verify(signer.PublicKey(), signature, header, messages); err != nil {
		t.Fatalf("verify base signature: %v", err)
	}

	proof, err := engine.ProofGen(signer.PublicKey(), signature, header, []byte("holder-binding"), messages, []int{0, 2})
	if err != nil {
		t.Fatalf("derive proof: %v", err)
	}
	if err := engine.ProofVerify(
		signer.PublicKey(),
		proof,
		header,
		[]byte("holder-binding"),
		[][]byte{messages[0], messages[2]},
		[]int{0, 2},
	); err != nil {
		t.Fatalf("verify derived proof: %v", err)
	}
}
