package bbs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// ZKryptiumSigner produces BBS signatures via the Rust zkryptium bridge.
type ZKryptiumSigner struct {
	privateKeyHex string
	publicKey     []byte
}

// ZKryptiumEngine implements the BBS Engine (verify, proof gen/verify) via the
// Rust zkryptium bridge.
type ZKryptiumEngine struct{}

type zkryptiumRequest struct {
	Op                    string   `json:"op"`
	PrivateKeyHex         string   `json:"privateKeyHex,omitempty"`
	PublicKeyHex          string   `json:"publicKeyHex,omitempty"`
	SignatureHex          string   `json:"signatureHex,omitempty"`
	ProofHex              string   `json:"proofHex,omitempty"`
	HeaderHex             string   `json:"headerHex,omitempty"`
	PresentationHeaderHex string   `json:"presentationHeaderHex,omitempty"`
	MessagesHex           []string `json:"messagesHex,omitempty"`
	DisclosedIndexes      []int    `json:"disclosedIndexes,omitempty"`
}

type zkryptiumResponse struct {
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
	SignatureHex string `json:"signatureHex,omitempty"`
	ProofHex     string `json:"proofHex,omitempty"`
	OK           bool   `json:"ok,omitempty"`
	Error        string `json:"error,omitempty"`
}

var (
	zkBridgeOnce sync.Once
	zkBridgePath string
	zkBridgeErr  error
)

// NewZKryptiumSignerFromPrivateKeyHex builds a signer from a hex-encoded BLS12-381 private key.
func NewZKryptiumSignerFromPrivateKeyHex(privateKeyHex string) (*ZKryptiumSigner, error) {
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	resp, err := runZKryptium(zkryptiumRequest{
		Op:            "public_key",
		PrivateKeyHex: privateKeyHex,
	})
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(resp.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("bbs: decode zkryptium public key: %w", err)
	}
	return &ZKryptiumSigner{
		privateKeyHex: privateKeyHex,
		publicKey:     pub,
	}, nil
}

// NewZKryptiumSignerFromPrivateKeyBytes builds a signer from raw BLS12-381 private key bytes.
func NewZKryptiumSignerFromPrivateKeyBytes(privateKey []byte) (*ZKryptiumSigner, error) {
	return NewZKryptiumSignerFromPrivateKeyHex(hex.EncodeToString(privateKey))
}

// Sign produces a BBS signature over messages bound to header.
func (s *ZKryptiumSigner) Sign(header []byte, messages [][]byte) ([]byte, error) {
	resp, err := runZKryptium(zkryptiumRequest{
		Op:            "sign",
		PrivateKeyHex: s.privateKeyHex,
		PublicKeyHex:  hex.EncodeToString(s.publicKey),
		HeaderHex:     hex.EncodeToString(header),
		MessagesHex:   encodeMessagesHex(messages),
	})
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(resp.SignatureHex)
}

// PublicKey returns the compressed BLS12-381 G2 public key.
func (s *ZKryptiumSigner) PublicKey() []byte {
	return append([]byte{}, s.publicKey...)
}

// NewZKryptiumEngine returns a BBS engine backed by the zkryptium bridge.
func NewZKryptiumEngine() *ZKryptiumEngine {
	return &ZKryptiumEngine{}
}

// Verify checks a BBS base signature over messages bound to header.
func (b *ZKryptiumEngine) Verify(publicKey, signature, header []byte, messages [][]byte) error {
	_, err := runZKryptium(zkryptiumRequest{
		Op:           "verify",
		PublicKeyHex: hex.EncodeToString(publicKey),
		SignatureHex: hex.EncodeToString(signature),
		HeaderHex:    hex.EncodeToString(header),
		MessagesHex:  encodeMessagesHex(messages),
	})
	return err
}

// ProofGen derives a BBS proof disclosing the messages at disclosedIndexes.
func (b *ZKryptiumEngine) ProofGen(publicKey, signature, header, presentationHeader []byte, messages [][]byte, disclosedIndexes []int) ([]byte, error) {
	resp, err := runZKryptium(zkryptiumRequest{
		Op:                    "proof_gen",
		PublicKeyHex:          hex.EncodeToString(publicKey),
		SignatureHex:          hex.EncodeToString(signature),
		HeaderHex:             hex.EncodeToString(header),
		PresentationHeaderHex: hex.EncodeToString(presentationHeader),
		MessagesHex:           encodeMessagesHex(messages),
		DisclosedIndexes:      append([]int{}, disclosedIndexes...),
	})
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(resp.ProofHex)
}

// ProofVerify checks a BBS derived proof against the disclosed messages.
func (b *ZKryptiumEngine) ProofVerify(publicKey, proof, header, presentationHeader []byte, disclosedMessages [][]byte, disclosedIndexes []int) error {
	_, err := runZKryptium(zkryptiumRequest{
		Op:                    "proof_verify",
		PublicKeyHex:          hex.EncodeToString(publicKey),
		ProofHex:              hex.EncodeToString(proof),
		HeaderHex:             hex.EncodeToString(header),
		PresentationHeaderHex: hex.EncodeToString(presentationHeader),
		MessagesHex:           encodeMessagesHex(disclosedMessages),
		DisclosedIndexes:      append([]int{}, disclosedIndexes...),
	})
	return err
}

func encodeMessagesHex(messages [][]byte) []string {
	out := make([]string, len(messages))
	for i, msg := range messages {
		out[i] = hex.EncodeToString(msg)
	}
	return out
}

func runZKryptium(req zkryptiumRequest) (*zkryptiumResponse, error) {
	bin, err := zkryptiumBridgeBinary()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("bbs: marshal zkryptium request: %w", err)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("bbs: zkryptium bridge: %s", strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("bbs: zkryptium bridge: %w", err)
	}
	var resp zkryptiumResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("bbs: decode zkryptium response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("bbs: zkryptium: %s", resp.Error)
	}
	return &resp, nil
}

func zkryptiumBridgeBinary() (string, error) {
	zkBridgeOnce.Do(func() {
		if override := os.Getenv("BBS_ZKRYPTIUM_BRIDGE_BIN"); override != "" {
			zkBridgePath = override
			return
		}
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			zkBridgeErr = fmt.Errorf("bbs: resolve zkryptium bridge path")
			return
		}
		bridgeDir := filepath.Join(filepath.Dir(file), "zkryptium-bridge")
		manifest := filepath.Join(bridgeDir, "Cargo.toml")
		cmd := exec.Command("cargo", "build", "--quiet", "--release", "--manifest-path", manifest)
		cmd.Dir = bridgeDir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if stderr.Len() > 0 {
				zkBridgeErr = fmt.Errorf("bbs: build zkryptium bridge: %s", strings.TrimSpace(stderr.String()))
			} else {
				zkBridgeErr = fmt.Errorf("bbs: build zkryptium bridge: %w", err)
			}
			return
		}
		name := "zkryptium-bridge"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		zkBridgePath = filepath.Join(bridgeDir, "target", "release", name)
	})
	if zkBridgeErr != nil {
		return "", zkBridgeErr
	}
	return zkBridgePath, nil
}
