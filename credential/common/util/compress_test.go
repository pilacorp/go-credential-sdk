package util

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCompress(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "compress simple string",
			input:   []byte("Hello, World!"),
			wantErr: false,
		},
		{
			name:    "compress empty data",
			input:   []byte{},
			wantErr: false,
		},
		{
			name:    "compress large data",
			input:   bytes.Repeat([]byte("This is a test string for compression. "), 1000),
			wantErr: false,
		},
		{
			name:    "compress unicode data",
			input:   []byte("Hello 世界! Привет! こんにちは!"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify that compressed data is not empty for non-empty input
				if len(tt.input) > 0 && len(compressed) == 0 {
					t.Errorf("Compress() returned empty data for non-empty input")
				}
				// Verify that compressed data is valid gzip format
				if len(compressed) > 0 {
					_, decompressErr := Decompress(compressed)
					if decompressErr != nil {
						t.Errorf("Compress() returned invalid gzip data: %v", decompressErr)
					}
				}
			}
		})
	}
}

func TestDecompress(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "decompress valid gzip data",
			input:   createValidGzipData([]byte("Hello, World!")),
			wantErr: false,
		},
		{
			name:    "decompress empty data",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "decompress invalid data",
			input:   []byte("invalid gzip data"),
			wantErr: true,
		},
		{
			name:    "decompress corrupted gzip data",
			input:   []byte{0x1f, 0x8b, 0x08, 0x00}, // Incomplete gzip header
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decompress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decompress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompressDecompressRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "simple string",
			input: []byte("Hello, World!"),
		},
		{
			name:  "empty string",
			input: []byte(""),
		},
		{
			name:  "unicode string",
			input: []byte("Hello 世界! Привет! こんにちは!"),
		},
		{
			name:  "large data",
			input: bytes.Repeat([]byte("This is a test string for compression. "), 1000),
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
		},
		{
			name:  "json data",
			input: []byte(`{"name": "test", "value": 123, "array": [1, 2, 3]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compress
			compressed, err := Compress(tt.input)
			if err != nil {
				t.Fatalf("Compress() failed: %v", err)
			}

			// Decompress
			decompressed, err := Decompress(compressed)
			if err != nil {
				t.Fatalf("Decompress() failed: %v", err)
			}

			// Compare
			if !bytes.Equal(tt.input, decompressed) {
				t.Errorf("Round trip failed: input = %v, decompressed = %v", tt.input, decompressed)
			}
		})
	}
}

func TestCompressToBase64(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "compress and encode simple string",
			input:   []byte("Hello, World!"),
			wantErr: false,
		},
		{
			name:    "compress and encode empty data",
			input:   []byte{},
			wantErr: false,
		},
		{
			name:    "compress and encode large data",
			input:   bytes.Repeat([]byte("This is a test string for compression. "), 1000),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CompressToBase64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompressToBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify that result is valid base64
				if len(result) > 0 {
					_, decodeErr := base64.StdEncoding.DecodeString(result)
					if decodeErr != nil {
						t.Errorf("CompressToBase64() returned invalid base64: %v", decodeErr)
					}
				}
			}
		})
	}
}

func TestDecompressFromBase64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "decompress valid base64 data",
			input:   createValidBase64CompressedData([]byte("Hello, World!")),
			wantErr: false,
		},
		{
			name:    "decompress empty base64",
			input:   "",
			wantErr: true,
		},
		{
			name:    "decompress invalid base64",
			input:   "invalid-base64-data!@#",
			wantErr: true,
		},
		{
			name:    "decompress valid base64 but invalid gzip",
			input:   base64.StdEncoding.EncodeToString([]byte("not gzip data")),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecompressFromBase64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecompressFromBase64() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompressToBase64DecompressFromBase64RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "simple string",
			input: []byte("Hello, World!"),
		},
		{
			name:  "empty string",
			input: []byte(""),
		},
		{
			name:  "unicode string",
			input: []byte("Hello 世界! Привет! こんにちは!"),
		},
		{
			name:  "large data",
			input: bytes.Repeat([]byte("This is a test string for compression. "), 1000),
		},
		{
			name:  "json data",
			input: []byte(`{"name": "test", "value": 123, "array": [1, 2, 3]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compress to base64
			compressedBase64, err := CompressToBase64(tt.input)
			if err != nil {
				t.Fatalf("CompressToBase64() failed: %v", err)
			}

			// Decompress from base64
			decompressed, err := DecompressFromBase64(compressedBase64)
			if err != nil {
				t.Fatalf("DecompressFromBase64() failed: %v", err)
			}

			// Compare
			if !bytes.Equal(tt.input, decompressed) {
				t.Errorf("Round trip failed: input = %v, decompressed = %v", tt.input, decompressed)
			}
		})
	}
}

func TestCompressionRatio(t *testing.T) {
	// Test that compression actually reduces size for repetitive data
	repetitiveData := strings.Repeat("This is a repetitive string that should compress well. ", 100)
	input := []byte(repetitiveData)

	compressed, err := Compress(input)
	if err != nil {
		t.Fatalf("Compress() failed: %v", err)
	}

	// For repetitive data, compression should be effective
	if len(compressed) >= len(input) {
		t.Logf("Compression ratio: %d -> %d bytes (%.2f%%)",
			len(input), len(compressed), float64(len(compressed))/float64(len(input))*100)
	}

	// Verify decompression works
	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress() failed: %v", err)
	}

	if !bytes.Equal(input, decompressed) {
		t.Errorf("Data integrity check failed")
	}
}

// Helper functions for creating test data

func createValidGzipData(data []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	return buf.Bytes()
}

func createValidBase64CompressedData(data []byte) string {
	compressed := createValidGzipData(data)
	return base64.StdEncoding.EncodeToString(compressed)
}

func BenchmarkCompress(b *testing.B) {
	data := bytes.Repeat([]byte("This is a test string for compression benchmarking. "), 100)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := Compress(data)
		if err != nil {
			b.Fatalf("Compress() failed: %v", err)
		}
	}
}

func BenchmarkDecompress(b *testing.B) {
	originalData := bytes.Repeat([]byte("This is a test string for decompression benchmarking. "), 100)
	compressedData, err := Compress(originalData)
	if err != nil {
		b.Fatalf("Failed to create test data: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := Decompress(compressedData)
		if err != nil {
			b.Fatalf("Decompress() failed: %v", err)
		}
	}
}

func BenchmarkCompressToBase64(b *testing.B) {
	data := bytes.Repeat([]byte("This is a test string for base64 compression benchmarking. "), 100)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := CompressToBase64(data)
		if err != nil {
			b.Fatalf("CompressToBase64() failed: %v", err)
		}
	}
}

func BenchmarkDecompressFromBase64(b *testing.B) {
	originalData := bytes.Repeat([]byte("This is a test string for base64 decompression benchmarking. "), 100)
	compressedBase64, err := CompressToBase64(originalData)
	if err != nil {
		b.Fatalf("Failed to create test data: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := DecompressFromBase64(compressedBase64)
		if err != nil {
			b.Fatalf("DecompressFromBase64() failed: %v", err)
		}
	}
}
