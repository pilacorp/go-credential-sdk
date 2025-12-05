package util

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
)

func Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	gz := gzip.NewWriter(&buf)

	_, err := gz.Write(data)
	if err != nil {
		return nil, err
	}

	err = gz.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Decompress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)

	gz, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	return io.ReadAll(gz)
}

func CompressToBase64(data []byte) (string, error) {
	compressed, err := Compress(data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(compressed), nil
}

func DecompressFromBase64(data string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return Decompress(compressed)
}

func CompressToBase64URL(data []byte) (string, error) {
	compressed, err := Compress(data)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(compressed), nil
}

func DecompressFromBase64URL(data string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return Decompress(compressed)
}
