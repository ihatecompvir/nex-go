package nex

import (
	"bytes"
	"compress/zlib"
	"io/ioutil"
)

// DummyCompression represents no compression
type DummyCompression struct{}

// Compress returns the data as-is
func (compression *DummyCompression) Compress(data []byte) []byte {
	return data
}

// Decompress returns the data as-is
func (compression *DummyCompression) Decompress(data []byte) []byte {
	return data
}

// ZLibCompression represents ZLib compression
type ZLibCompression struct{}

// Compress returns the data as-is (needs to be updated to return ZLib compressed data)
func (compression *ZLibCompression) Compress(data []byte) []byte {
	return data
}

// Decompress returns the data as-is (needs to be updated to return ZLib decompressed data)
func (compression *ZLibCompression) Decompress(data []byte) []byte {
	b := bytes.NewReader(data)
	r, err := zlib.NewReader(b)
	if err != nil {
		return []byte{}
	}
	defer r.Close()

	decompressedData, _ := ioutil.ReadAll(r)
	return decompressedData
}
