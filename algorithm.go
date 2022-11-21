// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// Algorithm is the algorithm used for key derivation + encryption.
type Algorithm int

const (
	AesGcm128Sha256 Algorithm = iota + 1
	AesGcm256Sha256
	ChaCha20Poly1305Sha256

	numAlgorithms
)

// KeySize returns the minimum length of the key which must be passed to the NewEncryptingWriter.
func (a Algorithm) KeySize() int {
	switch a {
	case AesGcm128Sha256:
		return 16
	case AesGcm256Sha256:
		return 32
	case ChaCha20Poly1305Sha256:
		return 32
	default:
		return -1
	}
}

// CiphertextLength returns the length of the ciphertext which will be produced by encryption process.
//
// NOTE: This function does not account for the length of CiphertextHeader which must be stored either alongside
// the ciphertext or in the separate metadata storage.
func (a Algorithm) CiphertextLength(segmentSize int, plaintextLength int64) int64 {
	if segmentSize <= 0 {
		panic("segmentSize must be positive")
	}
	if plaintextLength < 0 {
		panic("plaintextLength must be non-negative")
	}

	tagSize := int64(a.tagSize())
	if plaintextLength == 0 {
		// The empty plaintext must be authenticated.
		return tagSize
	}

	segmentPlaintext := int64(segmentSize) - tagSize
	numSegments := (plaintextLength + segmentPlaintext - 1) / segmentPlaintext
	return plaintextLength + numSegments*tagSize
}

// PlaintextLength returns the length of the plaintext which will be read during decryption.
func (a Algorithm) PlaintextLength(segmentSize int, ciphertextLength int64) int64 {
	if segmentSize <= 0 {
		panic("segmentSize must be positive")
	}
	if ciphertextLength < 0 {
		panic("plaintextLength must be positive")
	}
	tagSize := int64(a.tagSize())
	if ciphertextLength < tagSize {
		// Do not panic here.
		return 0
	}

	numSegments := (ciphertextLength + int64(segmentSize) - 1) / int64(segmentSize)
	return ciphertextLength - numSegments*tagSize
}

// CiphertextRange returns the range that must be read in order to decrypt the [plaintextStart:plaintextEnd] slice of
// the plaintext (plaintextEnd is included in the range). plaintextTotal must be the total size of encrypted plaintext
func (a Algorithm) CiphertextRange(segmentSize int, plaintextStart int64, plaintextEnd int64, plaintextTotal int64) (ciphertextStart int64, ciphertextEnd int64) {
	if segmentSize <= 0 {
		panic("segmentSize must be positive")
	}
	if plaintextStart < 0 {
		panic("plaintextStart must be non-negative")
	}
	if plaintextEnd < 0 {
		panic("plaintextEnd must be non-negative")
	}
	if plaintextStart > plaintextEnd {
		panic("plaintextStart must not be greater than plaintextEnd")
	}
	if plaintextEnd >= plaintextTotal {
		panic("plaintextEnd must be smaller than plaintextTotal")
	}
	if plaintextTotal < 0 {
		panic("plaintextTotal must be non-negative")
	}

	ciphertextTotal := a.CiphertextLength(segmentSize, plaintextTotal)
	segmentLen := int64(segmentSize - a.tagSize())
	startIdx := plaintextStart / segmentLen
	ciphertextStart = startIdx * int64(segmentSize)
	if ciphertextStart >= ciphertextTotal {
		ciphertextStart = ciphertextTotal - 1
	}
	endIdx := (plaintextEnd + segmentLen - 1) / segmentLen
	ciphertextEnd = endIdx * int64(segmentSize)
	if ciphertextEnd >= ciphertextTotal {
		ciphertextEnd = ciphertextTotal - 1
	}
	return
}

func (a Algorithm) tagSize() int {
	return 16
}

func (a Algorithm) nonceSize() int {
	return 12
}

func (a Algorithm) saltSize() int {
	return 16
}

func (a Algorithm) aead(key []byte) (cipher.AEAD, error) {
	switch a {
	case AesGcm128Sha256, AesGcm256Sha256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case ChaCha20Poly1305Sha256:
		return chacha20poly1305.New(key)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func (a Algorithm) hasher() func() hash.Hash {
	return sha256.New
}

func appendToNonce(nonce []byte, segmentIdx uint32, isLast bool) {
	l := len(nonce)
	nonce[l-5] = byte(segmentIdx)
	nonce[l-4] = byte(segmentIdx >> 8)
	nonce[l-3] = byte(segmentIdx >> 16)
	nonce[l-2] = byte(segmentIdx >> 24)
	nonce[l-1] = 0
	if isLast {
		nonce[l-1] = 1
	}
}
