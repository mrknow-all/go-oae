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
func (a Algorithm) CiphertextLength(segmentSize int, plaintextLength int64) (int64, error) {
	if segmentSize <= 0 {
		return 0, errors.New("segmentSize must be positive")
	}
	if plaintextLength < 0 {
		return 0, errors.New("plaintextLength must be non-negative")
	}

	tagSize := int64(a.tagSize())
	if plaintextLength == 0 {
		// The empty plaintext must be authenticated.
		return tagSize, nil
	}

	segmentPlaintext := int64(segmentSize) - tagSize
	numSegments := (plaintextLength + segmentPlaintext - 1) / segmentPlaintext
	return plaintextLength + numSegments*tagSize, nil
}

// PlaintextLength returns the length of the plaintext which will be read during decryption.
func (a Algorithm) PlaintextLength(segmentSize int, ciphertextLength int64) (int64, error) {
	if segmentSize <= 0 {
		return 0, errors.New("segmentSize must be positive")
	}
	if ciphertextLength < 0 {
		return 0, errors.New("plaintextLength must be positive")
	}
	tagSize := int64(a.tagSize())
	if ciphertextLength < tagSize {
		return 0, nil
	}

	numSegments := (ciphertextLength + int64(segmentSize) - 1) / int64(segmentSize)
	return ciphertextLength - numSegments*tagSize, nil
}

// Range is a half-open range of indices (the end is non-inclusive, i.e. [Begin, End))
type Range struct {
	Begin int64
	End   int64
}

func (r Range) Validate() error {
	if r.Begin < 0 {
		return errors.New("start must be non-negative")
	}
	if r.End < 0 {
		return errors.New("end must be non-negative")
	}
	if r.Begin > r.End {
		return errors.New("start must not be greater than end")
	}
	return nil
}

// CiphertextRange returns the range that must be read in order to decrypt the plaintextRange slice of the plaintext.
// plaintextTotal must be the total size of the encrypted plaintext.
func (a Algorithm) CiphertextRange(segmentSize int, plaintextRange Range, plaintextTotal int64) (Range, error) {
	if segmentSize <= 0 {
		return Range{}, errors.New("segmentSize must be positive")
	}

	if err := plaintextRange.Validate(); err != nil {
		return Range{}, err
	}
	if plaintextRange.End > plaintextTotal {
		return Range{}, errors.New("end must be smaller than plaintextTotal")
	}
	if plaintextTotal < 0 {
		return Range{}, errors.New("plaintextTotal must be non-negative")
	}
	ciphertextTotal, err := a.CiphertextLength(segmentSize, plaintextTotal)
	if err != nil {
		return Range{}, err
	}
	segmentLen := int64(segmentSize - a.tagSize())
	// See DecryptingReadSeeker.Seek() for details on off by one offset.
	if plaintextRange.Begin > 0 {
		plaintextRange.Begin--
	}
	startIdx := plaintextRange.Begin / segmentLen
	ciphertextStart := startIdx * int64(segmentSize)
	if ciphertextStart > ciphertextTotal {
		ciphertextStart = ciphertextTotal
	}
	endIdx := (plaintextRange.End + segmentLen - 1) / segmentLen
	if endIdx == startIdx {
		// segmentReader will read at least two segments
		endIdx++
	}
	// segmentReader reads the next segment
	ciphertextEnd := (endIdx + 1) * int64(segmentSize)
	if ciphertextEnd > ciphertextTotal {
		ciphertextEnd = ciphertextTotal
	}
	return Range{ciphertextStart, ciphertextEnd}, nil
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
