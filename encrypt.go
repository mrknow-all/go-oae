// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// EncryptingWriter accepts plaintext and writes ciphertext into wrapped writer.
type EncryptingWriter struct {
	// Wrapped writer.
	W io.Writer

	aead       cipher.AEAD
	nonce      []byte
	tagSize    int
	closed     bool
	segmentIdx uint32
	segment    []byte
	offset     int
}

// NewEncryptingWriter returns EncryptingWriter that consumes the plaintext and writes the ciphertext into w. The
// key must be securely stored and must have at least algorithm.KeySize() bytes. The aad is the associated data and may
// be nil. The returned CiphertextHeader must be stored and later passed to the NewDecryptingReader or
// NewDecryptingReadSeeker. W is not closed automatically.
func NewEncryptingWriter(w io.Writer, key []byte, aad []byte, options EncryptOptions) (CiphertextHeader, *EncryptingWriter, error) {
	algorithm := options.Algorithm
	if algorithm == 0 {
		algorithm = DefaultAlgorithm
	}
	segmentSize := options.SegmentSize
	if segmentSize == 0 {
		segmentSize = DefaultSegmentSize
	}

	if segmentSize <= algorithm.tagSize() {
		return CiphertextHeader{}, nil, fmt.Errorf("segment size must be at least %d", algorithm.tagSize()+1)
	}
	if segmentSize > MaxSegmentSize {
		return CiphertextHeader{}, nil, fmt.Errorf("segment size must not be greater than %d", MaxSegmentSize)
	}

	wrapper := &EncryptingWriter{
		W:       w,
		tagSize: algorithm.tagSize(),
		segment: make([]byte, segmentSize),
	}

	var header CiphertextHeader
	header.Algorithm = algorithm
	header.SegmentSize = segmentSize

	keySize := algorithm.KeySize()
	if len(key) < keySize {
		return CiphertextHeader{}, nil, fmt.Errorf("key must be at least %d bytes", keySize)
	}
	header.Salt = make([]byte, algorithm.saltSize())
	if _, err := rand.Read(header.Salt); err != nil {
		return CiphertextHeader{}, nil, fmt.Errorf("could not get random: %w", err)
	}
	derivedKeyR := hkdf.New(algorithm.hasher(), key, header.Salt, aad)
	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(derivedKeyR, derivedKey); err != nil {
		return CiphertextHeader{}, nil, fmt.Errorf("could not derive key: %w", err)
	}
	aead, err := algorithm.aead(derivedKey)
	if err != nil {
		return CiphertextHeader{}, nil, fmt.Errorf("could not init cipher: %w", err)
	}
	wrapper.aead = aead
	// 4 bytes for segment size + 1 byte for final prefix.
	noncePrefixLen := algorithm.nonceSize() - 5
	header.NoncePrefix = make([]byte, noncePrefixLen)
	if _, err := rand.Read(header.NoncePrefix); err != nil {
		return CiphertextHeader{}, nil, fmt.Errorf("could not get random: %w", err)
	}
	wrapper.nonce = make([]byte, algorithm.nonceSize())
	copy(wrapper.nonce, header.NoncePrefix)

	return header, wrapper, nil
}

// Write encrypts plaintext p and writes full ciphertext segments into the wrapped writer. Errors from wrapped writer
// are returned as is.
func (e *EncryptingWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("writer is closed")
	}

	n := 0
	for {
		free := len(e.segment) - e.tagSize - e.offset
		l := len(p) - n
		// Do not call writeSegment even if the segment becomes full, because we do not know if this call was the last
		// Write() call.
		if free >= l {
			copy(e.segment[e.offset:], p[n:])
			n += l
			e.offset += l
			return n, nil
		}
		copy(e.segment[e.offset:], p[n:n+free])
		n += free
		e.offset += free
		err := e.writeSegment(false)
		e.offset = 0
		if err != nil {
			return n, err
		}
		e.segmentIdx++
		if e.segmentIdx >= MaxNumSegments {
			maxPlaintextLen := int64(len(e.segment)-e.tagSize) * MaxNumSegments
			return n, fmt.Errorf("cannot encrypt more than %d bytes", maxPlaintextLen)
		}
	}
}

// Close writes the last ciphertext segment into the wrapped writer, but does not close it. Calling Close the second
// time is a no-op.
func (e *EncryptingWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.writeSegment(true)
}

func (e *EncryptingWriter) writeSegment(isLast bool) error {
	appendToNonce(e.nonce, e.segmentIdx, isLast)
	e.aead.Seal(e.segment[:0], e.nonce, e.segment[:e.offset], nil)
	_, err := e.W.Write(e.segment[:e.offset+e.tagSize])
	return err
}

// NewEncryptingWriterWithHeader is a helper which creates a new EncryptingWriter and then writes the header before
// the ciphertext. See NewEncryptingWriter for details.
func NewEncryptingWriterWithHeader(w io.Writer, key []byte, aad []byte, options EncryptOptions) (*EncryptingWriter, error) {
	header, ew, err := NewEncryptingWriter(w, key, aad, options)
	if err != nil {
		return nil, err
	}
	if err := header.MarshalTo(w); err != nil {
		return nil, err
	}
	return ew, nil
}
