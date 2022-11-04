// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"bytes"
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

	common
	closed  bool
	segment []byte
}

var _ io.Writer = (*EncryptingWriter)(nil)

type common struct {
	aead       cipher.AEAD
	nonce      []byte
	tagSize    int
	segmentIdx int
	offset     int
}

// NewEncryptingWriter returns EncryptingWriter that consumes the plaintext and writes the ciphertext into w. The
// key must be securely stored and must have at least algorithm.KeySize() bytes. The aad is the associated data and may
// be nil. The returned CiphertextHeader must be stored and later passed to the NewDecryptingReader or
// NewDecryptingReadSeeker. W is not closed automatically.
func NewEncryptingWriter(w io.Writer, key []byte, aad []byte, options EncryptOptions) (CiphertextHeader, *EncryptingWriter, error) {
	wrapper := &EncryptingWriter{W: w}
	header, err := initCommon(&wrapper.common, key, aad, options)
	if err != nil {
		return CiphertextHeader{}, nil, err
	}
	wrapper.segment = make([]byte, header.SegmentSize)
	return header, wrapper, nil
}

func initCommon(c *common, key []byte, aad []byte, options EncryptOptions) (CiphertextHeader, error) {
	algorithm := options.Algorithm
	if algorithm == 0 {
		algorithm = DefaultAlgorithm
	}
	segmentSize := options.SegmentSize
	if segmentSize == 0 {
		segmentSize = DefaultSegmentSize
	}

	if segmentSize <= algorithm.tagSize() {
		return CiphertextHeader{}, fmt.Errorf("segment size must be at least %d", algorithm.tagSize()+1)
	}
	if segmentSize > MaxSegmentSize {
		return CiphertextHeader{}, fmt.Errorf("segment size must not be greater than %d", MaxSegmentSize)
	}

	c.tagSize = algorithm.tagSize()

	var header CiphertextHeader
	header.Algorithm = algorithm
	header.SegmentSize = segmentSize

	keySize := algorithm.KeySize()
	if len(key) < keySize {
		return CiphertextHeader{}, fmt.Errorf("key must be at least %d bytes", keySize)
	}
	header.Salt = make([]byte, algorithm.saltSize())
	if _, err := rand.Read(header.Salt); err != nil {
		return CiphertextHeader{}, fmt.Errorf("could not get random: %w", err)
	}
	derivedKeyR := hkdf.New(algorithm.hasher(), key, header.Salt, aad)
	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(derivedKeyR, derivedKey); err != nil {
		return CiphertextHeader{}, fmt.Errorf("could not derive key: %w", err)
	}
	aead, err := algorithm.aead(derivedKey)
	if err != nil {
		return CiphertextHeader{}, fmt.Errorf("could not init cipher: %w", err)
	}
	c.aead = aead
	// 4 bytes for segment size + 1 byte for final prefix.
	noncePrefixLen := algorithm.nonceSize() - 5
	header.NoncePrefix = make([]byte, noncePrefixLen)
	if _, err := rand.Read(header.NoncePrefix); err != nil {
		return CiphertextHeader{}, fmt.Errorf("could not get random: %w", err)
	}
	c.nonce = make([]byte, algorithm.nonceSize())
	copy(c.nonce, header.NoncePrefix)

	return header, nil
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
	appendToNonce(e.nonce, uint32(e.segmentIdx), isLast)
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

// EncryptingReader reads plaintext and returns ciphertext.
type EncryptingReader struct {
	// Wrapped reader.
	R io.Reader

	common
	segment segmentReader
	// prefix is the serialized header
	prefix       []byte
	prefixOffset int
}

var _ io.Reader = (*EncryptingReader)(nil)

// NewEncryptingReader returns EncryptingReader that reads the plaintext and returns the ciphertext to caller. The
// key must be securely stored and must have at least algorithm.KeySize() bytes. The aad is the associated data and may
// be nil. The returned CiphertextHeader must be stored and later passed to the NewDecryptingReader or
// NewDecryptingReadSeeker. R is not closed automatically.
//
// EncryptingReader is a pull style interface which is very useful e.g. in case when you need to encrypt the file when
// uploading it via http.Client. While you could use EncryptingWriter and two io.Pipes for this case, this is a cleaner
// solution.
func NewEncryptingReader(r io.Reader, key []byte, aad []byte, options EncryptOptions) (CiphertextHeader, *EncryptingReader, error) {
	wrapper := &EncryptingReader{R: r}
	header, err := initCommon(&wrapper.common, key, aad, options)
	if err != nil {
		return CiphertextHeader{}, nil, err
	}
	wrapper.segment = newSegmentReader(header.SegmentSize)
	return header, wrapper, nil
}

// Read reads plaintext from wrapped reader, encrypts it and returns ciphertext. Errors from wrapped reader are returned
// as is.
func (e *EncryptingReader) Read(p []byte) (int, error) {
	n := 0
	if e.prefixOffset < len(e.prefix) {
		copy(p, e.prefix[e.prefixOffset:])
		available := len(e.prefix) - e.prefixOffset
		if len(p) <= available {
			e.prefixOffset += len(p)
			return len(p), nil
		} else {
			n += available
			e.prefixOffset = len(e.prefix)
		}
	}
	for {
		curSegment := e.segment.current(e.tagSize)
		if curSegment != nil {
			available := len(curSegment) - e.offset
			l := len(p) - n
			if available >= l {
				copy(p[n:], curSegment[e.offset:e.offset+available])
				n += l
				e.offset += l
				return n, nil
			}
			copy(p[n:n+available], curSegment[e.offset:])
			n += available
			e.offset += available
		}
		if e.segment.isLast() {
			return n, io.EOF
		}
		err := e.readNextAndEncrypt()
		e.offset = 0
		if err != nil {
			return n, err
		}
		e.segmentIdx++
		if e.segmentIdx >= MaxNumSegments {
			maxPlaintextLen := int64(e.segment.segmentSize()-e.tagSize) * MaxNumSegments
			return n, fmt.Errorf("cannot encrypt more than %d bytes", maxPlaintextLen)
		}
	}
}

func (e *EncryptingReader) readNextAndEncrypt() error {
	_, err := e.segment.readNext(e.R, e.tagSize)
	if err != nil {
		return err
	}
	appendToNonce(e.nonce, uint32(e.segmentIdx), e.segment.isLast())
	// We pass only plaintext to Seal, which writes the tag to the end of the segment.
	curSegment := e.segment.current(0)
	e.aead.Seal(curSegment[:0], e.nonce, curSegment, nil)
	return nil
}

// NewEncryptingReaderWithHeader is a helper which creates a new EncryptingReader which returns the header before
// the ciphertext. See NewEncryptingReader for details.
func NewEncryptingReaderWithHeader(r io.Reader, key []byte, aad []byte, options EncryptOptions) (*EncryptingReader, error) {
	wrapper := &EncryptingReader{R: r}
	header, err := initCommon(&wrapper.common, key, aad, options)
	if err != nil {
		return nil, err
	}
	var headerBytes bytes.Buffer
	if err := header.MarshalTo(&headerBytes); err != nil {
		return nil, err
	}
	wrapper.prefix = headerBytes.Bytes()
	wrapper.segment = newSegmentReader(header.SegmentSize)
	return wrapper, nil
}
