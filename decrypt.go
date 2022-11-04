// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
)

// DecryptingReadSeeker reads ciphertext and returns plaintext.
type DecryptingReadSeeker struct {
	// Wrapped reader.
	R io.ReadSeeker

	aead             cipher.AEAD
	nonce            []byte
	tagSize          int
	segmentIdx       int
	segment          segmentReader
	offset           int
	ciphertextOffset int64
}

var _ io.ReadSeeker = (*DecryptingReadSeeker)(nil)

// DecryptingReader is a variant of DecryptingReadSeeker which supports ciphertext readers without Seek().
type DecryptingReader struct {
	// Wrapped reader.
	R io.Reader

	inner DecryptingReadSeeker
}

var _ io.Reader = (*DecryptingReader)(nil)

// NewDecryptingReadSeeker returns DecryptingReadSeeker that reads the ciphertext and returns the plaintext. Key and aad
// must match the parameters to NewEncryptingWriter. Header must be the CiphertextHeader
// returned from NewEncryptingWriter. Wrapped reader must not have any trailing bytes after the ciphertext.
//
// NewDecryptingReadSeeker guarantees to not call any methods of wrapped reader until the first Read() or Seek() is called on the
// result.
//
// Calling Seek() with io.SeekEnd is not supported. Seeking to the end of plaintext or beyond will return an error.
// r.Seek() will only be called with io.SeekCurrent.
func NewDecryptingReadSeeker(r io.ReadSeeker, key []byte, aad []byte, header CiphertextHeader) (*DecryptingReadSeeker, error) {
	result := &DecryptingReadSeeker{
		R: r,
	}
	if err := initDecryptingReadSeeker(result, key, aad, header); err != nil {
		return nil, err
	}
	return result, nil
}

// NewDecryptingReader returns a wrapper around reader that reads the ciphertext and returns the plaintext to the caller. Key
// and aad must match the parameters to NewEncryptingWriter. Header must be the CiphertextHeader returned from
// NewEncryptingWriter. Wrapped reader must not have any trailing bytes after the ciphertext.
//
// NewDecryptingReader guarantees to not call any methods of wrapped reader until the first Read() is called on the result.
func NewDecryptingReader(r io.Reader, key []byte, aad []byte, header CiphertextHeader) (*DecryptingReader, error) {
	result := &DecryptingReader{
		R: r,
		inner: DecryptingReadSeeker{
			R: failingSeeker{
				r: r,
			},
		},
	}
	if err := initDecryptingReadSeeker(&result.inner, key, aad, header); err != nil {
		return nil, err
	}
	return result, nil
}

// Read reads the next portion of ciphertext. Errors from wrapped reader are returned as is.
func (d *DecryptingReadSeeker) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		curSegment := d.segment.current(0)
		if curSegment != nil {
			available := len(curSegment) - d.tagSize - d.offset
			l := len(p) - n
			copy(p[n:], curSegment[d.offset:d.offset+available])
			if available >= l {
				n += l
				d.offset += l
				break
			}
			n += available
		}
		if d.segment.isLast() {
			return n, io.EOF
		}
		d.segmentIdx++
		if err := d.readNextAndDecrypt(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Seek sets the offset in plaintext. Only SeekStart and SeekCurrent are supported, passing SeekEnd will result in
// error. Setting offset to the end of plaintext or further will return an error (note that this differs from e.g. file
// where setting offset to the end of file is ok).
//
// Seek will call Seek of the wrapped writer with SeekCurrent at most once.
func (d *DecryptingReadSeeker) Seek(offset int64, whence int) (int64, error) {
	segmentSize := int64(d.segment.segmentSize())
	segmentPlaintext := segmentSize - int64(d.tagSize)

	var curPlaintextOffset int64
	if d.segmentIdx != -1 {
		curPlaintextOffset = segmentPlaintext*int64(d.segmentIdx) + int64(d.offset)
	}
	var nextPlaintextOffset int64
	switch whence {
	case io.SeekStart:
		nextPlaintextOffset = offset
	case io.SeekCurrent:
		nextPlaintextOffset = curPlaintextOffset + offset
	case io.SeekEnd:
		return 0, errors.New("SeekEnd not supported")
	default:
		return 0, errors.New("unknown whence")
	}
	if nextPlaintextOffset < 0 {
		return 0, errors.New("negative offset")
	}

	nextSegmentIdx := nextPlaintextOffset / segmentPlaintext
	if nextSegmentIdx >= MaxNumSegments {
		return 0, io.EOF
	}
	// If the seek is inside the currently loaded segment, skip re-reading the segment.
	if nextSegmentIdx != int64(d.segmentIdx) {
		_, err := d.R.Seek(nextSegmentIdx*segmentSize-d.ciphertextOffset, io.SeekCurrent)
		if err != nil {
			d.resetSegment()
			return 0, err
		}
		d.segment.resetCurrent()
		d.segmentIdx = int(nextSegmentIdx)
		d.ciphertextOffset = nextSegmentIdx * segmentSize
		if err := d.readNextAndDecrypt(); err != nil {
			return 0, err
		}
	}

	d.offset = int(nextPlaintextOffset - nextSegmentIdx*segmentPlaintext)
	if d.offset > len(d.segment.current(0)) {
		d.resetSegment()
		return 0, io.EOF
	}
	return nextPlaintextOffset, nil
}

// Read reads the next portion of ciphertext. Errors from wrapped reader are returned as is.
func (d *DecryptingReader) Read(p []byte) (n int, err error) {
	return d.inner.Read(p)
}

func initDecryptingReadSeeker(result *DecryptingReadSeeker, key []byte, aad []byte, header CiphertextHeader) error {
	if header.SegmentSize <= header.Algorithm.tagSize() {
		return errors.New("incorrect header: too small segment size")
	}
	if header.SegmentSize >= MaxSegmentSize {
		return errors.New("incorrect header: too large segment size")
	}

	result.nonce = make([]byte, header.Algorithm.nonceSize())
	result.tagSize = header.Algorithm.tagSize()
	// -1 means "no segment loaded" and is also a good default because it will be incremented before first readSegment().
	result.segmentIdx = -1
	result.segment = newSegmentReader(header.SegmentSize)

	keySize := header.Algorithm.KeySize()
	if len(key) < keySize {
		return fmt.Errorf("incorrect header: key must be at least %d bytes", keySize)
	}
	if len(header.Salt) != header.Algorithm.saltSize() {
		return fmt.Errorf("incorrect header: salt must be %d bytes", header.Algorithm.saltSize())
	}
	derivedKeyR := hkdf.New(header.Algorithm.hasher(), key, header.Salt, aad)
	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(derivedKeyR, derivedKey); err != nil {
		return fmt.Errorf("incorrect header: could not derive key: %w", err)
	}
	aead, err := header.Algorithm.aead(derivedKey)
	if err != nil {
		return fmt.Errorf("could not init cipher: %w", err)
	}
	result.aead = aead
	// 4 bytes for segment size + 1 byte for final prefix.
	noncePrefixLen := header.Algorithm.nonceSize() - 5
	if len(header.NoncePrefix) != noncePrefixLen {
		return fmt.Errorf("incorrect header: nonce prefix must be at least %d bytes", noncePrefixLen)
	}
	copy(result.nonce, header.NoncePrefix)
	return nil
}

func (d *DecryptingReadSeeker) readNextAndDecrypt() error {
	d.offset = 0
	n, err := d.segment.readNext(d.R, 0)
	if err != nil {
		d.resetSegment()
		return err
	}
	d.ciphertextOffset += int64(n)

	appendToNonce(d.nonce, uint32(d.segmentIdx), d.segment.isLast())
	curSegment := d.segment.current(0)
	_, err = d.aead.Open(curSegment[:0], d.nonce, curSegment, nil)
	if err != nil {
		d.resetSegment()
		return fmt.Errorf("incorrect ciphertext: %w", err)
	}
	return nil
}

// resetSegment must be called upon any error when reading or seeking, otherwise the next Read() may return inconsistent
// data, either stale contents or unencrypted ciphertext.
func (d *DecryptingReadSeeker) resetSegment() {
	d.segment.fail()
	d.offset = 0
}

// NewDecryptingReadSeekerWithHeader is a helper which reads the header from ciphertext and creates a new
// DecryptingReadSeeker. See NewDecryptingReadSeeker for details.
func NewDecryptingReadSeekerWithHeader(r io.ReadSeeker, key []byte, aad []byte) (*DecryptingReadSeeker, error) {
	var header CiphertextHeader
	if err := header.UnmarshalFrom(r); err != nil {
		return nil, err
	}
	return NewDecryptingReadSeeker(r, key, aad, header)
}

// NewDecryptingReaderWithHeader is a helper which reads the header from ciphertext and creates a new
// DecryptingReader. See NewDecryptingReader for details.
func NewDecryptingReaderWithHeader(r io.Reader, key []byte, aad []byte) (*DecryptingReader, error) {
	var header CiphertextHeader
	if err := header.UnmarshalFrom(r); err != nil {
		return nil, err
	}
	return NewDecryptingReader(r, key, aad, header)
}
