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

// See readSegment for the description of overread. 8 should be smaller than tagSize for any algorithm.
const overread = 8

// DecryptingReadSeeker reads ciphertext and returns plaintext.
type DecryptingReadSeeker struct {
	// Wrapped reader.
	R io.ReadSeeker

	aead             cipher.AEAD
	nonce            []byte
	tagSize          int
	gotEof           bool
	segmentIdx       int
	segment          []byte
	segmentLen       int
	offset           int
	ciphertextOffset int64
}

// DecryptingReader is a variant of DecryptingReadSeeker which supports ciphertext readers without Seek().
type DecryptingReader struct {
	// Wrapped reader.
	R io.Reader

	inner DecryptingReadSeeker
}

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
		if d.segmentLen > 0 {
			available := d.segmentLen - d.tagSize - d.offset
			l := len(p) - n
			copy(p[n:], d.segment[d.offset:d.offset+available])
			if available >= l {
				n += l
				d.offset += l
				break
			}
			n += available
		}
		if d.gotEof {
			return n, io.EOF
		}
		d.segmentIdx++
		// If the current segment is zero, we just started reading from the start.
		usePrevSegment := d.segmentIdx != 0
		err := d.readSegment(usePrevSegment)
		d.offset = 0
		if err != nil {
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
	segmentSize := int64(len(d.segment) - overread)
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
		d.gotEof = false
		d.segmentIdx = int(nextSegmentIdx)
		d.ciphertextOffset = nextSegmentIdx * segmentSize
		if err := d.readSegment(false); err != nil {
			// resetSegment has been called by readSegment already.
			return 0, err
		}
	}

	d.offset = int(nextPlaintextOffset - nextSegmentIdx*segmentPlaintext)
	if d.offset > d.segmentLen {
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
	// See readSegment about overread
	result.segment = make([]byte, header.SegmentSize+overread)

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

func (d *DecryptingReadSeeker) readSegment(usePrevSegment bool) error {
	// We do not know the plaintext or ciphertext len and do not want to call Seek() to get it or ask the user to store
	// it. We over-read the segment by a few bytes and check if we got an io.EOF. If we did not get io.EOF, it means
	// there is at least one segment after the current segment.
	if d.gotEof {
		return errors.New("internal error: trying to read past EOF")
	} else if usePrevSegment {
		// The previous readSegment ended up either gotEof or read the full segment. The last bytes are the first bytes
		// of the next segment.
		copy(d.segment[:overread], d.segment[len(d.segment)-overread:])
		n, err := io.ReadFull(d.R, d.segment[overread:])
		d.ciphertextOffset += int64(n)
		if err == nil {
			d.gotEof = false
			d.segmentLen = len(d.segment) - overread
		} else if err == io.ErrUnexpectedEOF {
			d.gotEof = true
			d.segmentLen = n + overread
		} else {
			d.resetSegment()
			return err
		}
	} else {
		// We either started reading or just seeked to different segment.
		n, err := io.ReadFull(d.R, d.segment)
		d.ciphertextOffset += int64(n)
		if err == nil {
			d.gotEof = false
			d.segmentLen = len(d.segment) - overread
		} else if err == io.ErrUnexpectedEOF {
			d.gotEof = true
			d.segmentLen = n
		} else {
			d.resetSegment()
			return err
		}
	}

	appendToNonce(d.nonce, uint32(d.segmentIdx), d.gotEof)
	_, err := d.aead.Open(d.segment[:0], d.nonce, d.segment[:d.segmentLen], nil)
	if err != nil {
		d.resetSegment()
		return fmt.Errorf("incorrect ciphertext: %w", err)
	}
	return nil
}

// resetSegment must be called upon any error when reading or seeking, otherwise the next Read() may return inconsistent
// data, either stale contents or unencrypted ciphertext.
func (d *DecryptingReadSeeker) resetSegment() {
	// Set to true so that next Read() immediately returns without trying to readSegment().
	d.gotEof = true
	d.segmentLen = 0
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
