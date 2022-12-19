// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// "OAE1"
const magicV1 = 0x3145414F

// CiphertextHeader is the metadata returned from the NewEncryptingWriter and must be stored alongside the ciphertext
// and later passed to the NewDecryptingReader or NewDecryptingReadSeeker alongside the aad. You can serialize
// CiphertextHeader yourself or use MarshalTo and UnmarshalFrom methods.
type CiphertextHeader struct {
	Algorithm   Algorithm
	SegmentSize int
	Salt        []byte
	NoncePrefix []byte
}

// MarshalTo writes header to writer. You can use it with NewEncryptingWriter:
//
//	ew, header, err := oae.NewEncryptingWriter(w, key, aad, oae.EncryptOptions{})
//	header.MarshalTo(w)
//	ew.Write(plaintext)
//
// NewEncryptingWriterWithHeader calls this method for you.
func (c *CiphertextHeader) MarshalTo(w io.Writer) error {
	magic := uint32(magicV1)
	if err := binary.Write(w, binary.LittleEndian, &magic); err != nil {
		return fmt.Errorf("cannot write magic bytes: %w", err)
	}
	algorithm := uint32(c.Algorithm)
	if err := binary.Write(w, binary.LittleEndian, &algorithm); err != nil {
		return fmt.Errorf("cannot write algorithm: %w", err)
	}
	segmentSize := uint32(c.SegmentSize)
	if err := binary.Write(w, binary.LittleEndian, &segmentSize); err != nil {
		return fmt.Errorf("cannot write segment size: %w", err)
	}
	saltLen := uint32(len(c.Salt))
	if err := binary.Write(w, binary.LittleEndian, &saltLen); err != nil {
		return fmt.Errorf("cannot write salt length: %w", err)
	}
	if _, err := w.Write(c.Salt); err != nil {
		return fmt.Errorf("cannot write salt: %w", err)
	}
	nonceLen := uint32(len(c.NoncePrefix))
	if err := binary.Write(w, binary.LittleEndian, &nonceLen); err != nil {
		return fmt.Errorf("cannot write nonce prefix length: %w", err)
	}
	if _, err := w.Write(c.NoncePrefix); err != nil {
		return fmt.Errorf("cannot write nonce prefix: %w", err)
	}
	return nil
}

// UnmarshalFrom fills header from reader. You can use it with NewDecryptingReader or NewDecryptingReadSeeker:
//
//	var header oae.CiphertextHeader
//	header.UnmarshalFrom(r)
//	er, err := oae.NewDecryptingReader(r, key, aad, header)
//	er.Read(ciphertext)
func (c *CiphertextHeader) UnmarshalFrom(r io.Reader) error {
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return fmt.Errorf("cannot read magic bytes: %w", err)
	}
	if magic != magicV1 {
		return errors.New("not a header")
	}
	var algorithm uint32
	if err := binary.Read(r, binary.LittleEndian, &algorithm); err != nil {
		return fmt.Errorf("cannot read algorithm: %w", err)
	}
	if algorithm >= uint32(numAlgorithms) {
		return fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
	c.Algorithm = Algorithm(algorithm)
	var segmentSize uint32
	if err := binary.Read(r, binary.LittleEndian, &segmentSize); err != nil {
		return fmt.Errorf("cannot read segment size: %w", err)
	}
	// Segment size will be validated by NewDecryptingReader
	c.SegmentSize = int(segmentSize)
	var saltLen uint32
	if err := binary.Read(r, binary.LittleEndian, &saltLen); err != nil {
		return fmt.Errorf("cannot read salt length: %w", err)
	}
	if saltLen < uint32(c.Algorithm.saltSize()) {
		return fmt.Errorf("salt has incorrect size: %d vs %d", saltLen, c.Algorithm.saltSize())
	}
	c.Salt = make([]byte, int(saltLen))
	if _, err := io.ReadFull(r, c.Salt); err != nil {
		return fmt.Errorf("cannot read salt: %w", err)
	}
	var noncePrefixLen uint32
	if err := binary.Read(r, binary.LittleEndian, &noncePrefixLen); err != nil {
		return fmt.Errorf("cannot read nonce prefix length: %w", err)
	}
	// Nonce prefix len will be validated by NewDecryptingReader, this check ensures we do not allocate too much memory.
	if noncePrefixLen >= uint32(c.Algorithm.nonceSize()) {
		return fmt.Errorf("nonce prefix has incorrect size: %d vs %d", noncePrefixLen, c.Algorithm.nonceSize())
	}
	c.NoncePrefix = make([]byte, int(noncePrefixLen))
	if _, err := io.ReadFull(r, c.NoncePrefix); err != nil {
		return fmt.Errorf("cannot read nonce prefix: %w", err)
	}
	return nil
}
