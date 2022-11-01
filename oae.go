// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

const (
	// DefaultAlgorithm and DefaultSegmentSize should be used in almost all cases unless you have specific requirements
	// (see EncryptionOptions for details on segment size).
	DefaultAlgorithm   = AesGcm128Sha256
	DefaultSegmentSize = 4096
	// MaxSegmentSize is used to limit the memory usage when reading the untrusted ciphertext.
	MaxSegmentSize = 8 * 1024 * 1024

	// MaxNumSegments is the maximum number of ciphertext segments.
	MaxNumSegments = 0xfffffffe
)

// EncryptOptions are the options which are used by NewEncryptingWriter.
type EncryptOptions struct {
	// Zero value means the default algorithm is used.
	Algorithm Algorithm
	// SegmentSize limits the amount of data which can be encrypted. The default segment size of 4096 will limit
	// the plaintext size to ~15.9Tb. Zero value means the default segment size is used.
	SegmentSize int
}
