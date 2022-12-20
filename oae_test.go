// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"bytes"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

var testAlgorithms = []Algorithm{AesGcm128Sha256, AesGcm256Sha256, ChaCha20Poly1305Sha256}
var testAads = [][]byte{nil, []byte("this is a test aad")}

func init() {
	rand.Seed(0)
}

// The general test for various segment sizes + read sizes to catch the off-by-one errors.
func TestEncryptDecrypt(t *testing.T) {
	for _, algorithm := range testAlgorithms {
		key := make([]byte, algorithm.KeySize())
		_, err := rand.Read(key)
		require.NoError(t, err)
		for _, aad := range testAads {
			tagSize := algorithm.tagSize()
			segmentSizes := []int{tagSize + 1, tagSize + 2, tagSize + 3, tagSize + 4, 1023, 1024, 4096, 4097}
			for _, segmentSize := range segmentSizes {
				options := EncryptOptions{
					Algorithm:   algorithm,
					SegmentSize: segmentSize,
				}
				plaintextSizes := []int{0, 1, segmentSize - 1, segmentSize, segmentSize + 1, segmentSize*2 - 1, segmentSize * 2, segmentSize*2 + 1}
				for _, plaintextSize := range plaintextSizes {
					plaintext := make([]byte, plaintextSize)
					_, err := rand.Read(plaintext)
					require.NoError(t, err)

					writesSizes := []int{1, 2, segmentSize - 1, segmentSize, segmentSize + 1, plaintextSize - 1, plaintextSize}
					for _, writeSize := range writesSizes {
						testEncryptDecryptWriter(t, plaintext, key, aad, options, writeSize)
						testEncryptDecryptReader(t, plaintext, key, aad, options, writeSize)
						testCiphertextRange(t, plaintext, key, aad, options, writeSize)
					}
				}
			}
		}
	}
}

func testEncryptDecryptWriter(t *testing.T, plaintext []byte, key []byte, aad []byte, options EncryptOptions, writeSize int) {
	if writeSize < 1 {
		return
	}

	var out bytes.Buffer
	header, ew, err := NewEncryptingWriter(&out, key, aad, options)
	require.NoError(t, err, "NewEncryptingWriter with options %v", options)

	var headerOut bytes.Buffer
	err = header.MarshalTo(&headerOut)
	require.NoError(t, err, "MarshalTo with header %+v", header)

	for o := 0; o < len(plaintext); o += writeSize {
		to := o + writeSize
		if to > len(plaintext) {
			to = len(plaintext)
		}
		n, err := ew.Write(plaintext[o:to])
		require.NoError(t, err, "EncryptingWriter Write with options %v, plaintext len %d, offset %d", options, len(plaintext), o)
		require.EqualValues(t, n, to-o, "EncryptingWriter Write with options %v, plaintext len %d, offset %d", options, len(plaintext), o)
	}
	err = ew.Close()
	require.NoError(t, err, "EncryptingWriter Close with options %v", options)
	// Test that the second Close() is a no-op.
	err = ew.Close()
	require.NoError(t, err, "EncryptingWriter Close with options %v", options)
	ciphertext := out.Bytes()
	headerBytes := headerOut.Bytes()

	testDecrypt(t, plaintext, key, aad, options, writeSize, ciphertext, err, headerBytes, header)
}

func testEncryptDecryptReader(t *testing.T, plaintext []byte, key []byte, aad []byte, options EncryptOptions, writeSize int) {
	if writeSize < 1 {
		return
	}

	in := bytes.NewReader(plaintext)
	header, ew, err := NewEncryptingReader(in, key, aad, options)
	require.NoError(t, err, "NewEncryptingReader with options %v", options)

	var headerOut bytes.Buffer
	err = header.MarshalTo(&headerOut)
	require.NoError(t, err, "MarshalTo with header %+v", header)

	var out bytes.Buffer
	_, err = io.CopyBuffer(onlyWriter{w: &out}, ew, make([]byte, writeSize))
	require.NoError(t, err, "EncryptingReader io.Copy with options %v, plaintext len %d", options, len(plaintext))
	headerBytes := headerOut.Bytes()
	ciphertext := out.Bytes()

	testDecrypt(t, plaintext, key, aad, options, writeSize, ciphertext, err, headerBytes, header)
}

func testDecrypt(t *testing.T, plaintext []byte, key []byte, aad []byte, options EncryptOptions, writeSize int, ciphertext []byte, err error, headerBytes []byte, header CiphertextHeader) {
	// Test that we correctly compute ciphertext and plaintext lengths.
	clen, err := options.Algorithm.CiphertextLength(options.SegmentSize, int64(len(plaintext)))
	require.NoError(t, err)
	require.EqualValues(t, len(ciphertext), clen)
	plen, err := options.Algorithm.PlaintextLength(options.SegmentSize, int64(len(ciphertext)))
	require.NoError(t, err)
	require.EqualValues(t, len(plaintext), plen)
	crange, err := options.Algorithm.CiphertextRange(options.SegmentSize, Range{0, int64(len(plaintext))}, int64(len(plaintext)))
	require.NoError(t, err)
	require.EqualValues(t, 0, crange.Begin)
	require.EqualValues(t, len(ciphertext), crange.End)

	var readHeader CiphertextHeader
	err = readHeader.UnmarshalFrom(bytes.NewReader(headerBytes))
	require.NoError(t, err, "UnmarshalFrom")

	br := bytes.NewReader(ciphertext)
	dr, err := NewDecryptingReader(br, key, aad, header)
	require.NoError(t, err, "NewDecryptingReader with header %+v", header)
	testDecryptingReader(t, dr, header, plaintext, writeSize)

	// Append a few bytes to ciphertext to check if we process this correctly.
	const prefixLen = 10
	ciphertextWithPrefix := make([]byte, prefixLen)
	ciphertextWithPrefix = append(ciphertextWithPrefix, ciphertext...)
	brs := bytes.NewReader(ciphertextWithPrefix)
	_, _ = brs.Seek(prefixLen, io.SeekStart)
	drs, err := NewDecryptingReadSeeker(brs, key, aad, header)
	require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
	testDecryptingReader(t, drs, header, plaintext, writeSize)
	testDecryptingSeeker(t, drs, header, plaintext, writeSize)

	// Test Seek immediately after NewDecryptingReadSeeker
	drs, err = NewDecryptingReadSeeker(bytes.NewReader(ciphertext), key, aad, header)
	require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
	testSeekAfterNew(t, drs, header, plaintext, 0)
	drs, err = NewDecryptingReadSeeker(bytes.NewReader(ciphertext), key, aad, header)
	require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
	testSeekAfterNew(t, drs, header, plaintext, len(plaintext)/2)
}

func testDecryptingReader(t *testing.T, dr io.Reader, header CiphertextHeader, plaintext []byte, readSize int) {
	if len(plaintext) == 0 {
		buf := make([]byte, 1)
		n, err := dr.Read(buf)
		require.Zero(t, n, "DecryptingReader Read with header %+v, plaintext len %d did not return when reading past the end", header, len(plaintext))
		require.Equal(t, err, io.EOF, "DecryptingReader Read with header %+v, plaintext len %d did not return when reading past the end", header, len(plaintext))
		return
	}

	buf := make([]byte, len(plaintext))
	for o := 0; o < len(plaintext); o += readSize {
		to := o + readSize
		if to > len(plaintext) {
			to = len(plaintext)
		}
		n, err := dr.Read(buf[o:to])
		if err == io.EOF {
			require.Equal(t, to, len(plaintext), "DecryptingReader Read with header %+v, plaintext len %d got premature EOF", header, len(plaintext))
		} else {
			require.NoError(t, err, "DecryptingReader Read with header %+v, plaintext len %d at offset %d", header, len(plaintext), o)
		}
		require.Equal(t, n, to-o, "DecryptingReader Read with header %+v, plaintext len %d at offset %d", header, len(plaintext), o)
	}
	// Test for EOF at the end
	n, err := dr.Read(buf[:1])
	require.Zero(t, n, "DecryptingReader Read with header %+v, plaintext len %d did not return when reading past the end", header, len(plaintext))
	require.Equal(t, err, io.EOF, "DecryptingReader Read with header %+v, plaintext len %d did not return when reading past the end", header, len(plaintext))
	n, err = dr.Read(buf)
	require.Zero(t, n, "DecryptingReader Read with header %+v, plaintext len %d did not return when reading past the end", header, len(plaintext))
	require.Equal(t, err, io.EOF, "DecryptingReader Read with header %+v, plaintext len %d did not return when reading past the end", header, len(plaintext))

	require.Equal(t, plaintext, buf, "DecryptingReader with header %+v, plaintext len %d read different bytes", header, len(plaintext))
}

func testDecryptingSeeker(t *testing.T, dr io.ReadSeeker, header CiphertextHeader, plaintext []byte, readSize int) {
	if len(plaintext) == 0 {
		off, err := dr.Seek(0, io.SeekStart)
		require.Zero(t, off, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))
		require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))

		off, err = dr.Seek(-1, io.SeekStart)
		require.Zero(t, off, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))
		require.Error(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))

		off, err = dr.Seek(0, io.SeekCurrent)
		require.Zero(t, off, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))
		require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))

		off, err = dr.Seek(-2, io.SeekCurrent)
		require.Zero(t, off, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))
		require.Error(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly", header, len(plaintext))

		return
	}

	n, err := dr.Seek(0, io.SeekStart)
	require.EqualValues(t, 0, n, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to start", header, len(plaintext))
	require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to start", header, len(plaintext))

	n, err = dr.Seek(int64(len(plaintext)), io.SeekStart)
	require.EqualValues(t, len(plaintext), n, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to end", header, len(plaintext))
	require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to end", header, len(plaintext))

	n, err = dr.Seek(0, io.SeekCurrent)
	require.EqualValues(t, len(plaintext), n, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to end", header, len(plaintext))
	require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to end", header, len(plaintext))

	_, err = dr.Seek(0, io.SeekStart)
	require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to start", header, len(plaintext))

	_, err = dr.Seek(-1, io.SeekStart)
	require.Error(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to start", header, len(plaintext))

	_, err = dr.Seek(-1, io.SeekCurrent)
	require.Error(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly to start", header, len(plaintext))

	buf := make([]byte, len(plaintext))
	var curOff int
	// This is almost fuzzing: we make random Seek() calls and see if anything breaks.
	for i := 0; i < 50; i++ {
		whence := rand.Intn(2)
		var off int
		switch whence {
		case io.SeekStart:
			off = rand.Intn(len(plaintext) + 1)
			curOff = off
		case io.SeekCurrent:
			// Randomly switch to small offset to test intra-segment seeks.
			switch rand.Intn(4) {
			case 0:
				off = rand.Intn(len(plaintext) + 1 - curOff)
			case 1:
				off = -rand.Intn(curOff + 1)
			case 2:
				if curOff < len(plaintext) {
					off = 1
				} else if curOff > 0 {
					off = -1
				}
			case 3:
				if curOff > 0 {
					off = -1
				} else if curOff < len(plaintext) {
					off = 1
				}
			}
			curOff += off
		}
		require.True(t, curOff >= 0 && curOff <= len(plaintext), "internal test error, incorrectly generated offset: %d not in [0, %d]", curOff, len(plaintext))

		n, err := dr.Seek(int64(off), whence)
		require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly off %d, whence %d, curoff %d", header, len(plaintext), off, whence, curOff)
		require.Equal(t, int64(curOff), n, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek correctly off %d, whence %d, curoff %d", header, len(plaintext), off, whence, curOff)

		if curOff < len(plaintext) {
			l := rand.Intn(len(plaintext) - curOff)
			for o := 0; o < l; o += readSize {
				to := o + readSize
				if to > l {
					to = l
				}
				n, err := dr.Read(buf[o:to])
				if err == io.EOF {
					require.Equal(t, len(plaintext), to, "DecryptingReadSeeker Read with header %+v, plaintext len %d got premature EOF at offset %d + %d", header, len(plaintext), curOff, o)
				} else {
					require.NoError(t, err, "DecryptingReadSeeker Read with header %+v, plaintext len %d at offset %d + %d", header, len(plaintext), curOff, o)
				}
				require.Equal(t, to-o, n, "DecryptingReadSeeker Read with header %+v, plaintext len %d at offset %d + %d", header, len(plaintext), curOff, o)
			}

			require.Equal(t, plaintext[curOff:curOff+l], buf[:l], "DecryptingReadSeeker with header %+v, plaintext len %d read different bytes at [%d:%d]", header, len(plaintext), off, off+l)
			curOff += l
		}
	}
}

func testSeekAfterNew(t *testing.T, dr io.ReadSeeker, header CiphertextHeader, plaintext []byte, seekFor int) {
	n, err := dr.Seek(int64(seekFor), io.SeekStart)
	require.EqualValues(t, seekFor, n, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek to %d", header, len(plaintext), seekFor)
	require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek to %d", header, len(plaintext), seekFor)

	l := len(plaintext) - seekFor
	buf := make([]byte, l)
	rn, err := dr.Read(buf)
	require.EqualValues(t, l, rn, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not read after to %d", header, len(plaintext), seekFor)
	require.NoError(t, err, "DecryptingReadSeeker Read with header %+v, plaintext len %d did not read after seek to %d", header, len(plaintext), seekFor)

	require.Equal(t, plaintext[seekFor:], buf, "DecryptingReadSeeker Read with header %+v, plaintext len %d did not read correctly after seek to %d", header, len(plaintext), seekFor)
}

func testCiphertextRange(t *testing.T, plaintext []byte, key []byte, aad []byte, options EncryptOptions, size int) {
	if size < 1 {
		return
	}

	var out bytes.Buffer
	header, ew, err := NewEncryptingWriter(&out, key, aad, options)
	require.NoError(t, err, "NewEncryptingWriter with options %v", options)
	_, err = ew.Write(plaintext)
	require.NoError(t, err, "EncryptingWriter Write with options %v, plaintext len %d", options, len(plaintext))
	err = ew.Close()
	require.NoError(t, err, "EncryptingWriter Close with options %v, plaintext len %d", options, len(plaintext))
	ciphertext := out.Bytes()

	buf := make([]byte, size)
	segmentLen := options.SegmentSize - options.Algorithm.tagSize()
	offsets := []int{0, 1, segmentLen - 1, segmentLen, segmentLen + 1, len(plaintext) - 1, len(plaintext)}
	for _, off := range offsets {
		if off < 0 || off > len(plaintext) {
			continue
		}

		r := &readStats{r: bytes.NewReader(ciphertext)}
		er, err := NewDecryptingReadSeeker(r, key, aad, header)
		require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
		_, err = er.Seek(int64(off), io.SeekStart)
		if err != io.EOF {
			require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v, plaintext len %d did not seek to %d", header, len(plaintext), off)
		}
		n, err := er.Read(buf)
		if err == io.EOF {
			continue
		}
		require.NoError(t, err, "DecryptingReadSeeker Read with header %+v, plaintext len %d did not read %d after seek to %d", header, len(plaintext), len(buf), off)
		plaintextRange := Range{
			Begin: int64(off),
			End:   int64(off + size),
		}
		if plaintextRange.End > int64(len(plaintext)) {
			plaintextRange.End = int64(len(plaintext))
		}
		expected := int(plaintextRange.End - plaintextRange.Begin)
		require.EqualValues(t, expected, n, "DecryptingReadSeeker Read with header %+v, plaintext len %d did not read expected after seek to %d", header, len(plaintext), len(buf), off)

		ciphertextRange, err := options.Algorithm.CiphertextRange(options.SegmentSize, plaintextRange, int64(len(plaintext)))
		require.NoError(t, err, "CiphertextRange with segment size %d, plaintext range %+v and plaintext total %d", options.SegmentSize, plaintextRange, len(plaintext))
		require.EqualValues(t, r.readFrom, ciphertextRange.Begin, "CiphertextRange with segment size %d, plaintext range %+v and plaintext total %d", options.SegmentSize, plaintextRange, len(plaintext))
		require.EqualValues(t, r.readFrom+r.readLen, ciphertextRange.End, "CiphertextRange with segment size %d, plaintext range %+v and plaintext total %d", options.SegmentSize, plaintextRange, len(plaintext))
	}
}

type readStats struct {
	r io.ReadSeeker

	readFrom int
	readLen  int
}

func (r *readStats) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	r.readLen += n
	return n, err
}

func (r *readStats) Seek(offset int64, whence int) (int64, error) {
	r.readFrom = int(offset)
	return r.r.Seek(offset, whence)
}

// Test how many calls to Seek are made when doing a partial read.
func TestCountCalls(t *testing.T) {
	for _, algorithm := range testAlgorithms {
		key := make([]byte, algorithm.KeySize())
		_, err := rand.Read(key)
		require.NoError(t, err)
		for _, aad := range testAads {
			const segmentSize = 4000
			options := EncryptOptions{
				Algorithm:   algorithm,
				SegmentSize: segmentSize,
			}
			const plaintextSize = segmentSize * 4
			plaintext := make([]byte, plaintextSize)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)

			var out bytes.Buffer
			header, ew, err := NewEncryptingWriter(&out, key, aad, options)
			require.NoError(t, err, "NewEncryptingWriter with options %v", options)
			n, err := ew.Write(plaintext)
			require.NoError(t, err, "EncryptingWriter Write with options %v, plaintext len %d", options, len(plaintext))
			require.EqualValues(t, len(plaintext), n, "EncryptingWriter Write with options %v, plaintext len %d", options, len(plaintext))
			err = ew.Close()
			require.NoError(t, err, "EncryptingWriter Close with options %v", options)
			ciphertext := out.Bytes()

			buf := make([]byte, len(plaintext))
			// Test Read() + intra-segment Seek() + Read() + next segment Seek() + Read()
			r := countCalls{r: bytes.NewReader(ciphertext)}
			dr, err := NewDecryptingReadSeeker(&r, key, aad, header)
			require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
			require.Equal(t, 0, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			n, err = dr.Read(buf[:segmentSize/2])
			require.NoError(t, err, "DecryptingReadSeeker initial Read with header %+v", header)
			require.Equal(t, segmentSize/2, n, "DecryptingReadSeeker initial Read with header %+v returned %d", header, n)
			require.Equal(t, 2, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			o, err := dr.Seek(1, io.SeekCurrent)
			require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v", header)
			require.EqualValues(t, segmentSize/2+1, o, "DecryptingReadSeeker Seek with header %+v returned %d", header, n)
			n, err = dr.Read(buf[:segmentSize/4])
			require.NoError(t, err, "DecryptingReadSeeker Read with header %+v", header)
			require.Equal(t, segmentSize/4, n, "DecryptingReadSeeker initial Read with header %+v returned %d", header, n)
			require.Equal(t, 2, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			o, err = dr.Seek(segmentSize, io.SeekCurrent)
			require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v", header)
			n, err = dr.Read(buf[:segmentSize/8])
			require.NoError(t, err, "DecryptingReadSeeker Read with header %+v", header)
			require.Equal(t, segmentSize/8, n, "DecryptingReadSeeker initial Read with header %+v returned %d", header, n)
			require.Equal(t, 4, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 1, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			// Test intra-segment Seek() + Read()
			r = countCalls{r: bytes.NewReader(ciphertext)}
			dr, err = NewDecryptingReadSeeker(&r, key, aad, header)
			require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
			require.Equal(t, 0, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			o, err = dr.Seek(1, io.SeekCurrent)
			require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v", header)
			require.EqualValues(t, 1, o, "DecryptingReadSeeker Seek with header %+v returned %d", header, n)
			require.Equal(t, 2, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 1, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			n, err = dr.Read(buf[:segmentSize/4])
			require.NoError(t, err, "DecryptingReadSeeker Read with header %+v", header)
			require.Equal(t, segmentSize/4, n, "DecryptingReadSeeker initial Read with header %+v returned %d", header, n)
			require.Equal(t, 2, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 1, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			// Test next segment Seek() + Read()
			r = countCalls{r: bytes.NewReader(ciphertext)}
			dr, err = NewDecryptingReadSeeker(&r, key, aad, header)
			require.NoError(t, err, "NewDecryptingReadSeeker with header %+v", header)
			require.Equal(t, 0, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			o, err = dr.Seek(segmentSize, io.SeekCurrent)
			require.NoError(t, err, "DecryptingReadSeeker Seek with header %+v", header)
			require.EqualValues(t, segmentSize, o, "DecryptingReadSeeker Seek with header %+v returned %d", header, n)
			require.Equal(t, 2, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 1, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")

			n, err = dr.Read(buf[:segmentSize/4])
			require.NoError(t, err, "DecryptingReadSeeker Read with header %+v", header)
			require.Equal(t, segmentSize/4, n, "DecryptingReadSeeker initial Read with header %+v returned %d", header, n)
			require.Equal(t, 2, r.reads, "num Read() after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.startSeeks, "num Seek(io.SeekStart) after NewDecryptingReadSeeker")
			require.Equal(t, 1, r.currentSeeks, "num Seek(io.SeekCurrent) after NewDecryptingReadSeeker")
			require.Equal(t, 0, r.endSeeks, "num Seek(io.SeekEnd) after NewDecryptingReadSeeker")
		}
	}
}

type countCalls struct {
	r            io.ReadSeeker
	reads        int
	startSeeks   int
	currentSeeks int
	endSeeks     int
}

func (c *countCalls) Read(p []byte) (n int, err error) {
	c.reads++
	return c.r.Read(p)
}

func (c *countCalls) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		c.startSeeks++
	case io.SeekCurrent:
		c.currentSeeks++
	case io.SeekEnd:
		c.endSeeks++
	}
	return c.r.Seek(offset, whence)
}

func TestWithHeader(t *testing.T) {
	for _, algorithm := range testAlgorithms {
		key := make([]byte, algorithm.KeySize())
		_, err := rand.Read(key)
		require.NoError(t, err)

		var out bytes.Buffer
		ew, err := NewEncryptingWriterWithHeader(&out, key, nil, EncryptOptions{})
		require.NoError(t, err)

		const plaintextSize = 1000000
		plaintext := make([]byte, plaintextSize)
		_, err = rand.Read(plaintext)
		require.NoError(t, err)

		n, err := ew.Write(plaintext)
		require.NoError(t, err)
		require.Equal(t, plaintextSize, n)

		err = ew.Close()
		require.NoError(t, err)

		ciphertext := out.Bytes()
		buf := make([]byte, plaintextSize+1)

		dr, err := NewDecryptingReaderWithHeader(bytes.NewReader(ciphertext), key, nil)
		require.NoError(t, err)
		n, err = dr.Read(buf)
		require.Equal(t, err, io.EOF)
		require.Equal(t, plaintextSize, n)
		require.Equal(t, plaintext, buf[:plaintextSize])

		drs, err := NewDecryptingReadSeekerWithHeader(bytes.NewReader(ciphertext), key, nil)
		require.NoError(t, err)
		const offset = 10000
		o, err := drs.Seek(offset, io.SeekStart)
		require.NoError(t, err)
		require.EqualValues(t, offset, o)
		n, err = drs.Read(buf)
		require.Equal(t, err, io.EOF)
		require.Equal(t, plaintextSize-offset, n)
		require.Equal(t, plaintext[offset:], buf[:plaintextSize-offset])
	}

	for _, algorithm := range testAlgorithms {
		key := make([]byte, algorithm.KeySize())
		_, err := rand.Read(key)
		require.NoError(t, err)

		const plaintextSize = 1000000
		plaintext := make([]byte, plaintextSize)
		_, err = rand.Read(plaintext)
		require.NoError(t, err)

		var out bytes.Buffer
		er, err := NewEncryptingReaderWithHeader(bytes.NewReader(plaintext), key, nil, EncryptOptions{})
		require.NoError(t, err)

		_, err = io.Copy(&out, er)
		require.NoError(t, err)

		ciphertext := out.Bytes()
		buf := make([]byte, plaintextSize+1)

		dr, err := NewDecryptingReaderWithHeader(bytes.NewReader(ciphertext), key, nil)
		require.NoError(t, err)
		n, err := dr.Read(buf)
		require.Equal(t, err, io.EOF)
		require.Equal(t, plaintextSize, n)
		require.Equal(t, plaintext, buf[:plaintextSize])
	}

	for _, algorithm := range testAlgorithms {
		key := make([]byte, algorithm.KeySize())
		_, err := rand.Read(key)
		require.NoError(t, err)

		const plaintextSize = 1000000
		plaintext := make([]byte, plaintextSize)
		_, err = rand.Read(plaintext)
		require.NoError(t, err)

		var out bytes.Buffer
		er, err := NewEncryptingReaderWithHeader(bytes.NewReader(plaintext), key, nil, EncryptOptions{})
		require.NoError(t, err)

		_, err = io.CopyBuffer(onlyWriter{w: &out}, er, make([]byte, 2))
		require.NoError(t, err)

		ciphertext := out.Bytes()
		buf := make([]byte, plaintextSize+1)

		dr, err := NewDecryptingReaderWithHeader(bytes.NewReader(ciphertext), key, nil)
		require.NoError(t, err)
		n, err := dr.Read(buf)
		require.Equal(t, err, io.EOF)
		require.Equal(t, plaintextSize, n)
		require.Equal(t, plaintext, buf[:plaintextSize])
	}
}

// onlyWriter is used to remove ReadFrom implementation in bytes.Buffer so that io.CopyBuffer does not use it.
type onlyWriter struct {
	w *bytes.Buffer
}

func (o onlyWriter) Write(p []byte) (n int, err error) {
	return o.w.Write(p)
}
