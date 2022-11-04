// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import (
	"errors"
	"io"
)

// failingSeeker is a Reader to ReadSeeker adapter which panics if Seek() is called.
type failingSeeker struct {
	r io.Reader
}

func (f failingSeeker) Read(p []byte) (int, error) {
	return f.r.Read(p)
}

func (f failingSeeker) Seek(_ int64, _ int) (int64, error) {
	panic("internal error: Seek called")
}

// segmentReader allows reading data in segments and returns flag if the segment is the last one (you cannot use plain
// io.Reader for this, because it may return io.EOF only during next read).
type segmentReader struct {
	segment     []byte
	nextSegment []byte
	// If -1, there is no current segment
	segmentLen int
	// If -1, there is no next segment
	nextSegmentLen int
}

func newSegmentReader(segmentSize int) segmentReader {
	return segmentReader{
		segment:        make([]byte, segmentSize),
		nextSegment:    make([]byte, segmentSize),
		segmentLen:     -1,
		nextSegmentLen: -1,
	}
}

// Reads next segment and returns the number of read bytes. If tagSize is set, only first segmentSize-tagSize elements
// are read for each segment. It must be zero for ciphertext readers and algorithm.tagSize() for plaintext readers.
func (s *segmentReader) readNext(r io.Reader, tagSize int) (int, error) {
	var total int
	if s.segmentLen != -1 {
		if s.nextSegmentLen == -1 {
			return total, errors.New("internal error: trying to read past EOF")
		}
		// Swap buffers.
		tmp := s.segment
		s.segment = s.nextSegment
		s.nextSegment = tmp
		s.segmentLen = s.nextSegmentLen
	} else {
		// Read the current segment first.
		n, err := io.ReadFull(r, s.segment[:len(s.segment)-tagSize])
		total += n
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			s.fail()
			return total, err
		}
		s.segmentLen = n
	}
	n, err := io.ReadFull(r, s.nextSegment[:len(s.nextSegment)-tagSize])
	total += n
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		s.fail()
		return total, err
	}
	if n > 0 {
		s.nextSegmentLen = n
	} else {
		s.nextSegmentLen = -1
	}
	return total, nil
}

// Drops the current segment (is there is any). This should be used when seeking the reader.
func (s *segmentReader) resetCurrent() {
	s.segmentLen = -1
	s.nextSegmentLen = -1
}

// Drops the current segment (is there is any) and also sets isLast. This means
func (s *segmentReader) fail() {
	s.segmentLen = 0
	s.nextSegmentLen = -1
}

// Returns current segment or nil if no segment has been read. See readNext for tagSize.
func (s *segmentReader) current(tagSize int) []byte {
	if s.segmentLen == -1 {
		return nil
	}
	return s.segment[:s.segmentLen+tagSize]
}

func (s *segmentReader) isLast() bool {
	return s.segmentLen != -1 && s.nextSegmentLen == -1
}

func (s *segmentReader) segmentSize() int {
	return len(s.segment)
}
