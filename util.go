// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

package oae

import "io"

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
