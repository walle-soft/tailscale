// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// package logproto contains components for the SSH Session Hauling protocol.
package logproto

// The SSH Session Hauling Protocol.
//
// The SSH Session Hauling Protocol transports SSH session logs from a source
// to a destination node within Tailscale.
//
// The protocol runs over an upgraded HTTP/1.1 connection. The upgrade is done
// using the "ts-ssh-haul" Upgrade header. The client must send the name of the
// session file to create as the SSH-Session-Name header.
//
// After the server has performed the upgrade, frames may be sent. The client
// begins by sending a Resume frame, the server replies with a Resume frame
// indicating the last log line it has persisted. If it hasn't persisted
// anything it returns 0. The client then begins sending Log Message frames,
// each of which includes a single JSON log line. The client should send an Ack
// frame with an ID of 0 after a batch of Log Message frames. The server will
// then send an Ack frame in reply with the highest Log Message frame it has
// persisted. The client should only have a small number of unacknowledged Log
// Message frames. When the client needs to close the connection it should send
// a Reset frame, which will close the send side of the connection. A client
// must not send any frames after sending a Reset frame. In practice this means
// that the client should send a final Ack frame and wait for the response to
// ensure all Log Message frames have been processed and then send a Rst frame.
//
// The server, upon completing the upgrade, waits for a Resume frame and
// replies with the highest log message it has persisted, ignoring any half
// written lines at the end of the log, then it waits for the client to send
// Log Message frames. Upon receiving frames the server persists the log line
// to disk. Upon receiving an Ack frame the server replies with the highest
// line it has persisted. Upon receiving a Reset frame, the server replies with
// a Rst frame of its own with an identifier of the last processed log line
// plus one. After the server sends the Reset frame it may close the
// connection. After the client receives the Reset frame from the server, it
// may close the connection.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"tailscale.com/types/logger"
)

var ErrIrreconcilable = errors.New("client and server state are irreconcilable")
var ErrClosed = errors.New("client is closed")

const UpgradeProto = "ts-ssh-log"

// FrameHeaderSize is the size of a frame header. 4 bytes for length, 1 byte
// for type, and 8 bytes for the identifier.
const FrameHeaderSize = 13

// FrameType is used to identify the type of a given frame.
type FrameType uint8

// These are the types of frames:
const (
	FTUndefined FrameType = 0 // Invalid frame
	FTLogMsg    FrameType = 1 // Log Message
	FTAck       FrameType = 2 // Acknowledgement
	FTResume    FrameType = 3 // Resume Sending Logs
	FTRst       FrameType = 4 // Close stream
)

func (ft FrameType) String() string {
	switch ft {
	case FTUndefined:
		return "undefined"
	case FTLogMsg:
		return "log message"
	case FTAck:
		return "acknowledgement"
	case FTResume:
		return "resume"
	case FTRst:
		return "reset"
	default:
		return "unknown"
	}
}

// Identifier is the position of the log line within the resulting .cast file.
// We send it explicitly so that we can perform acknowledgements and resume a
// stream that is interrupted.
type Identifier uint64

// DecodeHeader reads the length, frame type, and identifier from a slice of
// bytes representing the frame header.
func DecodeHeader(hdr [13]byte) (uint32, FrameType, uint64) {
	l := binary.BigEndian.Uint32(hdr[0:4])
	ft := FrameType(hdr[4])
	id := binary.BigEndian.Uint64(hdr[5:])
	return l, ft, id
}

type FrameBuilder struct{}

func (fb FrameBuilder) LogMessage(id uint64, msg []byte) []byte {
	buf := make([]byte, 0, FrameHeaderSize)
	return fb.AppendLogMessage(buf, id, msg)
}

func (FrameBuilder) AppendLogMessage(dst []byte, id uint64, msg []byte) []byte {
	// 4 byte length + 1 byte type + 8 byte ID + msg length
	var l = uint32(13 + len(msg))
	dst = binary.BigEndian.AppendUint32(dst, l)
	dst = append(dst, byte(FTLogMsg))
	dst = binary.BigEndian.AppendUint64(dst, id)
	return append(dst, msg...)
}

func (fb FrameBuilder) Ack(ack uint64) []byte {
	return fb.AppendAck(make([]byte, 0, FrameHeaderSize), ack)
}

func (fb FrameBuilder) AppendAck(dst []byte, ack uint64) []byte {
	return fb.nopayload(dst, ack, FTAck)
}

func (fb FrameBuilder) Resume(maxAck uint64) []byte {
	return fb.AppendResume(make([]byte, 0, FrameHeaderSize), maxAck)
}

func (fb FrameBuilder) AppendResume(dst []byte, maxAck uint64) []byte {
	return fb.nopayload(dst, maxAck, FTResume)
}

func (fb FrameBuilder) Reset(id uint64) []byte {
	return fb.AppendReset(make([]byte, 0, FrameHeaderSize), id)
}

func (fb FrameBuilder) AppendReset(dst []byte, id uint64) []byte {
	return fb.nopayload(dst, id, FTRst)
}

func (FrameBuilder) nopayload(dst []byte, id uint64, ft FrameType) []byte {
	dst = binary.BigEndian.AppendUint32(dst, FrameHeaderSize)
	dst = append(dst, byte(ft))
	return binary.BigEndian.AppendUint64(dst, id)
}

type logindex struct {
	offsets []int64 // offsets for each log line
	startID uint64  // the log line number of the offsets[0]
	eof     int64   // offset of the last byte of the last full log line
}

func newlogindex() *logindex {
	return &logindex{offsets: make([]int64, 0)}
}

func (li *logindex) reset() {
	li.offsets = li.offsets[:0]
	li.startID = 0
	li.eof = 0
}

// addOffset adds an offset to the index at the end. It is assumed that
// this offset will be the next log line in the file.
func (li *logindex) addOffset(offset int64) {
	li.offsets = append(li.offsets, offset)
}

func (li *logindex) contains(id uint64) bool {
	return id >= li.startID && id < li.startID+uint64(len(li.offsets))
}

// next returns an offset to start reading at and the number of bytes to
// read given the start log line ID and a maximum number of log lines.
//
// returns -1, 0 if start is not within in the index.
func (li *logindex) next(start uint64, max int) (offset, length int64, count int) {
	if !li.contains(start) {
		return -1, 0, 0
	}
	idx := int(start - li.startID)
	offset = li.offsets[idx]
	if len(li.offsets[idx:]) > max {
		return offset, li.offsets[idx+max] - offset, len(li.offsets[idx : idx+max])
	}
	return offset, li.eof - offset, len(li.offsets[idx:])
}

func (li *logindex) ack(id uint64) bool {
	if !li.contains(id) {
		return false
	}
	idx := int(id-li.startID) + 1
	li.offsets = li.offsets[idx:]
	li.startID = id + 1
	return true
}

type Client struct {
	fb   FrameBuilder
	logf logger.Logf
	li   *logindex

	src io.ReadSeekCloser // .cast file

	mu     sync.Mutex
	closed chan struct{}
	ping   chan struct{}
}

func NewClient(logf logger.Logf, src io.ReadSeekCloser) *Client {
	return &Client{
		logf:   logf,
		ping:   make(chan struct{}, 1),
		closed: make(chan struct{}, 1),
		src:    src,
		li:     newlogindex(),
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return nil
	default:
	}
	close(c.closed)
	return nil // We don't close the file here because we need to do some cleanup.
}

func (c *Client) Run(ctx context.Context, dst io.ReadWriter) error {
	// TODO(skriptble): When we've closed the client we don't want to exit immediately,
	// instead we want to attempt to finish sending the logs to the other end.
	// Alternatively we might want to have the server connect to this node and attempt
	// to pull any remaining log lines that might have been missed in the shutdown
	// process.
	select {
	case <-c.closed:
		return ErrClosed
	default:
	}
	const maxframes = 100 // arbitrary
	var fb FrameBuilder
	var hdr [13]byte

	// On the first run, we'll need to build the index.
	if c.li.startID == 0 {
		err := c.extendIndex(0)
		if err != nil {
			return fmt.Errorf("couldn't extend index on first run: %w", err)
		}
	}

	// First send a Resume frame to understand where to start sending from.
	resume := fb.Resume(0)
	_, err := dst.Write(resume)
	if err != nil {
		c.logf("Couldn't write resume frame: %v", err)
		return fmt.Errorf("couldn't write resume frame: %w", err)
	}
	_, err = io.ReadFull(dst, hdr[:])
	if err != nil {
		c.logf("Couldn't read response to resume frame: %v", err)
		return fmt.Errorf("couldn't read response resume frame: %w", err)
	}
	l, ft, id := DecodeHeader(hdr)
	if ft != FTResume || l != 13 {
		// TODO(skriptble): Is there any reason we shouldn't just accept
		// any frame and throw away incorrect ones?
		return fmt.Errorf("incorrect frame type %q or length %d", ft, l)
	}
	if !c.li.contains(id) {
		// This is an edge case where the server previous acknowledged receipt
		// of log lines but no longer has them. Someone probably deleted the
		// file and restarted tailscaled.
		err = c.extendIndex(id)
		if err != nil {
			return fmt.Errorf("couldn't extend index: %w", err)
		}
		if !c.li.contains(id) {
			// If the id still isn't within the index that means the ID we were
			// given isn't from this file, or the server has a bug and it's
			// requesting a log line beyond what it's acknowledged and what we
			// have.
			return fmt.Errorf("server requesting invalid log line id %d", id)
		}
	}

	// Send frames until we've caught up, and then wait for a notification that
	// there are more log lines to process and send.
	for {
		offset, length, count := c.li.next(id, maxframes)
		if offset < 0 {
			select {
			case <-c.ping:
				err = c.extendIndex(id)
				if err != nil {
					c.logf("Couldn't extend index within ping: %v", err)
					return fmt.Errorf("couldn't extend index within ping: %w", err)
				}
				continue
			case <-ctx.Done():
				// TODO(skriptble): Attempt to perform a clean shutdown?
				return ctx.Err()
			case <-c.closed:
				defer c.src.Close()
				rst := fb.Reset(id + 1)
				_, err := dst.Write(rst)
				if err != nil {
					c.logf("couldn't shutdown hauling cleanly: %v", err)
					return ErrClosed
				}
				_, err = io.ReadFull(dst, hdr[:])
				if err != nil {
					c.logf("couldn't read response RST frame: %v", err)
					return ErrClosed
				}
				l, ft, rstid := DecodeHeader(hdr)
				if ft != FTRst || l != 13 || rstid != id+1 {
					c.logf("didn't receive correct frame during shutdown: type=%s", ft)
				}
				return ErrClosed
			}
		}

		frames, err := c.readFrames(id, offset, length, count)
		if err != nil {
			c.logf("Couldn't read frames: %v", err)
			return fmt.Errorf("couldn't read frame: %w", err)
		}

		_, err = dst.Write(frames)
		if err != nil {
			c.logf("couldn't write frames: %v", err)
			return fmt.Errorf("couldn't write frames: %w", err)
		}

		_, err = io.ReadFull(dst, hdr[:])
		if err != nil {
			c.logf("Couldn't read response: %v", err)
			return fmt.Errorf("couldn't read response from frame write: %w", err)
		}
		l, ft, id = DecodeHeader(hdr)
		if ft != FTAck || l != 13 {
			return fmt.Errorf("incorrect frame type %q or length %d", ft, l)
		}
		c.li.ack(id) // This can technically fail, but not sure what we should do when it does.
	}
}

// readFrames will read frames from the underlying storage and return log lines
// found as LogMsg frames with an Ack frame at the end.
//
// start is the ID of the log line starting at offset.
func (c *Client) readFrames(start uint64, offset, length int64, count int) ([]byte, error) {
	// Read bytes.
	_, err := c.src.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		panic(fmt.Errorf("Invalid length: %d start=%d offset=%d c.li=%#v", length, start, offset, c.li))
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(c.src, buf)
	if err != nil {
		return nil, err
	}
	// We need a buffer that is len(buf) + (13 * len(lines)) + 13 large.
	// The additional 13 bytes is for an Ack frame.
	out := make([]byte, 0, len(buf)+(13*count))
	id := start
	for {
		idx := bytes.IndexByte(buf, byte('\n'))
		if idx == -1 {
			break
		}
		out = c.fb.AppendLogMessage(out, id, buf[:idx+1])
		id++
		buf = buf[idx+1:]
	}
	if len(out) == 0 {
		c.logf("found no log lines: start=%d, offset=%d, length=%d, buf=%s", start, offset, length, buf)
		return nil, errors.New("no log lines found")
	}
	out = c.fb.AppendAck(out, 0)
	c.logf("read frames #lines=%d start=%d offset=%d length=%d", id-start, start, offset, length)
	return out, nil
}

// extendIndex extends the index, beginning at log line start.
func (c *Client) extendIndex(start uint64) error {
	// We're either trying to extend the front of the index or the back
	// of the index.

	// If we're trying to add to the front of the index, just reset the index
	// and rebuild the entire thing. This isn't efficient, but the case where
	// we actually need to do this should be rare (e.g. file disappeared on
	// the server side).
	if start < c.li.startID {
		c.li.reset()
	}

	// Determine the difference between our current EOF and the actual EOF.
	eof, err := c.src.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if eof <= c.li.eof {
		// The file is empty so there's nothing for us to index.
		return nil
	}
	offset, err := c.src.Seek(c.li.eof, io.SeekStart)
	if err != nil {
		return err
	}
	remaining := eof - offset // remaining bytes to read
	chunk := int64(1 << 14)   // Read 16k chunks (arbitrarily picked).
	buf := make([]byte, 0, chunk)
	potential := offset
	for {
		if remaining == 0 {
			break
		}
		if chunk > remaining {
			chunk = remaining
			buf = buf[:chunk]
		}
		// c.logf("doing a read: eof=%d potential=%d remaining=%d chunk=%d c.li.eof=%d", eof, potential, remaining, chunk, c.li.eof)
		n, err := io.ReadFull(c.src, buf)
		if err != nil {
			c.logf("problem reading: remaining=%d, buflen=%d, eof=%d, err=%v", remaining, len(buf), eof, err)
			return err
		}
		var bufpos int64 // number of bytes we've truncated buf by
		for {
			pos := bytes.IndexByte(buf, byte('\n'))
			if pos == -1 {
				break
			}
			// c.logf("adding potential offset: %d", potential)
			c.li.addOffset(potential)
			potential = offset + bufpos + int64(pos) + 1 // new potential offset is the byte after newline
			// c.logf("new potential: %d", potential)
			bufpos += int64(len(buf[:pos+1]))
			buf = buf[pos+1:]
		}
		offset += int64(n)
		remaining -= chunk
	}
	c.li.eof = potential // might be actual EOF or first byte of partially written log line
	c.logf("extended index: %#v", c.li)
	return nil
}

func (c *Client) Notify() {
	if c == nil {
		return
	}
	select {
	case c.ping <- struct{}{}:
	default:
	}
}

type Server struct {
	dst  io.ReadWriteSeeker
	logf logger.Logf
}

func NewServer(dst io.ReadWriteSeeker, logf logger.Logf) *Server {
	return &Server{dst: dst, logf: logf}
}

func (s *Server) Run(ctx context.Context, src io.ReadWriteCloser) error {
	var fb FrameBuilder
	var hdr [13]byte

	// First read a Resume frame and reply with the current log line.
	_, err := io.ReadFull(src, hdr[:])
	if err != nil {
		return err
	}
	l, ft, id := DecodeHeader(hdr)
	if ft != FTResume || l != 13 || id != 0 {
		return fmt.Errorf("incorrect frame type %q or length %d", ft, l)
	}
	lines, err := s.countLines()
	if err != nil {
		return err
	}
	resume := fb.Resume(lines)
	_, err = src.Write(resume)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// If we get a context cancel or timeout, just close the connection.
		<-ctx.Done()
		src.Close()
	}()
	for {
		_, err = io.ReadFull(src, hdr[:])
		if err != nil {
			return err
		}
		l, ft, id = DecodeHeader(hdr)
		switch ft {
		case FTLogMsg:
			if id != lines {
				s.logf("logoproto-server unexpected log message: expected=%d got=%d", lines, id)
				return fmt.Errorf("incorrect log message ID: expected=%d got=%d", lines, id)
			}
			n, err := io.CopyN(s.dst, src, int64(l-FrameHeaderSize))
			if err != nil {
				return err
			}
			s.logf("received log line for line=%d id=%d wrote %d bytes", lines, id, n)
			lines++
		case FTAck:
			ack := fb.Ack(lines)
			_, err = src.Write(ack)
			if err != nil {
				s.logf("logproto-server couldn't send ack: %v", err)
				return err
			}
			s.logf("received ack for id=%d sending ack of lines=%d", id, lines)
		case FTRst:
			lines++
			rst := fb.Reset(lines)
			_, err = src.Write(rst)
			if err != nil {
				s.logf("logproto-server received error while writing rst: %v", err)
			}
			return nil // Ignore the error since we're shutting down the stream.
		case FTResume, FTUndefined:
			return fmt.Errorf("incorrect frame type %q", ft)
		default:
			return fmt.Errorf("unknown frame type %q (%d)", ft, ft)
		}
	}
}

// countLines counts the number of lines in s.dst. It leaves s.dst at the end of the
// file, if the file ends with a newline, or at the byte after the newline. This
// is useful for callers as it ensures that any half written lines can be overwritten.
func (s *Server) countLines() (uint64, error) {
	// Find the end of the file.
	eof, err := s.dst.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	// Don't bother doing anything if the file is empty.
	if eof == 0 {
		return 0, nil
	}
	_, err = s.dst.Seek(0, io.SeekStart)
	remaining := eof
	chunk := int64(1 << 14)
	buf := make([]byte, 0, chunk)
	var count uint64
	var lastNewline int
	var offset int
	for {
		if remaining == 0 {
			break
		}
		if chunk > remaining {
			chunk = remaining
			buf = buf[:chunk] // We only need to do this when we make the chunk smaller.
		}
		n, err := io.ReadFull(s.dst, buf)
		if err != nil {
			return 0, err
		}
		count += uint64(bytes.Count(buf, []byte("\n")))
		if last := bytes.LastIndexByte(buf, byte('\n')); last != -1 {
			lastNewline = offset + last
		}
		offset += n
		remaining -= chunk
	}
	_, err = s.dst.Seek(int64(lastNewline)+1, io.SeekStart)
	return count, err
}
