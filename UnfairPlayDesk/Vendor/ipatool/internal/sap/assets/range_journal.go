package assets

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const rangeJournalLimit = 64 << 20
const rangeRecordHeader = 44

type rangeKey struct {
	offset int64
	length uint32
}
type rangeRecord struct {
	position int64
	digest   [32]byte
}
type rangeJournal struct {
	sync.Mutex
	file    *os.File
	records map[rangeKey]rangeRecord
	end     int64
}

// Persist small, public restore-image metadata reads, not app/account data.
// Asset preparation holds the cross-process lock while this file is open.
func openRangeJournal() (*rangeJournal, error) {
	directory, err := cacheDirectory()
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(filepath.Dir(directory), "restore-26A434-index-v1.bin"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	journal := &rangeJournal{file: file, records: make(map[rangeKey]rangeRecord)}
	header := make([]byte, rangeRecordHeader)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	for journal.end < rangeJournalLimit {
		if _, err := file.ReadAt(header, journal.end); err != nil {
			break
		}
		offset, length := int64(binary.LittleEndian.Uint64(header)), binary.LittleEndian.Uint32(header[8:])
		if offset < 0 || length == 0 || length > remoteSmallReadSize || journal.end+rangeRecordHeader+int64(length) > rangeJournalLimit {
			break
		}
		record := rangeRecord{position: journal.end + rangeRecordHeader}
		copy(record.digest[:], header[12:])
		if record.position+int64(length) > info.Size() {
			break
		}
		journal.records[rangeKey{offset, length}] = record
		journal.end = record.position + int64(length)
	}
	if err := file.Truncate(journal.end); err != nil {
		file.Close()
		return nil, err
	}
	return journal, nil
}

func (j *rangeJournal) read(data []byte, offset int64) bool {
	if len(data) > remoteSmallReadSize {
		return false
	}
	j.Lock()
	defer j.Unlock()
	record, ok := j.records[rangeKey{offset, uint32(len(data))}]
	if !ok {
		return false
	}
	_, err := j.file.ReadAt(data, record.position)
	return err == nil && sha256.Sum256(data) == record.digest
}

func (j *rangeJournal) store(data []byte, offset int64) {
	if len(data) == 0 || len(data) > remoteSmallReadSize {
		return
	}
	j.Lock()
	defer j.Unlock()
	if j.end+rangeRecordHeader+int64(len(data)) > rangeJournalLimit {
		return
	}
	digest := sha256.Sum256(data)
	header := make([]byte, rangeRecordHeader)
	binary.LittleEndian.PutUint64(header, uint64(offset))
	binary.LittleEndian.PutUint32(header[8:], uint32(len(data)))
	copy(header[12:], digest[:])
	if n, err := j.file.WriteAt(header, j.end); err != nil || n != len(header) {
		return
	}
	position := j.end + rangeRecordHeader
	if n, err := j.file.WriteAt(data, position); err != nil || n != len(data) {
		return
	}
	j.records[rangeKey{offset, uint32(len(data))}] = rangeRecord{position, digest}
	j.end = position + int64(len(data))
}

func (j *rangeJournal) Close() error { return j.file.Close() }

var _ io.Closer = (*rangeJournal)(nil)
