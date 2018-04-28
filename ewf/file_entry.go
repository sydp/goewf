package ewf

/*
#cgo LDFLAGS: -L.lib/ -lewf
#include "libewf/libewf.h"
#include <stdlib.h>

static char* makeCstring(ulong size) {
	return malloc(size);
}
*/
import "C"
import (
	"errors"
	"time"
	"unsafe"
	"io"
)

type FileEntry struct {
	h *C.libewf_file_entry_t
}

func (e *FileEntry) IsValid() bool {
	return e.h != nil
}

func (e *FileEntry) Free() (error) {
	var cError *C.libewf_error_t

	if C.libewf_file_entry_free(&e.h, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return errors.New(getLibEwfErrorString("goewf: unable to free ewf file entry handle", cError))
	}
	return nil
}

func (e *FileEntry) GetType() (uint8, error) {
	var cError *C.libewf_error_t

	var fileEntryType C.uchar

	if C.libewf_file_entry_get_type(e.h, &fileEntryType, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get file entry type", cError))
	}

	return uint8(fileEntryType), nil
}

func (e *FileEntry) GetFlags() (uint32, error) {
	var cError *C.libewf_error_t

	var fileEntryFlags C.uint

	if C.libewf_file_entry_get_flags(e.h, &fileEntryFlags, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get file entry flags", cError))
	}

	return uint32(fileEntryFlags), nil
}

func (e *FileEntry) GetMediaDataOffset() (int64, error) {
	var cError *C.libewf_error_t

	var mediaDataOffset C.long

	if C.libewf_file_entry_get_media_data_offset(e.h, &mediaDataOffset, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get media data offset", cError))
	}

	return int64(mediaDataOffset), nil
}

func (e *FileEntry) GetMediaDataSize() (uint64, error) {
	var cError *C.libewf_error_t

	var mediaDataSize C.ulong

	if C.libewf_file_entry_get_media_data_size(e.h, &mediaDataSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get media data size", cError))
	}

	return uint64(mediaDataSize), nil
}

func (e *FileEntry) GetDuplicateMediaDataOffset() (int64, error) {
	var cError *C.libewf_error_t

	var mediaDuplicateMediaDataOffset C.long

	if C.libewf_file_entry_get_duplicate_media_data_offset(e.h, &mediaDuplicateMediaDataOffset, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get duplicate media data offset", cError))
	}

	return int64(mediaDuplicateMediaDataOffset), nil
}

func (e *FileEntry) GetName() (string, error) {
	var cError *C.libewf_error_t
	var fileEntryNameSize C.ulong

	if C.libewf_file_entry_get_utf8_name_size(e.h, &fileEntryNameSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get file entry name size", cError))
	}

	if uint64(fileEntryNameSize) == 0 {
		return "", nil
	}

	var fileEntryName = C.makeCstring(fileEntryNameSize)
	defer C.free(unsafe.Pointer(fileEntryName))

	if C.libewf_file_entry_get_utf8_name(e.h, (*C.uchar)(unsafe.Pointer(fileEntryName)), fileEntryNameSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get file entry name", cError))
	}

	return C.GoString(fileEntryName), nil
}

func (e *FileEntry) GetSize() (uint64, error) {
	var cError *C.libewf_error_t

	var fileEntrySize C.ulong

	if C.libewf_file_entry_get_size(e.h, &fileEntrySize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get file entry size", cError))
	}

	return uint64(fileEntrySize), nil
}

func (e *FileEntry) GetCreationTime() (time.Time, error) {
	var cError *C.libewf_error_t

	var fileEntryCreationTime C.uint

	if C.libewf_file_entry_get_creation_time(e.h, &fileEntryCreationTime, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return time.Time{}, errors.New(getLibEwfErrorString("goewf: unable to get file entry creation time", cError))
	}

	return time.Unix(int64(fileEntryCreationTime), 0), nil
}

func (e *FileEntry) GetModificationTime() (time.Time, error) {
	var cError *C.libewf_error_t

	var fileEntryModificationTime C.uint

	if C.libewf_file_entry_get_modification_time(e.h, &fileEntryModificationTime, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return time.Time{}, errors.New(getLibEwfErrorString("goewf: unable to get file entry modification time", cError))
	}

	return time.Unix(int64(fileEntryModificationTime), 0), nil
}

func (e *FileEntry) GetAccessTime() (time.Time, error) {
	var cError *C.libewf_error_t

	var fileEntryAccessTime C.uint

	if C.libewf_file_entry_get_access_time(e.h, &fileEntryAccessTime, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return time.Time{}, errors.New(getLibEwfErrorString("goewf: unable to get file entry access time", cError))
	}

	return time.Unix(int64(fileEntryAccessTime), 0), nil
}

func (e *FileEntry) GetEntryModificationTime() (time.Time, error) {
	var cError *C.libewf_error_t

	var fileEntryEntryModificationTime C.uint

	if C.libewf_file_entry_get_entry_modification_time(e.h, &fileEntryEntryModificationTime, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return time.Time{}, errors.New(getLibEwfErrorString("goewf: unable to get file entry entry modification time", cError))
	}

	return time.Unix(int64(fileEntryEntryModificationTime), 0), nil
}

func (e *FileEntry) GetHashValueMD5() (string, error) {
	var cError *C.libewf_error_t
	var fileEntryHash = C.makeCstring(33)
	defer C.free(unsafe.Pointer(fileEntryHash))

	if C.libewf_file_entry_get_utf8_hash_value_md5(e.h, (*C.uchar)(unsafe.Pointer(fileEntryHash)), 33, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get file entry MD5", cError))
	}

	return C.GoString(fileEntryHash), nil
}

func (e *FileEntry) GetHashValueSHA1() (string, error) {
	var cError *C.libewf_error_t
	var fileEntryHash = C.makeCstring(33)
	defer C.free(unsafe.Pointer(fileEntryHash))

	if C.libewf_file_entry_get_utf8_hash_value_sha1(e.h, (*C.uchar)(unsafe.Pointer(fileEntryHash)), 33, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get file entry SHA1", cError))
	}

	return C.GoString(fileEntryHash), nil
}

func (e *FileEntry) GetNumberOfSubFileEntries() (int, error) {
	var cError *C.libewf_error_t

	var numSubFileEntries C.int

	if C.libewf_file_entry_get_number_of_sub_file_entries(e.h, &numSubFileEntries, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get number of subfile entries", cError))
	}

	return int(numSubFileEntries), nil
}

func (e *FileEntry) GetSubFileEntry(subFileEntryIndex int) (FileEntry, error) {
	var cError *C.libewf_error_t
	var subFileEntry = FileEntry{}

	if C.libewf_file_entry_get_sub_file_entry(e.h, C.int(subFileEntryIndex), &subFileEntry.h, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return FileEntry{}, errors.New(getLibEwfErrorString("goewf: unable to get sub file entry", cError))
	}

	return subFileEntry, nil
}

func (e *FileEntry) ReadBuffer(size int, buffer *[]byte) (int, error) {
	var cError *C.libewf_error_t

	if size == 0 {
		return 0, nil
	}

	if size < 0 || size > len(*buffer) {
		return 0, errors.New("goewf: invalid size")
	}

	var cBuffer = C.CBytes(*buffer)
	defer C.free(unsafe.Pointer(cBuffer))

	var readCount = int(C.libewf_file_entry_read_buffer(e.h, cBuffer, C.ulong(size), &cError))
	if readCount == -1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to read from file entry", cError))
	}

	copy(*buffer, C.GoBytes(cBuffer, C.int(readCount)))
	return readCount, nil
}

func (e *FileEntry) ReadBufferAtOffset(size int, buffer *[]byte, offset int64) (int64, error) {
	var cError *C.libewf_error_t

	if size == 0 {
		return 0, nil
	}

	if size < 0 || size > len(*buffer) {
		return 0, errors.New("goewf: invalid size")
	}

	var cBuffer = C.CBytes(*buffer)
	defer C.free(unsafe.Pointer(cBuffer))

	var readCount = int64(C.libewf_file_entry_read_buffer_at_offset(e.h, cBuffer, C.ulong(size), C.long(offset), &cError))

	if readCount == -1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to read at file entry offset", cError))
	}

	copy(*buffer, C.GoBytes(cBuffer, C.int(readCount)))
	return readCount, nil
}

func (e *FileEntry) SeekOffset(offset int64, origin int) (int64, error) {
	var cError *C.libewf_error_t

	if origin != io.SeekStart && origin != io.SeekCurrent && origin != io.SeekEnd {
		return -1, errors.New("goewf: invalid origin value")
	}

	retOffset := int64(C.libewf_file_entry_seek_offset(e.h, C.long(offset), C.int(origin), &cError))

	if retOffset == -1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to seek file entry", cError))
	}

	return retOffset, nil
}

func (e *FileEntry) GetOffset() (int, error) {
	var cError *C.libewf_error_t

	var retOffset C.long

	if C.libewf_file_entry_get_offset(e.h, &retOffset, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get current offset", cError))
	}

	return int(retOffset), nil
}