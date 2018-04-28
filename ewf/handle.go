package ewf

/*
#cgo LDFLAGS: -L.lib/ -lewf
#include "libewf/libewf.h"
#include <stdlib.h>
static char**makeCharArray(int size) {
    return calloc(sizeof(char*), size);
}

static char* makeCstring(ulong size) {
	return malloc(size);
}

static void setArrayString(char **a, char *s, int n) {
        a[n] = s;
}

static void freeCharArray(char **a, int size) {
        int i;
        for (i = 0; i < size; i++)
                free(a[i]);
        free(a);
}

static char* getCstring(char **a, int index) {
	return a[index];
}
*/
import "C"

import (
	"io"
	"errors"
	"unsafe"
	"strings"

	"github.com/vitaminwater/cgo.wchar"
	"fmt"
)

type EwfHandle struct {
	h *C.libewf_handle_t
}

type SectorRange struct {
	start uint64
	count uint64
}

func getLibEwfErrorString(msg string, cError *C.libewf_error_t) string {
	var cErrorMsg = unsafe.Pointer(C.makeCstring(512))
	defer C.free(cErrorMsg)

	if C.libewf_error_backtrace_sprint(cError, (*C.char)(cErrorMsg), 512) > 0 {
		return strings.Join([]string{msg, C.GoString((*C.char)(cErrorMsg))}, ": ")
	}
	return msg
}

func GetAccessFlagsRead() int {
	return int(C.libewf_get_access_flags_read())
}

func GetAccessFlagsReadWrite() int {
	return int(C.libewf_get_access_flags_read_write())
}

func GetAccessFlagsWrite() int {
	return int(C.libewf_get_access_flags_write())
}

func GetAccessFlagsWriteResume() int {
	return int(C.libewf_get_access_flags_write_resume())
}

func Glob(filename string) ([]string, error) {
	var cFilename = C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	var cError *C.libewf_error_t
	var ewfFilenames **C.char
	var ewfNumFilenames C.int

	if C.libewf_glob(cFilename, C.ulong(len(filename)), C.LIBEWF_FORMAT_UNKNOWN,
		&ewfFilenames, &ewfNumFilenames, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return []string{}, errors.New(getLibEwfErrorString("goewf: unable to create glob files", cError))
	}

	defer C.freeCharArray(ewfFilenames, ewfNumFilenames)

	var retFilenames = make([]string, int(ewfNumFilenames))
	for i := 0; i < int(ewfNumFilenames); i++ {
		retFilenames[i] = C.GoString(C.getCstring(ewfFilenames, C.int(i)))
	}

	return retFilenames, nil
}

func (e *EwfHandle) Init() error {
	var cError *C.libewf_error_t

	if C.libewf_handle_initialize(&e.h, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return errors.New(getLibEwfErrorString("goewf: unable to initialise ewf handle", cError))
	}
	return nil
}

func (e *EwfHandle) Free() error {
	var cError *C.libewf_error_t

	if C.libewf_handle_free(&e.h, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return errors.New(getLibEwfErrorString("goewf: unable to free ewf handle", cError))
	}
	return nil
}

func (e *EwfHandle) Clone(to *EwfHandle) error {
	var cError *C.libewf_error_t

	if C.libewf_handle_clone(&e.h, to.h, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return errors.New(getLibEwfErrorString("goewf: unable to clone ewf handle", cError))
	}
	return nil
}

func (e *EwfHandle) Open(filenames []string, accessFlags int) error {
	var cError *C.libewf_error_t

	var cFilenames = C.makeCharArray(C.int(len(filenames)))
	defer C.freeCharArray(cFilenames, C.int(len(filenames)))
	for i, s := range filenames {
		C.setArrayString(cFilenames, C.CString(s), C.int(i))
	}

	if C.libewf_handle_open(e.h, cFilenames, C.int(len(filenames)), C.int(accessFlags), &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return errors.New(getLibEwfErrorString("goewf: unable to open files", cError))
	}
	return nil
}

func (e *EwfHandle) Close() error {
	var cError *C.libewf_error_t

	if C.libewf_handle_close(e.h, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return errors.New(getLibEwfErrorString("goewf: unable to close ewf handle", cError))
	}
	return nil
}

func (e *EwfHandle) Read(size int, buffer *[]byte) (int64, error) {
	var cError *C.libewf_error_t

	if size == 0 {
		return 0, nil
	}

	if size < 0 || size > len(*buffer) {
		return 0, errors.New("goewf: invalid size")
	}

	var cBuffer = C.CBytes(*buffer)
	defer C.free(unsafe.Pointer(cBuffer))

	var readCount = int64(C.libewf_handle_read_buffer(e.h, cBuffer, C.ulong(size), &cError))
	if readCount == -1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to read", cError))
	}

	copy(*buffer, C.GoBytes(cBuffer, C.int(readCount)))
	return readCount, nil
}

func (e *EwfHandle) ReadAt(size int, buffer *[]byte, offset int) (int64, error) {
	var cError *C.libewf_error_t

	if size == 0 {
		return 0, nil
	}

	if size < 0 || size > len(*buffer) {
		return 0, errors.New("goewf: invalid size")
	}

	var cBuffer = C.CBytes(*buffer)
	defer C.free(unsafe.Pointer(cBuffer))

	var readCount = int64(C.libewf_handle_read_buffer_at_offset(e.h, cBuffer, C.ulong(size), C.long(offset), &cError))

	if readCount == -1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to read", cError))
	}

	copy(*buffer, C.GoBytes(cBuffer, C.int(readCount)))
	return readCount, nil
}

func (e *EwfHandle) Seek(offset int, origin int) (int64, error) {
	var cError *C.libewf_error_t

	if origin != io.SeekStart && origin != io.SeekCurrent && origin != io.SeekEnd {
		return -1, errors.New("goewf: invalid origin value")
	}

	retOffset := int64(C.libewf_handle_seek_offset(e.h, C.long(offset), C.int(origin), &cError))

	if retOffset == -1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to seek", cError))
	}

	return retOffset, nil
}

func (e *EwfHandle) Tell() (int64, error) {
	var cError *C.libewf_error_t

	var retOffset C.long

	if C.libewf_handle_get_offset(e.h, &retOffset, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get current offset", cError))
	}

	return int64(retOffset), nil
}

func (e *EwfHandle) GetSectorsPerChunk() (int, error) {
	var cError *C.libewf_error_t

	var sectorsPerChunk C.uint

	if C.libewf_handle_get_sectors_per_chunk(e.h, &sectorsPerChunk, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get sectors per chunk", cError))
	}

	return int(sectorsPerChunk), nil
}

func (e *EwfHandle) GetBytesPerSector() (int, error) {
	var cError *C.libewf_error_t

	var bytesPerSector C.uint

	if C.libewf_handle_get_bytes_per_sector(e.h, &bytesPerSector, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get bytes per sector", cError))
	}

	return int(bytesPerSector), nil
}

func (e *EwfHandle) GetChunkSize() (int, error) {
	var cError *C.libewf_error_t

	var chunkSize C.uint

	if C.libewf_handle_get_chunk_size(e.h, &chunkSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get chunk size", cError))
	}

	return int(chunkSize), nil
}

func (e *EwfHandle) GetErrorGranularity() (int, error) {
	var cError *C.libewf_error_t

	var errorGranularity C.uint

	if C.libewf_handle_get_error_granularity(e.h, &errorGranularity, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get error granularity", cError))
	}

	return int(errorGranularity), nil
}

func (e *EwfHandle) GetMediaSize() (int, error) {
	var cError *C.libewf_error_t

	var mediaSize C.ulong

	if C.libewf_handle_get_media_size(e.h, &mediaSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get media size", cError))
	}

	return int(mediaSize), nil
}

func (e *EwfHandle) GetMediaType() (int, error) {
	var cError *C.libewf_error_t

	var mediaType C.uchar

	if C.libewf_handle_get_media_type(e.h, &mediaType, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get media type", cError))
	}

	return int(mediaType), nil
}

func (e *EwfHandle) GetMediaFlags() (int, error) {
	var cError *C.libewf_error_t

	var mediaFlags C.uchar

	if C.libewf_handle_get_media_flags(e.h, &mediaFlags, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get media flags", cError))
	}

	return int(mediaFlags), nil
}

func (e *EwfHandle) GetFormat() (int, error) {
	var cError *C.libewf_error_t

	var format C.uchar

	if C.libewf_handle_get_format(e.h, &format, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get format", cError))
	}

	return int(format), nil
}

func (e *EwfHandle) GetNumberAcquiryErrors() (int, error) {
	var cError *C.libewf_error_t
	var numAcquiryErrors C.uint

	if C.libewf_handle_get_number_of_acquiry_errors(e.h, &numAcquiryErrors, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get number of acquiry errors", cError))
	}

	return int(numAcquiryErrors), nil
}

func (e *EwfHandle) GetAcquiryError(index uint) (SectorRange, error) {
	var cError *C.libewf_error_t
	var startSector C.ulong
	var sectorCount C.ulong

	if C.libewf_handle_get_acquiry_error(e.h, C.uint(index), &startSector, &sectorCount, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return SectorRange{}, errors.New(getLibEwfErrorString("goewf: unable to get acquiry error", cError))
	}

	return SectorRange{uint64(startSector), uint64(sectorCount)}, nil
}

func (e *EwfHandle) GetNumberOfChecksumErrors() (int, error) {
	var cError *C.libewf_error_t

	var numChecksumErrors C.uint

	if C.libewf_handle_get_number_of_checksum_errors(e.h, &numChecksumErrors, &cError) != 1 {
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get number of checksum errors", cError))
	}

	return int(numChecksumErrors), nil
}

func (e *EwfHandle) GetChecksumError(index int) (SectorRange, error) {
	var cError *C.libewf_error_t

	var start C.ulong
	var count C.ulong

	if C.libewf_handle_get_checksum_error(e.h, C.uint(index), &start, &count, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return SectorRange{}, errors.New(getLibEwfErrorString("goewf: unable to get checksum error", cError))
	}

	return SectorRange{uint64(start), uint64(count)}, nil
}

func (e *EwfHandle) GetNumberOfSessions() (int, error) {
	var cError *C.libewf_error_t

	var numberSessions C.uint

	if C.libewf_handle_get_number_of_sessions(e.h, &numberSessions, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get number of sessions", cError))
	}

	return int(numberSessions), nil
}

func (e *EwfHandle) GetSession(index int) (SectorRange, error) {
	var cError *C.libewf_error_t

	var start C.ulong
	var count C.ulong

	if C.libewf_handle_get_session(e.h, C.uint(index), &start, &count, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return SectorRange{}, errors.New(getLibEwfErrorString("goewf: unable to get session", cError))
	}

	return SectorRange{uint64(start), uint64(count)}, nil
}

func (e *EwfHandle) GetNumberOfTracks() (int, error) {
	var cError *C.libewf_error_t

	var numberTracks C.uint

	if C.libewf_handle_get_error_granularity(e.h, &numberTracks, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return 0, errors.New(getLibEwfErrorString("goewf: unable to get number of tracks", cError))
	}

	return int(numberTracks), nil
}

func (e *EwfHandle) GetTrack(index int) (SectorRange, error) {
	var cError *C.libewf_error_t

	var start C.ulong
	var count C.ulong

	if C.libewf_handle_get_track(e.h, C.uint(index), &start, &count, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return SectorRange{}, errors.New(getLibEwfErrorString("goewf: unable to get track", cError))
	}

	return SectorRange{uint64(start), uint64(count)}, nil
}

func (e *EwfHandle) GetNumberOfHeaderValues() (int, error) {
	var cError *C.libewf_error_t

	var numberHeaderValues C.uint

	if C.libewf_handle_get_number_of_header_values(e.h, &numberHeaderValues, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get error granularity", cError))
	}

	return int(numberHeaderValues), nil
}

func (e *EwfHandle) GetHeaderIdentifier(index int) (string, error) {
	var cError *C.libewf_error_t
	var headerIdentifierSize C.ulong

	if C.libewf_handle_get_header_value_identifier_size(e.h, C.uint(index), &headerIdentifierSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get header identifier size", cError) )
	}

	if headerIdentifierSize == 0 {
		return "", nil
	}

	var headerIdentifier = C.makeCstring(headerIdentifierSize)
	defer C.free(unsafe.Pointer(headerIdentifier))

	if C.libewf_handle_get_header_value_identifier(e.h,
												   C.uint(index),
												   (*C.uchar)(unsafe.Pointer(headerIdentifier)),
												   headerIdentifierSize,
												   &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get header identifier", cError))
	}

	return C.GoString(headerIdentifier), nil
}

func (e *EwfHandle) GetHeaderValue(identifier string) (string, error) {
	var cError *C.libewf_error_t
	var headerValueSize C.ulong
	var cIdentifierSize = C.ulong(len(identifier))
	var cIdentifier = C.CString(identifier)
	defer C.free(unsafe.Pointer(cIdentifier))

	result := C.libewf_handle_get_utf16_header_value_size(e.h,
														  (*C.uchar)(unsafe.Pointer(cIdentifier)),
														  cIdentifierSize,
														  &headerValueSize,
														  &cError)
	if result == -1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get header value size", cError))
	} else if result == 0  {
		return "", nil
	}

	var headerValue = wchar.NewWcharString(int(headerValueSize))

	if C.libewf_handle_get_utf16_header_value(e.h,
		                                      (*C.uchar)(unsafe.Pointer(cIdentifier)),
		                                      cIdentifierSize,
											  (*C.ushort)(unsafe.Pointer(headerValue.Pointer())),
		                                      headerValueSize,
		                                      &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get header value", cError))
	}

	goHeaderValue, err := headerValue.GoString()
	if err != nil {
		return "", errors.New("goewf: unable to convert header value to gostring")
	}

	return goHeaderValue, nil
}

func (e *EwfHandle) GetNumberOfHashValues() (int, error) {
	var cError *C.libewf_error_t

	var numberHashValues C.uint

	if C.libewf_handle_get_number_of_hash_values(e.h, &numberHashValues, &cError) != 1 {
		return -1, errors.New(getLibEwfErrorString("goewf: unable to get number of hash values", cError))
	}

	return int(numberHashValues), nil
}

func (e *EwfHandle) GetHashValueIdentifier(index int) (string, error) {
	var cError *C.libewf_error_t
	var hashValueIdentifierSize C.ulong

	if C.libewf_handle_get_hash_value_identifier_size(e.h, C.uint(index), &hashValueIdentifierSize, &cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get hash value identifier size", cError) )
	}

	if hashValueIdentifierSize == 0 {
		return "", nil
	}

	var hashValueIdentifier = C.makeCstring(hashValueIdentifierSize)
	defer C.free(unsafe.Pointer(hashValueIdentifier))

	if C.libewf_handle_get_hash_value_identifier(e.h,
												C.uint(index),
												(*C.uchar)(unsafe.Pointer(hashValueIdentifier)),
												hashValueIdentifierSize,
												&cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get hash value identifier", cError))
	}

	return C.GoString(hashValueIdentifier), nil
}

func (e *EwfHandle) GetHashValue(identifier string) (string, error) {
	var cError *C.libewf_error_t
	var hashValueSize C.ulong
	var cIdentifierSize = C.ulong(len(identifier))
	var cIdentifier = C.CString(identifier)
	defer C.free(unsafe.Pointer(cIdentifier))

	result := C.libewf_handle_get_utf16_hash_value_size(e.h,
														(*C.uchar)(unsafe.Pointer(cIdentifier)),
														cIdentifierSize,
														&hashValueSize,
														&cError)
	if result == -1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get hash value size", cError))
	} else if result == 0  {
		return "", nil
	}

	var hashValue = wchar.NewWcharString(int(hashValueSize))

	if C.libewf_handle_get_utf16_hash_value(e.h,
											(*C.uchar)(unsafe.Pointer(cIdentifier)),
											cIdentifierSize,
											(*C.ushort)(unsafe.Pointer(hashValue.Pointer())),
											hashValueSize,
											&cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return "", errors.New(getLibEwfErrorString("goewf: unable to get hash value", cError))
	}

	goHashValue, err := hashValue.GoString()
	if err != nil {
		return "", errors.New("goewf: unable to convert hash value to gostring")
	}

	return goHashValue, nil
}

func (e* EwfHandle) GetRootFileEntry() (FileEntry, error) {
    var fileEntry FileEntry
    var cError *C.libewf_error_t

    var result = int(C.libewf_handle_get_root_file_entry(e.h, &fileEntry.h, &cError))
    fmt.Println(result)
    if result == -1 {
   		defer C.free(unsafe.Pointer(cError))
   		return FileEntry{}, errors.New(getLibEwfErrorString("goewf: unable to get root file entry", cError))
    } else if result == 0 {
		return FileEntry{}, nil
    } else if result != 1 {
		return FileEntry{}, errors.New("goewf: unknown error")
	}

   return fileEntry, nil
}

func (e* EwfHandle) GetFileEntryByPath(path string) (FileEntry, error) {
	var fileEntry FileEntry
	var cError *C.libewf_error_t

	var cPath = wchar.NewWcharString(len(path))

	if C.libewf_handle_get_file_entry_by_utf16_path(e.h,
													(*C.ushort)(unsafe.Pointer(cPath.Pointer())),
													C.ulong(len(path)),
													&fileEntry.h,
													&cError) != 1 {
		defer C.free(unsafe.Pointer(cError))
		return FileEntry{}, errors.New(getLibEwfErrorString("goewf: unable to get root file entry", cError))
	}

	return fileEntry, nil
}