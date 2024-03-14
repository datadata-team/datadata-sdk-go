package cryptoutils

import (
	"bytes"
	"errors"
	"fmt"
)

// PKCS7Pad adds PKCS7 padding to the data block, http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
func PKCS7Pad(message []byte, blockSize int) (padded []byte, err error) {
	// block size must be bigger or equal 2
	if blockSize < 1<<1 {
		err = errors.New("block size is too small (minimum is 2 bytes)")
		return
	}
	// block size up to 255 requires 1 byte padding
	if blockSize < 1<<8 {
		// calculate padding length
		padLen := PadLength(len(message), blockSize)

		// define PKCS7 padding block
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)

		// apply padding
		padded = append(message, padding...)
		return padded, nil
	}
	// block size bigger or equal 256 is not currently supported
	err = errors.New("unsupported block size")
	return
}

// PKCS7Unpad removes PKCS7 padding from the data block, http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
// this function may return an error id padding is incorrect,
// however it will return unpaded data in any case
func PKCS7Unpad(padded []byte) (message []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				err = fmt.Errorf("pkcs7 unpad failed: %w", e)
			} else {
				err = fmt.Errorf("pkcs7 unpad failed: %v", p)
			}
		}
	}()

	// read padding length
	plen := len(padded)
	last_byte := padded[plen-1]
	padlen := int(last_byte)

	// check validity of PKCS7 padding
	for i := padlen; i > 1; i-- {
		if padded[plen-i] != last_byte {
			err = fmt.Errorf("invalid padding (byte -%d: %d). Is the message supplied PKCS7 padded?", i, padded[plen-i])
			break
		}
	}

	// remove padding
	return padded[:plen-padlen], err
}

// PadLength calculates padding length
func PadLength(slice_length, blocksize int) (padlen int) {
	padlen = blocksize - slice_length%blocksize
	if padlen == 0 {
		padlen = blocksize
	}
	return padlen
}

// func PKCS7Pad(plaintext []byte, blockSize int) []byte {
// 	paddingSize := blockSize - len(plaintext)%blockSize
// 	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
// 	return append(plaintext, paddingText...)
// }

// func PKCS7Unpad(s []byte) []byte {
// 	length := len(s)
// 	if length == 0 {
// 		return s
// 	}
// 	unPadding := int(s[length-1])
// 	return s[:(length - unPadding)]
// }
