// Package md5crypt implements FreeBSD's MD5-based crypt(3) function.
package md5crypt

/*
   Copyright (c) 2013 Damian Gryski <damian@gryski.com>

   Based on the implementation at http://code.activestate.com/recipes/325204-passwd-file-compatible-1-md5-crypt/

   Licensed same as the original:

   Original license:
   * "THE BEER-WARE LICENSE" (Revision 42):
   * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
   * can do whatever you want with this stuff. If we meet some day, and you think
   * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

   This port adds no further stipulations.  I forfeit any copyright interest.
*/

import (
	"bytes"
	"crypto/md5"
	"errors"
)

const p64alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var permute [5][3]int

func init() {
	permute = [5][3]int{
		[3]int{0, 6, 12},
		[3]int{1, 7, 13},
		[3]int{2, 8, 14},
		[3]int{3, 9, 15},
		[3]int{4, 10, 5},
	}
}

func pass64(b []byte) []byte {
	// not quite base64 encoding
	// 1) bits are encoded in the wrong order
	// 2) the alphabet is different

	pass := make([]byte, 0, (len(b)+1*4)/3)

	for _, v := range permute {

		v := int(b[v[0]])<<16 | int(b[v[1]])<<8 | int(b[v[2]])
		for j := 0; j < 4; j++ {
			pass = append(pass, p64alphabet[v&0x3f])
			v >>= 6
		}
	}
	v := b[11]
	pass = append(pass, p64alphabet[v&0x3f])
	v >>= 6
	pass = append(pass, p64alphabet[v&0x3f])

	return pass
}

// Crypt hashes the plaintext password using the salt from the hashed password.
func Crypt(plain []byte, hashed []byte) ([]byte, error) {

	if hashed[0] != '$' {
		return nil, errors.New("bad salt")
	}

	var magic []byte
	magicEnd := bytes.IndexByte(hashed[1:], '$')
	if magicEnd == -1 {
		return nil, errors.New("bad magic")
	}
	magicEnd += 2 // because we skipped the first '$' and we want the second '$'
	magic = hashed[0:magicEnd]

	var salt []byte
	saltEnd := bytes.IndexByte(hashed[magicEnd:], '$')
	if saltEnd == -1 {

            // no trailing '$'

            if len(hashed[magicEnd:]) > 8 {
		// remaining string is too long to be entirely salt
		return nil, errors.New("bad salt")
            }

            saltEnd = len(hashed[magicEnd:])
	}

	salt = hashed[magicEnd : magicEnd+saltEnd]

	m := md5.New()
	m.Write(plain)
	m.Write(salt)
	m.Write(plain)
	final := m.Sum(nil)

	m.Reset()
	m.Write(plain)
	m.Write(magic)
	m.Write(salt)

	for idx := len(plain); idx > 0; idx -= 16 {
		if idx > 16 {
			m.Write(final[:16])
		} else {
			m.Write(final[:idx])
		}
	}

	var ctx []byte
	for i := len(plain); i > 0; i >>= 1 {
		if i&1 == 1 {
			ctx = append(ctx, 0)
		} else {
			ctx = append(ctx, plain[0])
		}
	}

	m.Write(ctx)
	final = m.Sum(nil)

	for i := 0; i < 1000; i++ {
		m.Reset()

		if i&1 == 1 {
			m.Write(plain)
		} else {
			m.Write(final[:16])
		}

		if i%3 != 0 {
			m.Write(salt)
		}

		if i%7 != 0 {
			m.Write(plain)
		}

		if i&1 == 1 {
			m.Write(final[:16])
		} else {
			m.Write(plain)
		}

		final = m.Sum(nil)
	}

	var passwd []byte
	passwd = append(passwd, magic...)
	passwd = append(passwd, salt...)
	passwd = append(passwd, '$')
	passwd = append(passwd, pass64(final)...)

	return passwd, nil
}
