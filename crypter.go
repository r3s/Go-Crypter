package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

const salt = "qqH+KDE3J6VHw0oGO4ml50Wc3OEvF8 xIr_LPwEQlJ|c%zqknw1zTOmHHIbF"

// maxBuffer , maximum amount of data read from a file once is 4MB
const maxBuffer = 4 << 20

// encryptFile encrypts a file, accepts 3 arguments
// src:  source file, dest: destination file, key: password for encryption
func encryptFile(src, dest, key string) error {

	//Generate a key of required length using the pbkd2 lib and the input
	cipherKey := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	// Generate IV using rand lib
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)

	// Define a new AES cipher with our generated key
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return err
	}

	// Open input file to be encrypted
	fin, err := os.Open(src)
	defer fin.Close()
	if err != nil {
		return err
	}
	//Get input file size
	size, err := FileSize(src)
	if err != nil {
		return err
	}
	// Open ouput file
	fout, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	defer fout.Close()
	if err != nil {
		return err
	}
	// Write the IV at the start of the file
	_, err = fout.Write(iv)
	if err != nil {
		return err
	}

	// If file size is greater than 32KB, make a byte buffer of 32KB
	// Otherwise, create a buffer of file size
	var buf []byte
	if size > maxBuffer {
		buf = make([]byte, 32768)
	} else {
		buf = make([]byte, size)
	}

	// Loop until we reach end of file
	for {
		// Read data
		res, err := fin.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		// If end of file is reached or there is no data to be read, break
		if res == 0 || err == io.EOF {
			break
		}
		// Create a byte array for encrypted data
		cipherText := make([]byte, len(buf))
		// Encrypt the input data
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipherText, buf)
		//Write the encrypted data to output file
		_, err = fout.Write(cipherText)
		if err != nil {
			return err
		}

	}

	return nil
}

// decryptFile decrypts a file, accepts 3 arguments
// src:  source file, dest: destination file, key: password for encryption
func decryptFile(src, dest, key string) error {

	//Generate a key of required length using the pbkd2 lib and the input
	cipherKey := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	// Define a new AES cipher with our generated key
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return err
	}

	// Open input file to be encrypted
	fin, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fin.Close()
	//Get input file size
	size, err := FileSize(src)
	if err != nil {
		return err
	}
	// Open ouput file
	fout, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer fout.Close()

	iv := make([]byte, aes.BlockSize)
	_, err = fin.Read(iv)
	if err != nil {
		return err
	}

	// If file size is greater than 32KB, make a byte buffer of 32KB
	// Otherwise, create a buffer of file size
	var buf []byte
	if size > maxBuffer {
		buf = make([]byte, 32768)
	} else {
		buf = make([]byte, size)
	}
	// Loop until we reach end of file
	for {
		// Read data
		res, err := fin.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		// If end of file is reached or there is no data to be read, break
		if res == 0 || err == io.EOF {
			break
		}
		// Create a byte array for decrypted data
		cipherText := make([]byte, len(buf))
		// Decrypt the input data
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(cipherText, buf[:res])
		//Write the decrypted data to output file
		_, err = fout.Write(cipherText)
		if err != nil {
			return err
		}

	}

	return nil
}

// Main function
func main() {
	// Init logger
	log.SetFlags(0)
	log.SetPrefix("Crypter: ")

	// If there is no file name in the argument or if the argument is not a file
	// Exit with message
	if len(os.Args) < 2 {
		fmt.Println("Usage: crypter <filename>")
		os.Exit(1)
	} else if !IsFile(os.Args[1]) {
		fmt.Println("Usage: crypter <filename>")
		os.Exit(1)
	}
	// Get the file name
	src := os.Args[1]

	var choice byte
	fmt.Print("Encrypt(e) or Decrypt(d)? :")
	fmt.Scanf("%c\n", &choice)

	var key string
	fmt.Print("Enter password : ")
	fmt.Scanf("%s\n", &key)

	if choice == 'e' {
		dest := src + ".enc"
		err := encryptFile(src, dest, key)
		if err != nil {
			log.Fatal(err)
		}
	} else if choice == 'd' {
		dest := src + ".dec"
		err := decryptFile(src, dest, key)
		if err != nil {
			log.Fatal(err)
		}
	}

}
