package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

const salt = "qqH+KDE3J6VHw0oGO4ml50Wc3OEvF8 xIr_LPwEQlJ|c%zqknw1zTOmHHIbF"

// Function to encrypt a file
func encryptFile(file, key string) {

	fmt.Println("Encrypting...")

	//Generate a key of required length using the pbkd2 lib and the input
	cipherKey := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	// Generate IV using rand lib
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)

	// Define a new AES cipher with our generated key
	block, err := aes.NewCipher(cipherKey)
	HandleError(err, "cipher")

	// Open input file to be encrypted
	fin, err := os.Open(file)
	HandleError(err, "open input file")
	defer fin.Close()
	//Get input file size
	size := FileSize(file)
	// Open ouput file
	fout, err := os.OpenFile(file+".aes", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	HandleError(err, "open output file")
	defer fout.Close()
	// Write the IV at the start of the file
	_, err = fout.Write(iv)
	HandleError(err, "write to output")

	// If file size is greater than 32KB, make a byte buffer of 32KB
	// Otherwise, create a buffer of file size
	var buf []byte
	if size > (4 << 20) {
		buf = make([]byte, 32768)
	} else {
		buf = make([]byte, size)
	}

	// Loop until we reach end of file
	for {
		// Read data
		res, err := fin.Read(buf)
		// If there is any error, exit
		if err != nil && err != io.EOF {
			panic(err)
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
		HandleError(err, "writing cipher block")

	}

	fmt.Println("Done.")
}

// Function to decrypt a file
func decryptFile(file, key string) {

	fmt.Println("Decrypting...")

	//Generate a key of required length using the pbkd2 lib and the input
	cipherKey := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	// Define a new AES cipher with our generated key
	block, err := aes.NewCipher(cipherKey)
	HandleError(err, "cipher")

	// Open input file to be encrypted
	fin, err := os.Open(file)
	HandleError(err, "open input file")
	defer fin.Close()
	//Get input file size
	size := FileSize(file)
	// Open ouput file
	fout, err := os.OpenFile(file+".dec", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	HandleError(err, "open output file")
	defer fout.Close()

	iv := make([]byte, aes.BlockSize)
	_, err = fin.Read(iv)
	HandleError(err, "reading iv")

	// If file size is greater than 32KB, make a byte buffer of 32KB
	// Otherwise, create a buffer of file size
	var buf []byte
	if size > (4 << 20) {
		buf = make([]byte, 32768)
	} else {
		buf = make([]byte, size)
	}
	// Loop until we reach end of file
	for {
		// Read data
		res, err := fin.Read(buf)
		// If there is any error, exit
		if err != nil && err != io.EOF {
			panic(err)
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
		HandleError(err, "writing cipher block")

	}

	fmt.Println("Done.")
}

// Main function
func main() {
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
	file := os.Args[1]
	// Reader for options
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Encrypt(e) or Decrypt(d)? :")
	choice, _ := reader.ReadString('\n')

	fmt.Print("Enter password : ")
	key, _ := reader.ReadString('\n')

	if choice[0] == 'e' {
		encryptFile(file, key)
	} else if choice[0] == 'd' {
		decryptFile(file, key)
	}

}
