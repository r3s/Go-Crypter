package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

const salt = "qqH+KDE3J6VHw0oGO4ml50Wc3OEvF8 xIr_LPwEQlJ|c%zqknw1zTOmHHIbF"

// maxBuffer , maximum amount of data read from a file once is 4MB
const maxBuffer = 4 << 20

// usage function to print usage on -help
func usage() {
	fmt.Println("crypter <file1> <file2> ...")
	os.Exit(0)
}

// encryptFile : encrypts a file, accepts 3 arguments
// src:  source file, dest: destination file, key: password for encryption
func encryptFile(src, dest, key string) error {

	//Generate a key of required length using the pbkd2 lib and the input
	cipherKey := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	// Generate IV using rand lib
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return err
	}

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

// decryptFile : decrypts a file, accepts 3 arguments
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

	//Get IV from the input file
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

	// Commandline flag
	flag.Usage = usage
	flag.Parse()

	// Maximum process to run based on cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Waitgroup for multiple process
	var wg sync.WaitGroup

	var files []string
	invalids := 0

	// If arguments are given, check if they are files and count invalid files
	if len(flag.Args()) > 0 {
		for _, filename := range flag.Args() {
			if !IsFile(filename) {
				fmt.Println(filename + " is not a valid file")
				invalids = invalids + 1
			} else {
				files = append(files, filename)
			}
		}
	} else {
		log.Fatal("Please give atleast one file as input")
	}

	// If there are invalid files, handle them
	if invalids == len(flag.Args()) {
		log.Fatal("No valid files given")
	} else if invalids > 0 {
		var confirm byte
		fmt.Println("Ignore invalid files and continue?(y/n) ")
		fmt.Scanf("%c\n", &confirm)

		if confirm != 'y' {
			os.Exit(0)
		}
	}

	// User input
	var choice byte
	fmt.Print("Encrypt(e) or Decrypt(d)? :")
	fmt.Scanf("%c\n", &choice)

	var key string
	fmt.Print("Enter password : ")
	fmt.Scanf("%s\n", &key)

	if choice == 'e' {
		// Loop and call encryptFile for each file as goroutine
		for _, fname := range files {
			dest := fname + ".enc"
			wg.Add(1)
			go func(fname string) {
				log.Print("Encrypting " + fname)
				err := encryptFile(fname, dest, key)
				if err != nil {
					log.Print("Error encrypting", fname)
				}
				wg.Done()
			}(fname)
		}

	} else if choice == 'd' {
		// Loop and call decryptFile for each file as goroutine
		for _, fname := range files {
			dest := fname + ".dec"
			wg.Add(1)
			go func(fname string) {
				log.Print("Decrypting " + fname)
				err := decryptFile(fname, dest, key)
				if err != nil {
					log.Print("Error decrypting", fname)
				}
				wg.Done()
			}(fname)
		}
	} else {
		log.Fatal("Please enter a valid choice")
	}

	// Wait till every goroutine has finished
	wg.Wait()
	fmt.Println("Done.")
}
