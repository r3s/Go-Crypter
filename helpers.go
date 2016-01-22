package main

import (
	
	"fmt"
	"os"
)

// Abs : Simple abs function for integers. 
// I was only able to find float64 version in the math lib
func Abs(x int) int {
  if x < 0 {
    return -x
  }
  return x
}

// IsFile : Function to check if a given file path is actually a file
func IsFile(file string) bool {
    res, err := os.Stat(file)
    
    if err != nil || res.IsDir(){
        return false
    }
    return true
}

// FileSize : Return the file size of a file
func FileSize(file string)  int64{
    res, err := os.Stat(file)
    HandleError(err, "Stat file")
    return res.Size()
}

// HandleError : Generic function to raise panic if there is any error
func HandleError(err error, desc string){
    if err != nil{
        fmt.Println(desc)
        panic(err)
    }
}