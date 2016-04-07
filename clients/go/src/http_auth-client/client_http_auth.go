package main

import (
    "fmt"
    "net/http"
)
func main() {
    tr := &http.Transport{}
    client := &http.Client{Transport: tr}
    req, err := http.NewRequest("GET", "http://127.0.0.1:8080/http-auth/", nil)
    req.SetBasicAuth("andrey", "password")
    _, err = client.Do(req)
    if err != nil {
        fmt.Println(err)
    }
//    fmt.Println(resp)
}