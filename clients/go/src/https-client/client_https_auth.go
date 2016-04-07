package main

import (
    "fmt"
    "net/http"
    "crypto/tls"
)
func main() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    req, err := http.NewRequest("GET", "https://127.0.0.1/", nil)
    req.SetBasicAuth("andrey", "password")
    _, err = client.Do(req)
    if err != nil {
        fmt.Println(err)
    }
    //fmt.Println(resp)
}