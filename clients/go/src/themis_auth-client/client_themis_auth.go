package main

import (
    "fmt"
    "net/http"
    "github.com/cossacklabs/themis/gothemis/compare"
    "encoding/base64"
)
func main() {
    tr := &http.Transport{}
    client := &http.Client{Transport: tr}
    req, err := http.NewRequest("GET", "http://127.0.0.1:8080/themis-sc-auth/", nil)
    comp, err := compare.New();
    if nil != err {return}
    err = comp.Append([]byte("password"))
    if nil != err {return}
    data, err := comp.Begin();
    if nil != err {return}
    req.Header.Add("Authorization", "Themis andrey "+base64.StdEncoding.EncodeToString(data))
    resp , err := client.Do(req)
    if nil != err {return}
    if resp.StatusCode == 308 {
	data, err = base64.StdEncoding.DecodeString(resp.Header["Authorization"][0])
	if nil != err {return}
	data, err = comp.Proceed(data)
	if nil != err {return}
	req, err = http.NewRequest("GET", "http://127.0.0.1:8080/themis-sc-auth/", nil)
	req.Header.Add("Authorization", "Themis "+base64.StdEncoding.EncodeToString(data))
	resp , err = client.Do(req)
	if nil != err {return}
	if resp.StatusCode != 200 {
	    fmt.Println("error")
	}
    } else {
        fmt.Println("error")
    }
}