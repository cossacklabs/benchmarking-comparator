package main

import ("net"
	"strings"
	"net/textproto"
	"net/http"
//	"fmt"
	"bufio"
	"github.com/cossacklabs/themis/gothemis/session"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/compare"
	"encoding/base64"
//	"encoding/binary"
)

type callbacks struct{
	
}

func (clb *callbacks) GetPublicKeyForId(ss *session.SecureSession, id []byte)(*keys.PublicKey){
    return &keys.PublicKey {Value: id}
}

func (clb *callbacks) StateChanged(ss *session.SecureSession, state int){
	
}

func main(){
    conn, err := net.Dial("tcp", "127.0.0.1:8081")
    if err != nil { return }

    kp, err := keys.New(keys.KEYTYPE_EC)
    if err != nil { return }

    clb := &callbacks{}
    sess, err := session.New(kp.Public.Value, kp.Private, clb)
    if nil != err {return}

    data, err := sess.ConnectRequest()
    if nil != err {return}
    sendpeer := false
    for {
	_ , err = conn.Write(data)
	if nil != err {return}

	_ , err = conn.Read(data)
	if nil != err {return}

	data , sendpeer , err = sess.Unwrap(data)
	if nil != err {return}
	if !sendpeer {
	    break
	}
    }
    
//    fmt.Println("session established")

    comp, err := compare.New();
    if nil != err {return}
    err = comp.Append([]byte("password"))
    if nil != err {return}
    data, err = comp.Begin();
    if nil != err {return}
    data, err = sess.Wrap([]byte("GET /themis-sc-auth/ HTTP/1.1\r\nUser-Agent: curl/7.38.0\r\nAuthorization: Themis andrey "+base64.StdEncoding.EncodeToString(data)+"\r\nHost: 127.0.0.1:8081\r\nAccept: */*\r\n\r\n"))
    if nil != err {return}
    _ , err = conn.Write(data)
    if nil != err {return}
    data = make([]byte, 10000);
    _ , err = conn.Read(data)
    if nil != err {return}
    data , _ , err = sess.Unwrap(data)
    if nil != err {return}
    reader := bufio.NewReader(strings.NewReader(string(data[:])))
    tp := textproto.NewReader(reader)
    _, err = tp.ReadLine()
    mimeHeader, err := tp.ReadMIMEHeader()
    if nil != err {return}
    httpHeader := http.Header(mimeHeader)
    data, err = base64.StdEncoding.DecodeString(httpHeader["Authorization"][0])
    if nil != err {return}
    data, err = comp.Proceed(data)
    if nil != err {return}
    data, err = sess.Wrap([]byte("GET /themis-sc-auth/ HTTP/1.1\r\nUser-Agent: curl/7.38.0\r\nAuthorization: Themis "+base64.StdEncoding.EncodeToString(data)+"\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n"))
    if nil != err {return}
    _ , err = conn.Write(data)
    if nil != err {return}
    data = make([]byte, 10000);
    _ , err = conn.Read(data)
    if nil != err {return}
    data , _ , err = sess.Unwrap(data)
    if nil != err {return}
    reader = bufio.NewReader(strings.NewReader(string(data[:])))
    tp = textproto.NewReader(reader)
    _, err = tp.ReadLine()
    mimeHeader, err = tp.ReadMIMEHeader()
    if nil != err {return}
    httpHeader = http.Header(mimeHeader)
    data, err = base64.StdEncoding.DecodeString(httpHeader["Authorization"][0])
    if nil != err {return}
    data, err = comp.Proceed(data)
    if nil != err {return}
//    fmt.Println(string(httpHeader["Authorization"][0]))


//    fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
//    status, err := bufio.NewReader(conn).ReadString('\n')
}