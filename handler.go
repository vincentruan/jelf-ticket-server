package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
)

const (
	ProlongationPeriod   = 607875500
	ObtainTicketResponse = `
<ObtainTicketResponse>
	<message></message>
	<prolongationPeriod>%d</prolongationPeriod>
	<responseCode>OK</responseCode>
	<salt>%s</salt>
	<ticketId>1</ticketId>
	<ticketProperties>licensee=%s</ticketProperties>
</ObtainTicketResponse>
`
	ReleaseTicket = `
<ReleaseTicketResponse>
	<message></message>
	<responseCode>OK</responseCode>
	<salt>%s</salt>
</ReleaseTicketResponse>
`
)

func RunHttpServer() {
	http.HandleFunc("/rpc/obtainTicket.action", obtainTicketHandler)
	http.HandleFunc("/rpc/releaseTicket.action", releaseTicketHandler)
	http.HandleFunc("/", aliveHandler)

	addr := fmt.Sprintf("%s:%s", GConfig.Host, GConfig.Port)

	log.Printf("http start listen on: %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err.Error())
	}
}

func aliveHandler(w http.ResponseWriter, r *http.Request) {
	s := fmt.Sprintf("Server alive and running: http://%s:%s", GConfig.Host, GConfig.Port)
	log.Println(s)
	w.Write([]byte(s))
}

func obtainTicketHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf(
		"obtainTicketHandler recv:\n ip: %s\n method: %s\n url: %s\n headers: %s\n",
		r.RemoteAddr, r.Method, r.RequestURI, r.Header,
	)
	salt := r.URL.Query().Get("salt")
	rspStr := fmt.Sprintf(ObtainTicketResponse, ProlongationPeriod, salt, GConfig.User)
	doRsp(w, rspStr)
}

func releaseTicketHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf(
		"releaseTicketHandler recv:\n ip: %s\n method: %s\n url: %s\n headers: %s\n",
		r.RemoteAddr, r.Method, r.RequestURI, r.Header,
	)
	salt := r.URL.Query().Get("salt")
	rspStr := fmt.Sprintf(ReleaseTicket, salt)
	doRsp(w, rspStr)
}

func doRsp(w http.ResponseWriter, str string) {
	sign, err := rsaSign([]byte(str))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		signStr := fmt.Sprintf("<!-- %x -->\n%s", string(sign), str)
		w.Write([]byte(signStr))
	}
}

func rsaSign(bs []byte) ([]byte, error) {
	var nbs []byte
	md5 := crypto.MD5.New()
	if _, err := md5.Write(bs); err != nil {
		log.Fatal(err.Error())
		return nbs, err
	}
	var hash = md5.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, GConfig.RasKey, crypto.MD5, hash)
}
