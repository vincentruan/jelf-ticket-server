package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
)

type Config struct {
	Host   string
	Port   string
	User   string
	RasKey *rsa.PrivateKey
}

var GConfig = new(Config)

const (
	defaultHost = "127.0.0.1"
	defaultPort = "20518"
	defaultUser = "x-x-x"
)

func ParseArgs() {
	flag.StringVar(&GConfig.Host, "h", defaultHost, "host")
	flag.StringVar(&GConfig.Port, "p", defaultPort, "port")
	flag.StringVar(&GConfig.User, "u", defaultUser, "user")
	flag.Parse()
}

const KeyPath = "./key"

func InitRasKey() {
	rawKey, err := ioutil.ReadFile(KeyPath)
	if err != nil {
		log.Fatal("key not exist\n")
	}
	log.Println("load key success")
	block, _ := pem.Decode(rawKey)
	if block == nil {
		log.Fatal("pem key err")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err.Error())
	}
	GConfig.RasKey = rsaKey
	log.Println("load rasKey success")
}