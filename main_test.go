package main

import (
	"fmt"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"testing"
)

func TestReadingAWSCredentialsFile(t *testing.T) {
	creds, _ := ioutil.ReadFile("/Users/dsandor/.aws/credentials")

	credsIni, _ := ini.Load(creds)

	sections := credsIni.Sections()

	fmt.Printf("%+v\n", sections)

	testSection := credsIni.Section("edit_test")
	key := testSection.Key("test")
	key.SetValue("testvalue")

	credsIni.SaveTo("/Users/dsandor/.aws/credentials")
}
