package main

import (
	gotracing "github.com/MashaSamoylova/tracing-session"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	session, err := gotracing.NewSession("TEST-GO-GO")
	if err != nil {
		panic(err)
	}
	if err := session.SubscribeToProvider("{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"); err != nil {
		panic(err)
	}
	spew.Dump(session.StartSession())
}

