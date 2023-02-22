# Barebones Rendez-vous library written in Go

[![GoDoc](https://godoc.org/github.com/PretendoNetwork/nex-go?status.svg)](https://godoc.org/github.com/PretendoNetwork/nex-go)

### Install

`go get github.com/ihatecompvir/nex-go`

### Usage note

While this package can be used stand-alone, it only provides the bare minimum for a Rendez-vous server. It does not support any Rendez-vous protocols. To make proper Rendez-vous servers, see [NEX Protocols Go](https://github.com/ihatecompvir/nex-protocols-go)

This library is designed around, and customized for, Rock Band 3. While it may work with other Quazal Rendez-vous titles that aren't Rock Band 3, do not expect it to work correctly out of the box with anything but Rock Band 3. If you are looking for a more generic NEX/PRUDP library, see the upstream version of this repository.

### Usage

```Golang
package main

import (
    "github.com/ihatecompvir/nex-go"
)

func main() {
    nexServer := nex.NewServer()

    nexServer.SetPrudpVersion(0)
    nexServer.SetSignatureVersion(1)
    nexServer.SetKerberosKeySize(16)
    nexServer.SetAccessKey("ridfebb9")

    nexServer.On("Data", func(packet *nex.PacketV0) {
        // Handle data packet
    })

    nexServer.Listen("192.168.0.28:60000")
}
```