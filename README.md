# gocog
gocog is a simple Go library for validating Amazon Cognito JWTs. It supports both access and identity token validation and uses only the standard library.

## Installation

```shell
$ go get github.com/timwea/gocog
```

## Basic Usage

```golang
package main

import (
    "log"
    "github.com/timwea/gocog"
)

func main() {

    validator := gocog.NewCognitoJwtValidator("<userPoolId>", "<clientId>")

    err := validator.Validate("<token>")	
    if err != nil {
	log.Fatal(err)
    }

}
```



