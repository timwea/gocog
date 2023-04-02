# gocog
gocog is a simple and lightweight Go library for validating Amazon Cognito JWTs. It supports both access and identity token validation, and has no third-party dependencies.

## Installation

```shell
$ go get github.com/timwea/gocog
```

## Basic Usage

```golang
package main

import (
    "fmt"
    "github.com/timwea/gocog"
)

func main() {

    validator := gocog.CognitoJwtValidator{UserPoolId: "<userPoolId>", ClientId: "<clientId>"}

    err := validator.Validate("<token>")	
    if err != nil {
	fmt.Println(err)
    }

}
```



