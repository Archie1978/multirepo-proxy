package main

import (
	"log"

	"multirepo-proxy/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
