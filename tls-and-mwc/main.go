package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"webhook-server/tls-and-mwc/commands"
)

func main() {
	certPath := os.Getenv("CERT_DIR")
	if certPath == "" {
		certPath = "/tmp/certs"
	}
	fmt.Printf("CERT_PATH: " + certPath + "\n")
	// Flag to enable Creation of Webhook Mutator Config
	mutationConfig := flag.Bool("M", false, "Create Webhook Mutator Configuration.")
	flag.Parse()

	caPEM, err := commands.GenerateTLSCerts(certPath)
	if err != nil {
		log.Panic(err)
	}
	if *mutationConfig {
		ctx := context.Background()
		// Use CABundle to Register new MutationWebhook
		commands.CreateMutationConfig(ctx, caPEM)
	}
}

// Reference https://www.velotio.com/engineering-blog/managing-tls-certificate-for-kubernetes-admission-webhook
