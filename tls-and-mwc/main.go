package main

import (
	"context"
	"flag"
	"log"
)

var certPath = "../certs/"

func main() {
	// Flag to enable Creation of Webhook Mutator Config
	mutationConfig := flag.Bool("M", false, "Create Webhook Mutator Configuration.")
	flag.Parse()

	// caPEM, serverCertPEM, serverPrivKeyPEM, err := GenerateTLSCerts(certPath)
	caPEM, _, _, err := GenerateTLSCerts(certPath)
	if err != nil {
		log.Panic(err)
	}
	if *mutationConfig {
		ctx := context.Background()
		// Use CABundle to Register new MutationWebhook
		CreateMutationConfig(ctx, caPEM)
	}
}

// Reference https://www.velotio.com/engineering-blog/managing-tls-certificate-for-kubernetes-admission-webhook
