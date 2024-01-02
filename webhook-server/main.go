package main

import (
	"log"
	"net/http"
	"os"
	"webhook-server/webhook-server/userMutator"
)

// readinessHandler checks the readiness of the service to handle requests.
// In this implementation, it always indicates that the service is ready by
// returning a 200 OK status. In more complex scenarios, this function could
// check internal conditions before determining readiness.
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	// Check conditions to determine if service is ready to handle requests.
	// For simplicity, we're always returning 200 OK in this example.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

// livenessHandler checks the health of the service to ensure it's running and
// operational. In this implementation, it always indicates that the service is
// alive by returning a 200 OK status. In more advanced scenarios, this function
// could check internal health metrics before determining liveness.
func livenessHandler(w http.ResponseWriter, r *http.Request) {
	// Check conditions to determine if service is alive and healthy.
	// For simplicity, we're always returning 200 OK in this example.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Alive"))
}

func main() {
	var tlsCertDir = os.Getenv("SECRET")
	if tlsCertDir == "" {
		tlsCertDir = "/tmp/certs"
	}
	r := http.NewServeMux()
	// Regsiter routes
	r.HandleFunc("/mutate", userMutator.HandleAdmissionReview)
	r.HandleFunc("/readyz", readinessHandler)
	r.HandleFunc("/healthz", livenessHandler)

	log.Println("Server started on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", tlsCertDir+"/tls.crt", tlsCertDir+"/tls.key", r),
		"Failed to start server")
}
