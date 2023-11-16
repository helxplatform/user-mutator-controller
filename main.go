package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	giteaAPI "code.gitea.io/gitea/modules/structs"
	"github.com/gorilla/mux"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
)

type GiteaAccess struct {
	URL      string
	Username string
	Password string
}

var access *GiteaAccess
var authToken string

func init() {
	access, _ = getAccess()
	//authToken = createUserToken(access.URL, access.Username, access.Password, access.Username)
}

func startHTTPServer() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.ListenAndServe(":8080", nil)
}

func getAccess() (*GiteaAccess, error) {
	var access *GiteaAccess

	username, err := os.ReadFile("/etc/user-mutator-secrets/gitea-username")
	if err != nil {
		log.Fatalf("Error reading username: %v", err)
		return access, err
	}

	password, err := os.ReadFile("/etc/user-mutator-secrets/gitea-password")
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
		return access, err
	}

	url, err := os.ReadFile("/etc/user-mutator-configs/gitea-api-url")
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
		return access, err
	}

	access = &GiteaAccess{
		URL:      string(url),
		Username: string(username),
		Password: string(password),
	}

	return access, nil
}

func createUserToken(giteaBaseURL, adminUsername, adminPassword, username string) string {
	option := giteaAPI.CreateAccessTokenOption{
		Name: "auth_token",
	}

	jsonData, _ := json.Marshal(option)

	req, _ := http.NewRequest("POST", giteaBaseURL+"/users/"+username+"/tokens", bytes.NewBuffer(jsonData))
	req.SetBasicAuth(adminUsername, adminPassword)
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return ""
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	return result["sha1"]
}

func createUser(giteaBaseURL, adminUsername, adminPassword, username, password string) {
	/*
		user := giteaAPI.CreateUserOption{
			Username: username,
			Email:    "jeffw@renci.org",
			Password: password,
		}
	*/
	type CreateUser struct {
		Username string `json:"username" binding:"Required;Username;MaxSize(40)"`
		Email    string `json:"email" binding:"Required;Email;MaxSize(254)"`
		Password string `json:"password" binding:"Required;MaxSize(255)"`
	}
	user := CreateUser{
		Username: username,
		Email:    "xxx@gmail.com",
		Password: password,
	}

	jsonData, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", giteaBaseURL+"/admin/users", bytes.NewBuffer(jsonData))
	//req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("Failed to create user:", string(body))
	}
}

func userExists(giteaBaseURL, adminUsername, adminPassword, username string) (bool, error) {
	req, _ := http.NewRequest("GET", giteaBaseURL+"/users/"+username, nil)
	//req.Header.Add("Authorization", "token "+token)
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

func handleAdd(obj interface{}) {
	deployment := obj.(*appsv1.Deployment)
	if value, exists := deployment.Labels["executor"]; exists && value == "tycho" {
		if username, exists := deployment.Labels["username"]; exists {
			fmt.Printf("Deployment with executor=tycho found. Username: %s\n", username)
			userExists, err := userExists(access.URL, access.Username, access.Password, username)
			if err != nil {
				log.Printf("unable to check for user "+username, err)
				return
			}
			if userExists {
				log.Printf("Gitea user %s found", username)
			} else {
				log.Printf("Gitea user %s NOT found", username)
				createUser(access.URL, access.Username, access.Password, username, "ADx3*x5xww66")
			}
		} else {
			fmt.Println("Deployment with executor=tycho found, but no username label present.")
		}
	}
}

func handleUpdate(oldObj, newObj interface{}) {
	// This function will be triggered on updates, but currently does nothing.
	// You can add logic here if needed in the future.
}

func getCurrentNamespace() (string, error) {
	// Read the namespace associated with the service account token
	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", err
	}
	return string(namespace), nil
}

/*
func setupInformer(stopCh chan struct{}, namespace string) cache.SharedInformer {
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("Error getting cluster config: %v\n", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("Error setting up clientset: %v\n", err)
		os.Exit(1)
	}

	deploymentListWatcher := cache.NewListWatchFromClient(
		clientset.AppsV1().RESTClient(),
		"deployments",
		namespace,
		fields.Everything(),
	)

	informer := cache.NewSharedInformer(
		deploymentListWatcher,
		&appsv1.Deployment{},
		0,
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handleAdd,
		UpdateFunc: handleUpdate,
	})

	return informer
}
*/

func processAdmissionReview(admissionReview v1.AdmissionReview) *v1.AdmissionResponse {
	// Implement your logic here
	// For example, always allow the request:
	return &v1.AdmissionResponse{
		Allowed: true,
	}
}

func handleAdmissionReview(w http.ResponseWriter, r *http.Request) {
	// Read the body of the request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not read request body: %v", err), http.StatusBadRequest)
		return
	}

	// Decode the AdmissionReview request
	var admissionReviewReq v1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReviewReq); err != nil {
		http.Error(w, fmt.Sprintf("could not unmarshal request: %v", err), http.StatusBadRequest)
		return
	}

	// Process the request and prepare the response
	// This is where your custom logic will go
	admissionResponse := processAdmissionReview(admissionReviewReq)

	// Encode the response
	admissionReviewResp := v1.AdmissionReview{
		TypeMeta: admissionReviewReq.TypeMeta, // Use the same TypeMeta as the request
		Response: admissionResponse,
	}
	resp, err := json.Marshal(admissionReviewResp)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	// Write the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

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
	r := mux.NewRouter()
	r.HandleFunc("/mutate", handleAdmissionReview)
	r.HandleFunc("/readiness", readinessHandler)
	r.HandleFunc("/liveness", livenessHandler)
	http.Handle("/", r)
	log.Println("Server started on :8443")
	if err := http.ListenAndServeTLS(":8443", "/etc/user-mutator-secrets/tls.crt", "/etc/user-mutator-secrets/tls.key", nil); err != nil {
		log.Printf("Failed to start server: %v", err)
	}
}
