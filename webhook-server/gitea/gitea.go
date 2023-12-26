package gitea

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type GiteaAccess struct {
	URL      string
	Username string
	Password string
}

var access *GiteaAccess
var authToken string

func init() {
	//access, _ = getAccess()
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

// func handleUpdate(oldObj, newObj interface{}) {
// 	// This function will be triggered on updates, but currently does nothing.
// 	// You can add logic here if needed in the future.
// }

// func getCurrentNamespace() (string, error) {
// 	// Read the namespace associated with the service account token
// 	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(namespace), nil
// }
