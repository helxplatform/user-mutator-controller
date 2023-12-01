package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattbaird/jsonpatch"

	giteaAPI "code.gitea.io/gitea/modules/structs"
	"github.com/gorilla/mux"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type GiteaAccess struct {
	URL      string
	Username string
	Password string
}

type VolumeMount struct {
	MountPath string `json:"mountPath"`
	Name      string `json:"name"`
}

// VolumeSource represents the source of a volume.
type VolumeSource struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type VolumeConfig struct {
	VolumeMounts  []VolumeMount  `json:"volumeMounts"`
	VolumeSources []VolumeSource `json:"volumeSources"`
}

type UserFeatures struct {
	Config VolumeConfig `json:"config"`
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

// ReadUserFeaturesFromFile reads a UserFeatures instance from a JSON file.
func ReadUserFeaturesFromFile(basename, directory string) (*UserFeatures, error) {
	filePath := filepath.Join(directory, basename+".json")

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	// Read the file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}

	// Deserialize the JSON content into a UserFeatures instance
	var features UserFeatures
	err = json.Unmarshal(fileData, &features)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %s", err)
	}

	return &features, nil
}

// ExtractUsernameFromAdmissionReview extracts the 'username' label from a Deployment in an AdmissionReview.
func ExtractUsernameFromAdmissionReview(review admissionv1.AdmissionReview) (string, error) {
	// Decode the raw object to a Deployment
	var deployment appsv1.Deployment
	if err := json.Unmarshal(review.Request.Object.Raw, &deployment); err != nil {
		return "", fmt.Errorf("error unmarshalling deployment: %v", err)
	}

	// Extract the 'username' label
	username, ok := deployment.ObjectMeta.Labels["username"]
	if !ok {
		return "", fmt.Errorf("label 'username' not found in deployment")
	}

	return username, nil
}

// GetK8sVolumeMounts converts VolumeConfig's VolumeMounts to a slice of corev1.VolumeMount
func GetK8sVolumeMounts(config VolumeConfig) []corev1.VolumeMount {
	var k8sVolumeMounts []corev1.VolumeMount

	for _, vm := range config.VolumeMounts {
		k8sVolumeMount := corev1.VolumeMount{
			Name:      vm.Name,
			MountPath: vm.MountPath,
		}
		k8sVolumeMounts = append(k8sVolumeMounts, k8sVolumeMount)
	}

	return k8sVolumeMounts
}

// parseVolumeSource parses the VolumeSource string and returns an appropriate corev1.VolumeSource
func parseVolumeSource(source string) corev1.VolumeSource {
	// Split the source string by "://"
	parts := strings.SplitN(source, "://", 2)

	// Default to assuming the source is a PVC claim name
	if len(parts) == 1 {
		return corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: parts[0],
			},
		}
	}

	// Handle different schemes
	scheme := parts[0]
	switch scheme {
	case "pvc":
		return corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: parts[1],
			},
		}
		// Add cases for other schemes here
	}

	// Fallback to a default type if no recognized scheme is provided
	return corev1.VolumeSource{}
}

// GetK8sVolumes converts VolumeConfig's VolumeSources to a slice of corev1.Volume
func GetK8sVolumes(config VolumeConfig) []corev1.Volume {
	var k8sVolumes []corev1.Volume

	for _, vs := range config.VolumeSources {
		volumeSource := parseVolumeSource(vs.Source)
		k8sVolume := corev1.Volume{
			Name:         vs.Name,
			VolumeSource: volumeSource,
		}
		k8sVolumes = append(k8sVolumes, k8sVolume)
	}

	return k8sVolumes
}

func printVolumes(volumes []corev1.Volume) {
	log.Println("Volumes:")
	for _, volume := range volumes {
		log.Printf("Name: %s, VolumeSource: %#v\n", volume.Name, volume.VolumeSource)
	}
}

func printVolumeMounts(volumeMounts []corev1.VolumeMount) {
	log.Println("VolumeMounts:")
	for _, mount := range volumeMounts {
		log.Printf("Name: %s, MountPath: %s, ReadOnly: %v\n", mount.Name, mount.MountPath, mount.ReadOnly)
	}
}

func prettyPrintJSON(inputJSON string) (string, error) {
	var buffer bytes.Buffer
	err := json.Indent(&buffer, []byte(inputJSON), "", "    ")
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// printPatchOperations prints each JsonPatchOperation in the slice
func printPatchOperations(operations []jsonpatch.JsonPatchOperation) {
	for i, op := range operations {
		opJSON, err := json.MarshalIndent(op, "", "    ")
		if err != nil {
			log.Printf("Failed to marshal operation %d: %s", i, err)
			continue
		}
		fmt.Printf("Operation %d:\n%s\n", i, string(opJSON))
	}
}

// calculatePatch creates a patch between the original deployment and its modified version with added volumes and mounts
func calculatePatch(admissionReview *admissionv1.AdmissionReview, volumes []corev1.Volume, volumeMounts []corev1.VolumeMount) ([]byte, error) {

	/// Deserialize the original Deployment from the AdmissionReview
	var originalDeployment appsv1.Deployment
	if err := json.Unmarshal(admissionReview.Request.Object.Raw, &originalDeployment); err != nil {
		return nil, err
	}

	// Apply modifications to the Deployment
	modifiedDeployment := originalDeployment.DeepCopy()

	// Add volumes and volume mounts
	modifiedDeployment.Spec.Template.Spec.Volumes = append(modifiedDeployment.Spec.Template.Spec.Volumes, volumes...)
	if len(modifiedDeployment.Spec.Template.Spec.Containers) > 0 {
		modifiedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(
			modifiedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts, volumeMounts...)
	}

	/*
		// Serialize deployments to JSON
		log.Printf("marshalling original JSON")
		originalJSON, err := json.Marshal(originalDeployment)
		if err != nil {
			return nil, err
		}
	*/

	log.Printf("marshalling original new JSON")
	modifiedJSON, err := json.Marshal(modifiedDeployment)
	if err != nil {
		return nil, err
	}

	/*
		if prettyJSON, err := prettyPrintJSON(string(modifiedJSON)); err == nil {
			log.Printf("new JSON \n%s\n", prettyJSON)
		} else {
			log.Printf("Unable to make JSON pretty %v", err)
		}
	*/

	// Create patch
	patchOps, err := jsonpatch.CreatePatch(admissionReview.Request.Object.Raw, modifiedJSON)
	if err != nil {
		return nil, err
	}

	log.Printf("Patches:")
	printPatchOperations(patchOps)

	// Marshal patch to JSON
	patchBytes, err := json.Marshal(patchOps)
	if err != nil {
		return nil, err
	}

	return patchBytes, nil
}

func processAdmissionReview(admissionReview admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	// Implement your logic here
	// For example, always allow the request:
	log.Printf("processing admission for %s:%s", admissionReview.Request.Namespace, admissionReview.Request.Name)

	// Deserialize the AdmissionReview to a Deployment object
	var deployment appsv1.Deployment
	if err := json.Unmarshal(admissionReview.Request.Object.Raw, &deployment); err != nil {
		log.Printf("Error unmarshalling deployment: %v", err)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	if username, err := ExtractUsernameFromAdmissionReview(admissionReview); err == nil {
		log.Printf("deployment is for user = %s", username)
		if features, err := ReadUserFeaturesFromFile(username, "/etc/user-mutator-maps/user-features"); err == nil {
			volumes := GetK8sVolumes(features.Config)
			volumeMounts := GetK8sVolumeMounts(features.Config)

			printVolumes(volumes)
			log.Println()
			printVolumeMounts(volumeMounts)

			// Calculate the patch
			if patchBytes, err := calculatePatch(&admissionReview, volumes, volumeMounts); err != nil {
				log.Printf("Patch creation failed %v", err)
			} else {
				return &admissionv1.AdmissionResponse{
					UID:     admissionReview.Request.UID,
					Allowed: true,
					Patch:   patchBytes,
					PatchType: func() *admissionv1.PatchType {
						pt := admissionv1.PatchTypeJSONPatch
						return &pt
					}(),
				}
			}
		}
	} else {
		log.Printf("Username not detected %v", err)
	}
	return &admissionv1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
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
	var admissionReviewReq admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReviewReq); err != nil {
		http.Error(w, fmt.Sprintf("could not unmarshal request: %v", err), http.StatusBadRequest)
		return
	}

	// Process the request and prepare the response
	// This is where your custom logic will go
	admissionResponse := processAdmissionReview(admissionReviewReq)

	// Encode the response
	admissionReviewResp := admissionv1.AdmissionReview{
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
	r.HandleFunc("/readyz", readinessHandler)
	r.HandleFunc("/healthz", livenessHandler)
	http.Handle("/", r)
	log.Println("Server started on :8443")
	if err := http.ListenAndServeTLS(":8443", "/etc/user-mutator-secrets/user-mutator-cert-tls/tls.crt", "/etc/user-mutator-secrets/user-mutator-cert-tls/tls.key", nil); err != nil {
		log.Printf("Failed to start server: %v", err)
	}
}
