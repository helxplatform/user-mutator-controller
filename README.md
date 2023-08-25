# Mutating Controller for Kubernetes Deployments with Gitea Integration

## Overview

This controller is designed to watch Kubernetes Deployments with a specific label (`executor="tycho"`) and interacts with a Gitea instance based on the detected labels. When a matching Deployment is detected, the controller can perform actions such as checking or creating users in Gitea.

## Prerequisites

- A running Kubernetes cluster.
- A Gitea instance accessible from the cluster.
- Properly set up secret and config files for Gitea access within the Kubernetes cluster.

## Features

1. **Gitea Integration**: The controller has utility functions to communicate with a Gitea instance:
   - Check if a user exists.
   - Create a new user.
   - Generate user tokens.

2. **Deployment Watch**: The main logic of the controller revolves around watching for new or updated Deployments with the label `executor="tycho"`. Upon detection:
   - It checks for the `username` label and logs its value.

3. **HTTP Health and Readiness Endpoints**: The controller serves HTTP endpoints `/healthz` and `/readyz` for health and readiness probes, respectively.

## Setup

1. **Gitea Access Configuration**: Ensure you have secret and config files set up in the cluster containing Gitea access credentials (username, password, API URL). These are read at initialization.

2. **Deploy the Controller**: Package the controller into a container image and deploy it as a Kubernetes Deployment within your cluster.

3. **Permissions**: The controller should have appropriate permissions to watch for Deployments within the desired namespace(s).

4. **Monitoring**: Monitor the logs of the controller to observe its actions and ensure it's behaving as expected.

## Gitea User Creation with HTTP Basic Authentication in Go

### Introduction

This guide provides a step-by-step approach to creating users in Gitea using its API, with the Go programming language. The process uses HTTP Basic Authentication to ensure the authenticity and security of the API requests.

### Prerequisites

- A Gitea instance up and running.
- Administrative credentials for the Gitea instance.
- Go programming environment set up.

### Implementation Details

1. **Authentication**:
   Use the `SetBasicAuth(username, password string)` method provided by Go's `http.Request` type. This sets the request's `Authorization` header to use HTTP Basic Authentication, encoding the `username:password` combination into the correct format.

2. **Check User Existence**:
   Before creating a user, make a GET request to the `/users/:username` endpoint. If the user exists, the API will return a successful status.

3. **Create User**:
   If the user does not already exist, send a POST request to the `/admin/users` endpoint. Include the desired username, password, and other relevant details in the request body as JSON.

### Security Note

Always use HTTPS when interacting with the Gitea API, especially when sending credentials via HTTP Basic Authentication. This ensures your credentials are encrypted during transit and protects them from potential eavesdroppers.

### Conclusion

The Gitea API offers a comprehensive way to manage users. Using Go, you can create efficient scripts to automate user management, ensuring consistent and secure practices.

## Setting up a Mutating Admission Webhook for Kubernetes

### Overview

A mutating admission webhook provides a powerful tool to intercept and modify requests to the Kubernetes API server. By setting up a webhook, you can inspect and potentially mutate Kubernetes objects before they are stored, giving you fine-grained control over the behavior and properties of resources in your cluster.

### Prerequisites

- A running Kubernetes cluster.
- `kubectl` installed and configured to communicate with your cluster.
- A domain or IP where the webhook service will be reachable from the Kubernetes API server.
- A tool to generate TLS certificates (e.g., `openssl`).

### Steps

1. **Implement the Webhook Server**:
   - Write a server application that listens for incoming webhook requests.
   - This server should inspect the AdmissionReview request, mutate the object if necessary, and then send an AdmissionResponse.

2. **Deploy the Webhook**:
   - Package your webhook server as a container and create a Kubernetes Deployment to run it.
   - Expose the webhook server as a Service inside the cluster.

3. **Generate TLS Certificates**:
   - For secure communication between the Kubernetes API server and your webhook, generate a TLS certificate and key.
   - Make sure the certificate is valid for the service name under the `.svc` domain (e.g., `webhook-service.default.svc`).

4. **Create a MutatingWebhookConfiguration**:
   - This configuration tells the Kubernetes API server to send specific requests to your webhook.
   - Specify the resources, operations (e.g., `CREATE`, `UPDATE`), and the URL of your webhook service.
   - Include the CA bundle of the TLS certificate in this configuration so the API server can trust the webhook's certificate.

5. **Set Permissions**:
   - Ensure your webhook has the necessary RBAC permissions to read or modify the resources it needs.
   - Create appropriate ServiceAccount, Role, and RoleBinding resources.

6. **Optional Namespace Selector**:
   - If you're only interested in resources from specific namespaces, add a namespace selector to your MutatingWebhookConfiguration.

### Conclusion

By following these steps, you can set up a mutating admission webhook that inspects and potentially modifies Kubernetes resources before they're stored. This gives you a powerful tool to enforce policies, add default settings, or make other changes to resources as they're created or updated in your cluster.
