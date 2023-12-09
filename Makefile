# Makefile

# Variable for the binary name
BINARY_NAME := user-mutator
# Variable for the container name
BASE_IMAGE := user-mutator
REGISTRY := containers.renci.org/helxplatform
IMAGE_TAG := $(REGISTRY)/$(BASE_IMAGE)
CHART_NAME := $(BASE_IMAGE)
VERSION := 0.0.1

## Kind Related
KIND_CLUSTER := mutator

organization := "RENCI"
tmpdir := ./certs
secret := user-mutator-cert-tls
mutate_config := mutating-webhook
webhook_service := user-mutator
webhook_namespace := mutating-webhook

.PHONY: build go-build go-test push ca-key-cert mutate-config key-cert-secret clean deploy-webhook-server deploy-all kind-up kind-load kind-down kind-all clean-all

# Build the Go application
build:
	docker buildx build \
	--platform=linux/amd64 \
	--tag=$(IMAGE_TAG):$(VERSION) \
	--tag=$(IMAGE_TAG):latest \
	--tag=$(BASE_IMAGE):$(VERSION) \
	--tag=$(BASE_IMAGE):latest \
	.

go-build:
	@echo "Building Go application..."
	cd webhook-server && go build -o $(BINARY_NAME)

# Run tests
go-test:
	@echo "Running tests..."
	cd webhook-server && go test -v ./...

push:
	docker push $(IMAGE_TAG):$(VERSION)
	docker push $(IMAGE_TAG):latest

ca-key-cert: export MUTATE_CONFIG = $(mutate_config)
ca-key-cert: export WEBHOOK_SERVICE = $(webhook_service)
ca-key-cert: export WEBHOOK_NAMESPACE = $(webhook_namespace)
ca-key-cert: export ORGANIZATION = $(organization)
ca-key-cert:
	cd tls-and-mwc && go run main.go createMutationConfig.go generateTLSCerts.go

mutate-config: export MUTATE_CONFIG = $(mutate_config)
mutate-config: export WEBHOOK_SERVICE = $(webhook_service)
mutate-config: export WEBHOOK_NAMESPACE = $(webhook_namespace)
mutate-config: export ORGANIZATION = $(organization)
mutate-config: ca-key-cert
	cd tls-and-mwc && go run main.go createMutationConfig.go generateTLSCerts.go -M
	@echo ""
	@echo "To view the MutationWebhookConfig YAML use the following command."
	@echo "  kubectl get MutatingWebhookConfiguration $(mutate_config) -o yaml"
	@echo ""

key-cert-secret: ca-key-cert
	# create the secret with CA cert and server cert/key
	kubectl create namespace $(webhook_namespace) || true && \
	kubectl create secret generic $(secret) --from-file=tls.key=$(tmpdir)/key.pem --from-file=tls.crt=$(tmpdir)/cert.pem --dry-run=client -o yaml | kubectl -n $(webhook_namespace) apply -f -
	@echo ""
	@echo "To view the secret YAML use the following command."
	@echo "  kubectl -n $(webhook_namespace) get secret $(secret) -o yaml"
	@echo ""

clean:
	@echo "Cleaning up..."
	kubectl delete MutatingWebhookConfiguration $(mutate_config) || true && \
	helm -n $(webhook_namespace) delete $(CHART_NAME) || true && \
	kubectl -n $(webhook_namespace) delete secret $(secret) || true && \
	rm -rf ./certs || true && \
	rm -f webhook-server/$(BINARY_NAME)

deploy-webhook-server: key-cert-secret
	helm -n $(webhook_namespace) upgrade --install $(CHART_NAME) --set "image.pullPolicy=IfNotPresent" ./chart
	@echo ""
	@echo "To view and follow the logs of the mutator use the following command."
	@echo "  kubectl -n $(webhook_namespace) -l app.kubernetes.io/name=user-mutator logs -f"
	@echo ""

deploy-all: deploy-webhook-server mutate-config

kind-up:
	kind create cluster --name $(KIND_CLUSTER)

kind-load:
	kind load docker-image $(IMAGE_TAG):latest --name $(KIND_CLUSTER)

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)

kind-all: kind-up build kind-load deploy-webhook-server mutate-config

clean-all: clean kind-down
