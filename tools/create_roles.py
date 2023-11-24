#!/usr/bin/env python

import argparse
import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException

def generate_yaml(sa_name, namespace):
    yaml_content = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: {namespace}
  name: sgclusters-role
rules:
- apiGroups: ["stackgres.io"]
  resources: ["sgclusters"]
  verbs: ["create", "get", "list", "watch", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sgclusters-role-binding
  namespace: {namespace}
subjects:
- kind: ServiceAccount
  name: {sa_name}
  namespace: {namespace}
roleRef:
  kind: Role
  name: sgclusters-role
  apiGroup: rbac.authorization.k8s.io
"""
    return yaml_content

def apply_configuration(file_path):
    config.load_kube_config()
    with open(file_path, 'r') as f:
        yaml_content = f.read()
        k8s_client = client.api_client.ApiClient()
        try:
            api_response = client.api_client.ApiClient().create_from_yaml(yaml_content)
            print(api_response)
        except ApiException as e:
            print(f"Exception when calling Kubernetes API: {e}")

def main():
    parser = argparse.ArgumentParser(description="Generate and optionally apply a Kubernetes Role and RoleBinding for a service account.")
    parser.add_argument("service_account", help="Name of the service account")
    parser.add_argument("namespace", help="Kubernetes namespace")
    parser.add_argument("--submit", action="store_true", help="Apply the configuration using Kubernetes Python client")
    
    args = parser.parse_args()
    file_name = f"{args.namespace}_{args.service_account}_role_binding.yaml"

    if not os.path.exists(file_name):
        yaml_content = generate_yaml(args.service_account, args.namespace)
        with open(file_name, 'w') as file:
            file.write(yaml_content)
        print(f"Generated YAML file: {file_name}")
    else:
        print(f"Using existing YAML file: {file_name}")

    if args.submit:
        print("Applying configuration...")
        apply_configuration(file_name)

if __name__ == "__main__":
    main()
