#!/usr/bin/env python

from kubernetes import client, config
import base64
import sys
import argparse
import os
import yaml

def get_kubernetes_ca_cert(api_instance, namespace="default"):
    # Retrieve the default service account
    service_account = api_instance.read_namespaced_service_account("default", namespace)
    
    # Find the token secret
    for secret in service_account.secrets:
        if secret.name.startswith("default-token"):
            # Read the secret
            token_secret = api_instance.read_namespaced_secret(secret.name, namespace)
            # Return the CA cert
            return base64.b64encode(token_secret.data['ca.crt'].encode('utf-8')).decode('utf-8')
    raise RuntimeError("Unable to find default token with ca.crt")

def create_mutating_webhook_configuration(namespace, ca_cert):
    webhook_configuration = client.V1MutatingWebhookConfiguration(
        metadata=client.V1ObjectMeta(name="user-mutator-webhook"),
        webhooks=[client.V1MutatingWebhook(
            name="usermutator.k8s.io",
            client_config=client.AdmissionregistrationV1WebhookClientConfig(
                service=client.AdmissionregistrationV1ServiceReference(
                    namespace=namespace,
                    name="user-mutator",
                    path="/mutate",
                    port=8000
                ),
                ca_bundle=ca_cert
            ),
            failure_policy="Ignore",
            rules=[client.V1RuleWithOperations(
                operations=["CREATE", "UPDATE"],
                api_groups=["apps"],
                api_versions=["v1"],
                resources=["deployments"]
            )],
            namespace_selector=client.V1LabelSelector(
                match_labels={"name": namespace }
            ),
            object_selector=client.V1LabelSelector(
                match_labels={"executor": "tycho" }
            ),
            side_effects="None",
            admission_review_versions=["v1"]
        )]
    )
    return webhook_configuration

def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')

def save_to_yaml(webhook_configuration, filename):
    with open(filename, 'w') as file:
        yaml.dump(webhook_configuration.to_dict(), file, default_flow_style=False)

def submit_to_cluster(webhook_configuration, api_instance):
    try:
        api_response = api_instance.create_mutating_webhook_configuration(webhook_configuration)
        print(f"MutatingWebhookConfiguration created: {api_response.metadata.name}")
    except client.rest.ApiException as e:
        print(f"Exception when submitting MutatingWebhookConfiguration: {e}")

def main(namespace, submit):
    config.load_kube_config()
    core_v1_api = client.CoreV1Api()
    ca_cert = get_kubernetes_ca_cert(core_v1_api, namespace)
    yaml_filename = f"{namespace}-mutating-webhook-configuration.yaml"

    if os.path.exists(yaml_filename):
        print(f"Using existing configuration from {yaml_filename}")
        with open(yaml_filename, 'r') as file:
            webhook_configuration_dict = yaml.safe_load(file)
            webhook_configuration = client.V1MutatingWebhookConfiguration(**webhook_configuration_dict)
    else:
        webhook_configuration = create_mutating_webhook_configuration(namespace, ca_cert)
        save_to_yaml(webhook_configuration, yaml_filename)

    if submit:
        admission_api = client.AdmissionregistrationV1Api()
        submit_to_cluster(webhook_configuration, admission_api)

yaml.add_representer(type(None), represent_none)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate and optionally submit a MutatingWebhookConfiguration.')
    parser.add_argument('namespace', type=str, help='The namespace for the webhook.')
    parser.add_argument('--submit', action='store_true', help='Submit the configuration to Kubernetes after generation.')
    args = parser.parse_args()
    main(args.namespace, args.submit)
