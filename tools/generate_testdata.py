#!/usr/bin/env python

import sys
from jinja2 import Environment, BaseLoader

# Python script to generate a parameterized ConfigMap and PVC using Jinja2 templating and write them to files

configmap_template_text = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: user-features
  namespace: [[ namespace ]]
data:
  [[ username ]].json: |
    {
      "config": {
        "volumeMounts": [
          {
            "mountPath": "/mnt/test",
            "name": "test"
          }
        ],
        "volumeSources": [
          {
            "name": "test",
            "source": "pvc://[[ pvc_name ]]-test-pvc"
          }
        ]
      }
    }
"""

pvc_template_text = """
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: [[ pvc_name ]]-test-pvc
  namespace: [[ namespace ]]
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
"""

def generate_yaml(template_text, data, output_file):
    """
    Generates YAML with the given template and data using Jinja2 and writes it to a file.

    :param template_text: Template text for the YAML.
    :param data: Data to be used in the template.
    :param output_file: Path to the output file where the YAML will be written.
    :return: None
    """
    env = Environment(loader=BaseLoader(), variable_start_string='[[', variable_end_string=']]')
    template = env.from_string(template_text)
    yaml_content = template.render(data)
    
    with open(output_file, 'w') as file:
        file.write(yaml_content)

# Main execution
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: generate_configmap.py <namespace> <username>")
        sys.exit(1)

    namespace = sys.argv[1]
    username = sys.argv[2]
    pvc_name = username.lower()

    configmap_output_file = f"{namespace}_{username}_configmap.yaml"
    pvc_output_file = f"{namespace}_{pvc_name}_pvc.yaml"

    generate_yaml(configmap_template_text, {"namespace": namespace, "username": username, "pvc_name": pvc_name}, configmap_output_file)
    generate_yaml(pvc_template_text, {"namespace": namespace, "pvc_name": pvc_name}, pvc_output_file)

    print(f"ConfigMap written to {configmap_output_file}")
    print(f"PVC written to {pvc_output_file}")
