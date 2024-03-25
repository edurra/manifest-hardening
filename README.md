# Introduction
Automatically harden your K8s manifest according to a given policy.

# How to use it
To build the binary:

`go build .`

Run it:

`./manifest-hardening -input {inputFile} -output {outputFile} -policy {policyFile}`

Example:

`./manifest-hardening -input files/manifests/deployment.yaml -output files/hardened-manifest.yaml -policy files/policies/restricted.yaml`

The tool will check for compliance with the specified policy and automatically mutate the required files. The result will be stored in `output`.

Policies are defined as `.yaml` files. The `baseline` and `restricted` PSS policies are defined within the `files/policies` directory.

Supported resources: `Deployment`, `Pod`

# Configuration files

The allowed values are:

| Property                  | Description                                                  | Type    | Default                     |
|---------------------------|--------------------------------------------------------------|---------|----------------------------------------------------------------------|
| HostPID                   | Whether to allow the container to use the host's PID namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed. | boolean | `true`                                                               |
| HostNetwork               | Whether to allow the container to use the host's network namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed. | boolean | `true`                                                            |
| HostIPC                   | Whether to allow the container to use the host's IPC namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed. | boolean | `true`                                                                |
| Privileged                | Whether to run the container in privileged mode. If true, true/false/undefined are allowed. If false, only false/undefined allowed.               | boolean | `true`                                                                |
| HostProcess               | Whether to allow the container to access the host process namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed.  | boolean | `true`                                                         |
| CapabilitiesAdd           | Capabilities allowed to be in the Capabilities.Add field        | string  | `[ALL]`                                                  |
| CapabilitiesDrop          | Linux capabilities to drop from the container. If not specified, they will be added to the container.                 | string  | `[]`                                                                |
| ProcMount                 | The ProcMount type for the container                          | string  | `''`                                                              |
| Seccomp                   | Seccomp security profiles for the container. Need to add "Undefined" if empty seccomp profiles are allowed                   | string  | `[Undefined]`                                       |
| DisallowedVolumes         | Volume types disallowed for the container                     | string  | `[]`                                                          |
| AllowedVolumes            | Volume types allowed for the container                        | string  | `[*]` |
| AllowPrivilegeEscalation  | Whether to allow privilege escalation in the container. If true, true/false/undefined are allowed. If false, only false/undefined allowed.        | boolean | `true`                                                                |
| RunAsNonRoot              | Whether to run the container as a non-root user. If true, only true is allowed. If false, false/true/undefined are allowed.               | boolean | `false`                                                                 |
| RunAsUser                 | Whether to run the container as a specific user. If true, a random uid will be generated (if there isn't any already in use)               | boolean | `false`                                                                 |
