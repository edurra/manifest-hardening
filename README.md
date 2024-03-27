# Introduction
Automatically harden your K8s manifest according to a given policy.

# How to use it
To build the binary:

`go build .`

Run it:

`./manifest-hardening  <-policy {policyFile, policyName(restricted|baseline)}>  [-input inputFile]  [-output outputFile] [-verbose]`



- `policy` (required): path of the file containing the policy to use. It also admits the name of the PSS policy (i.e. `baseline` or `restricted`)
- `output` (optional): path to store the output manifest. If not set, it will be printed to console
- `input` (optional): path to the input manifest. **Note**: If no `inputFile` is provided, it is mandatory to pipe the manifest (e.g. `cat pod.yaml | ./manifest-hardening -policy file.yaml`). This is convenient when creating pods or deployments using `kubectl create/run --dry-run=client`. See the **Examples** section.
- `verbose` (optional): print the changes made to the manifest

The tool will check for compliance with the specified policy and automatically mutate the required files. The result will be stored in `output` or printed to the console.

Policies are defined as `.yaml` files. The `baseline` and `restricted` PSS policies are defined within the `files/policies` directory. They are also hardcoded, so they can be directly called by using (`-policy {baseline, restricted}`).

The supported resources are: `Deployment`, `Pod`


## Examples

Input, output and policy as files:

`./manifest-hardening -input files/manifests/deployment.yaml -output files/hardened-manifest.yaml -policy files/policies/restricted.yaml -verbose`

Input as file, output to console and PSS policy name:

`./manifest-hardening -input files/manifests/deployment.yaml -policy baseline -verbose`

Input as a pipe using `kubectl run`:

 `kubectl run nginx --image=nginx --dry-run=client -o yaml --command -- sleep infinity | ./manifest-hardening -policy restricted` 

# Configuration files

The allowed values are:

| Property                  | Description                                                  | Type    | Default                     |
|---------------------------|--------------------------------------------------------------|---------|----------------------------------------------------------------------|
| HostPID                   | Whether to allow the container to use the host's PID namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed. | boolean | `true`                                                               |
| HostNetwork               | Whether to allow the container to use the host's network namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed. | boolean | `true`                                                            |
| HostIPC                   | Whether to allow the container to use the host's IPC namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed. | boolean | `true`                                                                |
| Privileged                | Whether to run the container in privileged mode. If true, true/false/undefined are allowed. If false, only false/undefined allowed.               | boolean | `true`                                                                |
| HostProcess               | Whether to allow the container to access the host process namespace. If true, true/false/undefined are allowed. If false, only false/undefined allowed.  | boolean | `true`                                                         |
| CapabilitiesAdd           | Capabilities allowed to be in the Capabilities.Add field        | []string  | `[ALL]`                                                  |
| CapabilitiesDrop          | Linux capabilities to drop from the container. If not specified, they will be added to the container.                 | []string  | `[]`                                                                |
| ProcMount                 | The ProcMount type for the container                          | string  | `''`                                                              |
| Seccomp                   | Seccomp security profiles for the container. Need to add "Undefined" if empty seccomp profiles are allowed                   | []string  | `[Undefined]`                                       |
| DisallowedVolumes         | Volume types disallowed for the container                     | []string  | `[]`                                                          |
| AllowedVolumes            | Volume types allowed for the container                        | []string  | `[*]` |
| AllowPrivilegeEscalation  | Whether to allow privilege escalation in the container. If true, true/false/undefined are allowed. If false, only false/undefined allowed.        | boolean | `true`                                                                |
| RunAsNonRoot              | Whether to run the container as a non-root user. If true, only true is allowed. If false, false/true/undefined are allowed.               | boolean | `false`                                                                 |
| RunAsUser                 | Whether to run the container as a specific user. If true, a random uid will be generated (if there isn't any already in use)               | boolean | `false`                                                                 |
