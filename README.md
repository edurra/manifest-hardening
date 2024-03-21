Automatically harden your K8s manifest according to a PSS policy.

To build the binary:

`go build .`

Run it:

`./manifest-hardening -input files/deployment.yaml -output files/hardened-manifest.yaml -policy baseline`

The tool will check for compliance with the specified policy and automatically mutate the required files. The result will be stored in `output`.

Currently, only the `baseline` policy is supported.

Supported resources: `Deployment`, `Pod`