Automatically harden your K8s manifest according to a PSS policy.

`go build .`

`./manifest-hardening -input files/deployment.yaml -output files/hardened-manifest.yaml -policy baseline`

Currently, only the `baseline` policy is supported.

Supported resources: `Deployment`, `Pod`