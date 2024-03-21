package policy

type Policy struct {
	HostPID bool
	HostNetwork bool
	HostIPC bool
	Privileged bool
	HostProcess bool
	Capabilities []string
	HostPath bool
	ProcMount string
	Seccomp []string
}