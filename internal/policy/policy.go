package policy

type Policy struct {
	HostPID bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	HostNetwork bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	HostIPC bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	Privileged bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	HostProcess bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	Capabilities []string // only included values are allowed, * can be included
	HostPath bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	ProcMount string // this value is the only one allowed
	Seccomp []string //only values included are allowed
}