package policy

type Policy struct {
	HostPID bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	HostNetwork bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	HostIPC bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	Privileged bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	HostProcess bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	Capabilities []string // only included values are allowed, * can be included
	ProcMount string // this value is the only one allowed
	Seccomp []string // only values included are allowed. Need to add "Undefined" if empty seccomp profiles are allowed
	AllowedVolumes []string // only included values are allowed, * can be included
	DisallowedVolumes []string // included volumes are disallowed
	AllowPrivilegeEscalation bool // if true, both "true" and "false" are allowed. If "false", only "false" is allowed
	RunAsNonRoot bool // if true, only "true" is allowed. If "false", "true", "false" ,or nil are allowed
	RunAsUser bool // If true, a random value will be assigned. If false, the current value will be kept
}