package cmd

import (
	"edurra/manifest-hardening/internal/utils"
	"edurra/manifest-hardening/internal/policy"
	"edurra/manifest-hardening/internal/generator"
	"fmt"
	"flag"
	"os"
)

func Run() {

	inputFile := flag.String("input", "", "input manifest")
	outputFile := flag.String("output", "", "output manifest")
	pol := flag.String("policy", "", "policy {baseline}")

	flag.Parse()

	if *inputFile == "" || *outputFile == "" {
		fmt.Println("Error: Missing required flag")
		flag.Usage()
		os.Exit(1)
	}

	if *pol != "baseline"  && *pol != "restricted" {
		fmt.Println("Error: Missing policy")
		flag.Usage()
		os.Exit(1)
	}

	policies := map[string]policy.Policy{
		"baseline": policy.Policy{
			HostPID: false,
			HostNetwork: false,
			HostIPC: false,
			Privileged: false,
			HostProcess: false,
			Capabilities: []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"},
			ProcMount: "Default",
			Seccomp: []string{"RuntimeDefault", "Localhost", "Undefined"},
			DisallowedVolumes: []string{"HostPath"},
			AllowedVolumes: []string{"*"},
			AllowPrivilegeEscalation: true,
			RunAsNonRoot: false,
			RunAsUser: false,
		},
		"restricted": policy.Policy{
			HostPID: false,
			HostNetwork: false,
			HostIPC: false,
			Privileged: false,
			HostProcess: false,
			Capabilities: []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"},
			ProcMount: "Default",
			Seccomp: []string{"RuntimeDefault", "Localhost"},
			DisallowedVolumes: []string{"HostPath"},
			AllowedVolumes: []string{"ConfigMap", "CSI", "DownwardAPI", "EmptyDir", "Ephemeral", "PersistentVolumeClaim", "Projected", "Secret"},
			AllowPrivilegeEscalation: false,
			RunAsNonRoot: true,
			RunAsUser: true,
		},
	}

	obj, gKV, err := utils.ReadObject(*inputFile)

	if err != nil {
		fmt.Println(err)
	}

	
	newObject, err := generator.GenerateHardenedObject(obj, gKV, policies[*pol])

	if err == nil {
		utils.WriteObject(*outputFile, newObject)
	} else {
		fmt.Println(err)
	}

}