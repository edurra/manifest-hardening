package main

import (
	"example/internal/utils"
	"example/internal/policy"
	"example/internal/generator"
	"fmt"
	//appsv1 "k8s.io/api/apps/v1"
)

func main() {
	
	policies := map[string]policy.Policy{
		"baseline": policy.Policy{
			HostPID: false,
			HostNetwork: false,
			HostIPC: false,
			Privileged: false,
			HostProcess: false,
			Capabilities: []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"},
		},
	}

	obj, gKV, err := utils.ReadObject("test.yaml")

	if err != nil {
		fmt.Println(err)
	}

	
	newObject := generator.GenerateHardenedObject(obj, gKV, policies["baseline"])

	utils.WriteObject("test2.yaml", newObject)

	//newObject2 := newObject.(*appsv1.Deployment)
	//fmt.Println(*newObject2.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)
}