package cmd

import (
	"edurra/manifest-hardening/internal/utils"
	"edurra/manifest-hardening/internal/policy"
	"edurra/manifest-hardening/internal/generator"
	"fmt"
	"flag"
	"os"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime"
)

func Run() {
	var obj runtime.Object
	var gKV *schema.GroupVersionKind
	var err error
	var pol_cfg policy.Policy

	inputFile := flag.String("input", "", "input manifest")
	outputFile := flag.String("output", "", "output manifest")
	pol := flag.String("policy", "", "either the path to the policy config file or the name of the policy {restricted, baseline}")
	verbose := flag.Bool("verbose", false, "print the changes made to the manifest")

	flag.Parse()

	if *inputFile == "" {
		obj, gKV, err = utils.ReadFromPipe()

		if err != nil {
			fmt.Println(err)
			flag.Usage()
			os.Exit(1)
		}

	} else {
		obj, gKV, err = utils.ReadObject(*inputFile)
	}

	if *pol == "restricted" || *pol == "baseline" {

		pol_cfg = getPolicy(*pol)

	} else if *pol != ""{

		viper.SetConfigName("config")
		viper.SetConfigFile(*pol)
		viper.SetConfigType("yml")
	
		if err := viper.ReadInConfig(); err != nil {
			fmt.Printf("Error reading config file, %s", err)
			os.Exit(1)
		}
	
	
		viper.SetDefault("HostPID", true)
		viper.SetDefault("HostNetwork", true)
		viper.SetDefault("HostIPC", true)
		viper.SetDefault("Privileged", true)
		viper.SetDefault("HostProcess", true)
		viper.SetDefault("CapabilitiesAdd", []string{"ALL"})
		viper.SetDefault("CapabilitiesDrop", []string{})
		viper.SetDefault("ProcMount", "")
		viper.SetDefault("Seccomp", []string{"Undefined"})
		viper.SetDefault("AllowedVolumes", []string{"*"})
		viper.SetDefault("DisAllowedVolumes", []string{})
		viper.SetDefault("AllowPrivilegeEscalation", true)
		viper.SetDefault("RunAsNonRoot", false)
		viper.SetDefault("RunAsUser", false)
	
		if err := viper.Unmarshal(&pol_cfg); err != nil {
			fmt.Println("Error unmarshaling config file:", err)
			return
		}
	
	
		if err != nil {
			fmt.Println(err)
		}

	} else {
		fmt.Println("Error: Missing required flag (policy)")
		flag.Usage()
		os.Exit(1)
	}

	

	newObject, output, err := generator.GenerateHardenedObject(obj, gKV, pol_cfg)

	if err == nil {

		if *verbose {
			for _, o := range(output) {
				fmt.Println(o)
			}
			fmt.Println("")
		}

		if *outputFile == "" {
			objStr, _ := utils.ObjToString(newObject)
			fmt.Println("---")
			fmt.Println(objStr)
		} else {
			utils.WriteObject(*outputFile, newObject)
		}
		
	} else {
		fmt.Println(err)
	}

}

func getPolicy(pol string) (policy.Policy) {
	policies := map[string]policy.Policy{
		"baseline": policy.Policy{
			HostPID: false,
			HostNetwork: false,
			HostIPC: false,
			Privileged: false,
			HostProcess: false,
			CapabilitiesAdd: []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"},
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
			CapabilitiesAdd: []string{"NET_BIND_SERVICE"},
			CapabilitiesDrop: []string{"ALL"},
			ProcMount: "Default",
			Seccomp: []string{"RuntimeDefault", "Localhost"},
			DisallowedVolumes: []string{"HostPath"},
			AllowedVolumes: []string{"ConfigMap", "CSI", "DownwardAPI", "EmptyDir", "Ephemeral", "PersistentVolumeClaim", "Projected", "Secret"},
			AllowPrivilegeEscalation: false,
			RunAsNonRoot: true,
			RunAsUser: true,
		},
	}
	return policies[pol]
}
