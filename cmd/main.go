package cmd

import (
	"edurra/manifest-hardening/internal/utils"
	"edurra/manifest-hardening/internal/policy"
	"edurra/manifest-hardening/internal/generator"
	"fmt"
	"flag"
	"os"
	"github.com/spf13/viper"
)

func Run() {

	inputFile := flag.String("input", "", "input manifest")
	outputFile := flag.String("output", "", "output manifest")
	pol := flag.String("policy", "", "path to the policy config file")

	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Error: Missing required flag (inputFile)")
		flag.Usage()
		os.Exit(1)
	}

	if *outputFile == "" {
		fmt.Println("Error: Missing required flag (outputFile)")
		flag.Usage()
		os.Exit(1)
	}

	if *pol == "" {
		fmt.Println("Error: Missing required flag (policy)")
		flag.Usage()
		os.Exit(1)
	}

	viper.SetConfigName("config")
	viper.SetConfigFile(*pol)
	viper.SetConfigType("yml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	var pol_cfg policy.Policy

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

	obj, gKV, err := utils.ReadObject(*inputFile)

	if err != nil {
		fmt.Println(err)
	}

	
	newObject, err := generator.GenerateHardenedObject(obj, gKV, pol_cfg)

	if err == nil {
		utils.WriteObject(*outputFile, newObject)
	} else {
		fmt.Println(err)
	}

}