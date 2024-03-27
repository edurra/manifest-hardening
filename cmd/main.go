package cmd

import (
	"edurra/manifest-hardening/internal/utils"
	"edurra/manifest-hardening/internal/policy"
	"edurra/manifest-hardening/internal/generator"
	"fmt"
	"flag"
	"os"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
)

func Run() {

	inputFile := flag.String("input", "", "input manifest")
	outputFile := flag.String("output", "", "output manifest")
	pol := flag.String("policy", "", "path to the policy config file")
	verbose := flag.Bool("verbose", false, "path to the policy config file")

	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Error: Missing required flag (inputFile)")
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

	
	newObject, output, err := generator.GenerateHardenedObject(obj, gKV, pol_cfg)

	if err == nil {

		if *verbose {
			for _, o := range(output) {
				fmt.Printf(o)
			}
			fmt.Println("")
		}

		if *outputFile == "" {
			fmt.Println("---")

			serializer := json.NewSerializerWithOptions(json.DefaultMetaFactory, nil, nil, json.SerializerOptions{Yaml: true})

			yamlBytes, err := runtime.Encode(serializer, obj)
			if err != nil {
				fmt.Printf("Error encoding object to YAML: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(string(yamlBytes))
			
		} else {
			utils.WriteObject(*outputFile, newObject)
		}
		
	} else {
		fmt.Println(err)
	}

}