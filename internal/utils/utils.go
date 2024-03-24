package utils

import (
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/printers"
	"os"
	"reflect"
	"math/rand"
)

func ReadObject(filepath string)(runtime.Object, *schema.GroupVersionKind, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	stream, err := ioutil.ReadFile(filepath)

	if err != nil {
		return &corev1.Pod{}, nil, err
	}
	obj, gKV, err := decode(stream, nil, nil)
	
	if err != nil {
		return obj, gKV, err
	}

	return obj, gKV, nil
}

func WriteObject(filepath string, object runtime.Object) (error){
	newFile, err := os.Create(filepath)
	if err != nil {
		return err
	}

	y := printers.YAMLPrinter{}
	defer newFile.Close()
	y.PrintObj(object, newFile)
	
	return err
}

func ContainsValue(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func VolumeIsAllowed(volume corev1.Volume, allowedVolumes []string) (bool){
	allowed := false
	if ContainsValue(allowedVolumes, "*") {
		return true
	}

	for _, avol := range(allowedVolumes) {
		if !reflect.ValueOf(volume.VolumeSource).FieldByName(avol).IsNil() {
			allowed = true
		}
	}
	return allowed
}

func VolumeIsDisallowed(volume corev1.Volume, disallowedVolumes []string) (bool){
	disallowed := false
	for _, davol := range(disallowedVolumes) {
		if !reflect.ValueOf(volume.VolumeSource).FieldByName(davol).IsNil() {
			disallowed = true
		}
	}
	return disallowed
}

func RandomUser() (int64) {
	randNum := rand.Intn(65536)
	return int64(randNum + 1)
}
