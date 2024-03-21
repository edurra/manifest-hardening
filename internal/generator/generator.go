package generator

import (
	"example/internal/policy"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"fmt"
	"example/internal/utils"
)

func GenerateHardenedObject(obj runtime.Object, gVK *schema.GroupVersionKind, pol policy.Policy) (runtime.Object) {

	newObject := &appsv1.Deployment{}
	podSpec := corev1.PodSpec{}
	if gVK.Kind == "Deployment" {
		newObject = obj.(*appsv1.Deployment)

		podSpec = newObject.Spec.Template.Spec

		newPodSpec := evaluatePodSpec(podSpec, pol)

		newObject.Spec.Template.Spec = newPodSpec
		
	}
	
	return newObject
}

func evaluatePodSpec(ps corev1.PodSpec, pol policy.Policy) (corev1.PodSpec){

	if ps.SecurityContext == nil {
		ps.SecurityContext = &corev1.PodSecurityContext{}
	}

	if ps.HostPID != pol.HostPID {
		fmt.Println("hostPID does not match")
		ps.HostPID = pol.HostPID
	}

	if ps.HostNetwork != pol.HostNetwork {
		fmt.Println("hostNetwork does not match")
		ps.HostNetwork = pol.HostNetwork
	}

	if ps.HostIPC != pol.HostIPC {
		fmt.Println("hostIPC does not match")
		ps.HostIPC = pol.HostIPC
	}

	// Assess hostProcess for PodSecurityContext
	if ps.SecurityContext.WindowsOptions != nil {
		if ps.SecurityContext.WindowsOptions.HostProcess != nil {
			if *ps.SecurityContext.WindowsOptions.HostProcess != pol.HostProcess {
				fmt.Println("Host process does not match")
				*ps.SecurityContext.WindowsOptions.HostProcess = pol.HostProcess
			}
		}
	}

	// hostProcess can be overwritten at container level
	ps.Containers = assessHostProcess(ps.Containers, pol)

	if ps.InitContainers != nil {
		ps.InitContainers = assessHostProcess(ps.InitContainers, pol)
	}

	ps.Containers = assessPrivileged(ps.Containers, pol)

	if ps.InitContainers != nil {
		ps.InitContainers = assessPrivileged(ps.InitContainers, pol)
	}

	ps.Containers = assessCapabilities(ps.Containers, pol)

	return ps
}


func assessPrivileged(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.Privileged != nil {
			if *container.SecurityContext.Privileged != pol.Privileged {
				fmt.Println("Privileged does not match")
				*container.SecurityContext.Privileged = pol.Privileged
			}
		}	
	}
	return containers
}

func assessHostProcess(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.WindowsOptions != nil {
			if container.SecurityContext.WindowsOptions.HostProcess != nil {
				if *container.SecurityContext.WindowsOptions.HostProcess != pol.HostProcess {
					fmt.Println("HostProcess does not match")
					*container.SecurityContext.WindowsOptions.HostProcess = pol.HostProcess
				}
			}	
		}
	}
	return containers
}

func assessCapabilities(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.Capabilities != nil {
			if container.SecurityContext.Capabilities.Add != nil {
				newCapabilities := []corev1.Capability{}
				for _,capability := range(container.SecurityContext.Capabilities.Add) {
					if utils.ContainsValue(pol.Capabilities, string(capability)) {
						newCapabilities = append(newCapabilities, capability)
					} else {
						fmt.Printf("Droped capability: %v \n", string(capability))
					}
				}
				container.SecurityContext.Capabilities.Add = newCapabilities
			}	
		}
	}
	return containers
}
