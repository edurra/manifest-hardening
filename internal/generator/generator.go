package generator

import (
	"edurra/manifest-hardening/internal/policy"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"fmt"
	"edurra/manifest-hardening/internal/utils"
	"errors"
)

func GenerateHardenedObject(obj runtime.Object, gVK *schema.GroupVersionKind, pol policy.Policy) (runtime.Object, error) {

	var newObject runtime.Object

	switch gVK.Kind {
	case "Deployment":
		deployment, ok := obj.(*appsv1.Deployment)
		if !ok {
			return obj, errors.New("Error, could't assert the Deployment object")
		}
		newObject = deployment.DeepCopy()
		podSpec := &newObject.(*appsv1.Deployment).Spec.Template.Spec
		*podSpec = evaluatePodSpec(*podSpec, pol)

	case "Pod":
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return obj, errors.New("Error, could't assert the Pod object") 
		}
		newObject = pod.DeepCopy() 
		podSpec := &newObject.(*corev1.Pod).Spec
		*podSpec = evaluatePodSpec(*podSpec, pol)

	default:
		return obj, errors.New("Error, unkown resource kind")
	}

	return newObject, nil
}

func evaluatePodSpec(ps corev1.PodSpec, pol policy.Policy) (corev1.PodSpec){

	if ps.SecurityContext == nil {
		ps.SecurityContext = &corev1.PodSecurityContext{}
	}

	if pol.HostPID == false && ps.HostPID != pol.HostPID {
		fmt.Printf("hostPID does not match. Setting it to %v. \n", pol.HostPID)
		ps.HostPID = pol.HostPID
	}

	if pol.HostNetwork == false && ps.HostNetwork != pol.HostNetwork {
		fmt.Printf("hostNetwork does not match. Setting it to %v. \n", pol.HostNetwork)
		ps.HostNetwork = pol.HostNetwork
	}

	if pol.HostIPC == false && ps.HostIPC != pol.HostIPC {
		fmt.Printf("hostIPC does not match. Setting it to %v. \n", pol.HostIPC)
		ps.HostIPC = pol.HostIPC
	}

	if ps.Volumes != nil {
		newVolumes := []corev1.Volume{}
		for _, volume := range(ps.Volumes) {
			if utils.VolumeIsDisallowed(volume, pol.DisallowedVolumes) || (!utils.VolumeIsAllowed(volume, pol.AllowedVolumes)) {
				fmt.Printf("%s Volume not allowed. It has been deleted.\n", volume.Name)
			} else {
				newVolumes = append(newVolumes, volume)
			}
		}
		ps.Volumes = newVolumes
	}

	// Assess hostProcess for PodSecurityContext
	if ps.SecurityContext.WindowsOptions != nil {
		if ps.SecurityContext.WindowsOptions.HostProcess != nil {
			if pol.HostProcess == false && *ps.SecurityContext.WindowsOptions.HostProcess != pol.HostProcess {
				fmt.Printf("Host process does not match in pod security context. Setting it to %v.\n", pol.HostProcess)
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

	if ps.InitContainers != nil {
		ps.InitContainers = assessCapabilities(ps.InitContainers, pol)
	}

	ps.Containers = assessProcMount(ps.Containers, pol)

	if ps.InitContainers != nil {
		ps.InitContainers = assessProcMount(ps.InitContainers, pol)
	}

	if ps.SecurityContext.SeccompProfile != nil {
		if !utils.ContainsValue(pol.Seccomp, string(ps.SecurityContext.SeccompProfile.Type)) {
			fmt.Printf("Seccomp in pod security context not included in allowed values. Setting it to %v. \n", "Default")
			ps.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileType("Default")
		}
	} else {
		if !utils.ContainsValue(pol.Seccomp, "Undefined") {
			fmt.Printf("Seccomp in pod security context is undefined. Setting it to %v. \n", "Default")
			ps.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type: corev1.SeccompProfileType("Default"),
			}
		}
	}

	ps.Containers = assessSeccomp(ps.Containers, pol)

	if ps.InitContainers != nil {
		ps.InitContainers = assessSeccomp(ps.InitContainers, pol)
	}

	ps.Containers = assessAllowPrivilegeEscalation(ps.Containers, pol)

	if ps.InitContainers != nil {
		ps.InitContainers = assessAllowPrivilegeEscalation(ps.InitContainers, pol)
	}

	if pol.RunAsNonRoot == true {
		if ps.SecurityContext.RunAsNonRoot == nil {
			ps.SecurityContext.RunAsNonRoot = new(bool)
			*ps.SecurityContext.RunAsNonRoot = true
			fmt.Println("Pod RunAsNonRoot does not match. It was modified.")
		}
		if *ps.SecurityContext.RunAsNonRoot == false {
			*ps.SecurityContext.RunAsNonRoot = true
			fmt.Println("Pod RunAsNonRoot does not match. It was modified.")
		}
	}

	ps.Containers = assessRunAsNonRoot(ps.Containers, pol)

	if ps.InitContainers != nil {
		ps.InitContainers = assessRunAsNonRoot(ps.InitContainers, pol)
	}

	user := utils.RandomUser()
	if pol.RunAsUser == true {
		if ps.SecurityContext.RunAsUser == nil {
			ps.SecurityContext.RunAsUser = new(int64)
			*ps.SecurityContext.RunAsUser = user
			fmt.Println("RunAsUser does not match for pod. Assigning random user value.")
		} else {
			if *ps.SecurityContext.RunAsUser == 0 {
				*ps.SecurityContext.RunAsUser = user
				fmt.Println("RunAsUser does not match for pod. Assigning random user value.")
			}
		}
	}

	ps.Containers = assessRunAsUser(ps.Containers, pol, user)

	if ps.InitContainers != nil {
		ps.InitContainers = assessRunAsUser(ps.InitContainers, pol, user)
	}

	return ps
}


func assessPrivileged(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.Privileged != nil {
			if pol.Privileged == false && *container.SecurityContext.Privileged != pol.Privileged {
				fmt.Printf("Privileged does not match in container %v. Setting it to %v.\n", container.Name, pol.Privileged)
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
				if pol.HostProcess == false && *container.SecurityContext.WindowsOptions.HostProcess != pol.HostProcess {
					fmt.Printf("HostProcess does not match in container %v. Setting it to %v.\n", container.Name, pol.HostProcess)
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
					if utils.ContainsValue(pol.Capabilities, "*") || utils.ContainsValue(pol.Capabilities, string(capability)) {
						newCapabilities = append(newCapabilities, capability)
					} else {
						fmt.Printf("Dropped capability: %v in container %v.\n", string(capability), container.Name)
					}
				}
				container.SecurityContext.Capabilities.Add = newCapabilities
			}	
		}
	}
	return containers
}

func assessProcMount(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.ProcMount != nil {
			if  *container.SecurityContext.ProcMount != corev1.ProcMountType(pol.ProcMount) {
				fmt.Println("ProcMount does not match in container %v. Setting it to %v.\n", container.Name, pol.ProcMount)
				*container.SecurityContext.ProcMount  = corev1.ProcMountType(pol.ProcMount) 
			}
		}
	}
	return containers
}

func assessSeccomp(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.SeccompProfile != nil {
			if !utils.ContainsValue(pol.Seccomp, string(container.SecurityContext.SeccompProfile.Type)) {
				fmt.Printf("Seccomp profile not allowed in container %v. Setting it to %v.\n", container.Name, "Default")
				container.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileType("Default")
			}
		}
	}
	return containers
}

func assessAllowPrivilegeEscalation(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.AllowPrivilegeEscalation != nil {
			if pol.AllowPrivilegeEscalation == false && *container.SecurityContext.AllowPrivilegeEscalation != pol.Privileged {
				fmt.Printf("AllowPrivilegeEscalation does not match in container %v. Setting it to %v.\n", container.Name, pol.AllowPrivilegeEscalation)
				*container.SecurityContext.AllowPrivilegeEscalation = pol.AllowPrivilegeEscalation
			}
		}	
	}
	return containers
}

func assessRunAsNonRoot(containers []corev1.Container, pol policy.Policy) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		} 

		if pol.RunAsNonRoot == true  && container.SecurityContext.RunAsNonRoot != nil {
			if *container.SecurityContext.RunAsNonRoot == false {
				fmt.Printf("RunAsNonRoot does not match in container %v. Setting it to %v.\n", container.Name, pol.RunAsNonRoot)
				*container.SecurityContext.RunAsNonRoot = pol.RunAsNonRoot
			}
		}
	}
	return containers
}

func assessRunAsUser(containers []corev1.Container, pol policy.Policy, user int64) ([]corev1.Container) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		} 
		if pol.RunAsUser == true  && container.SecurityContext.RunAsUser != nil {
			if *container.SecurityContext.RunAsUser == 0 {
				fmt.Printf("RunAsUser does not match in container %v. Setting it to %v.\n", container.Name, user)
				*container.SecurityContext.RunAsUser = user
			}
		}
	}
	return containers
}