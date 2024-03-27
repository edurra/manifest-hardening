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

func GenerateHardenedObject(obj runtime.Object, gVK *schema.GroupVersionKind, pol policy.Policy) (runtime.Object, []string, error) {

	var newObject runtime.Object
	var output []string

	switch gVK.Kind {
		case "Deployment":
			deployment, ok := obj.(*appsv1.Deployment)
			if !ok {
				return obj, output, errors.New("Error, could't assert the Deployment object")
			}
			newObject = deployment.DeepCopy()
			podSpec := &newObject.(*appsv1.Deployment).Spec.Template.Spec
			*podSpec, output = evaluatePodSpec(*podSpec, pol)

		case "Pod":
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return obj, output, errors.New("Error, could't assert the Pod object") 
			}
			newObject = pod.DeepCopy() 
			podSpec := &newObject.(*corev1.Pod).Spec
			*podSpec, output = evaluatePodSpec(*podSpec, pol)

		default:
			return obj, output, errors.New("Error, unkown resource kind")
	}

	return newObject, output, nil
}

func evaluatePodSpec(ps corev1.PodSpec, pol policy.Policy) (corev1.PodSpec, []string){
	var output []string

	if ps.SecurityContext == nil {
		ps.SecurityContext = &corev1.PodSecurityContext{}
	}

	if pol.HostPID == false && ps.HostPID != pol.HostPID {
		output = append(output, fmt.Sprintf("hostPID does not match. Setting it to %v. ", pol.HostPID))
		ps.HostPID = pol.HostPID
	}

	if pol.HostNetwork == false && ps.HostNetwork != pol.HostNetwork {
		output = append(output, fmt.Sprintf("hostNetwork does not match. Setting it to %v. ", pol.HostNetwork))
		ps.HostNetwork = pol.HostNetwork
	}

	if pol.HostIPC == false && ps.HostIPC != pol.HostIPC {
		output = append(output, fmt.Sprintf("hostIPC does not match. Setting it to %v. ", pol.HostIPC))
		ps.HostIPC = pol.HostIPC
	}

	if ps.Volumes != nil {
		newVolumes := []corev1.Volume{}
		for _, volume := range(ps.Volumes) {
			if utils.VolumeIsDisallowed(volume, pol.DisallowedVolumes) || (!utils.VolumeIsAllowed(volume, pol.AllowedVolumes)) {
				output = append(output, fmt.Sprintf("%s Volume not allowed. It has been deleted.", volume.Name))
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
				output = append(output, fmt.Sprintf("Host process does not match in pod security context. Setting it to %v.", pol.HostProcess))
				*ps.SecurityContext.WindowsOptions.HostProcess = pol.HostProcess
			}
		}
	}

	// hostProcess can be overwritten at container level
	ps.Containers, output = assessHostProcess(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessHostProcess(ps.InitContainers, pol, output)
	}

	ps.Containers, output = assessPrivileged(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessPrivileged(ps.InitContainers, pol, output)
	}

	ps.Containers, output = assessCapabilitiesAdd(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessCapabilitiesAdd(ps.InitContainers, pol, output)
	}

	ps.Containers, output = assessCapabilitiesDrop(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessCapabilitiesDrop(ps.InitContainers, pol, output)
	}

	ps.Containers, output = assessProcMount(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessProcMount(ps.InitContainers, pol, output)
	}

	if !utils.ContainsValue(pol.Seccomp, "Undefined") {
		if ps.SecurityContext.SeccompProfile != nil {
			if !utils.ContainsValue(pol.Seccomp, string(ps.SecurityContext.SeccompProfile.Type)) {
				output = append(output, fmt.Sprintf("Seccomp in pod security context not included in allowed values. Setting it to %v. ", "Default"))
				ps.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileType("Default")
			}
		} else {
			output = append(output, fmt.Sprintf("Seccomp in pod security context is undefined. Setting it to %v. ", "Default"))
			ps.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type: corev1.SeccompProfileType("Default"),
			}
			
		}
	}

	ps.Containers, output = assessSeccomp(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessSeccomp(ps.InitContainers, pol, output)
	}

	ps.Containers, output = assessAllowPrivilegeEscalation(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessAllowPrivilegeEscalation(ps.InitContainers, pol, output)
	}

	if pol.RunAsNonRoot == true {
		if ps.SecurityContext.RunAsNonRoot == nil {
			ps.SecurityContext.RunAsNonRoot = new(bool)
			*ps.SecurityContext.RunAsNonRoot = true
			output = append(output, fmt.Sprintf("Pod RunAsNonRoot does not match. It was modified."))
		}
		if *ps.SecurityContext.RunAsNonRoot == false {
			*ps.SecurityContext.RunAsNonRoot = true
			output = append(output, fmt.Sprintf("Pod RunAsNonRoot does not match. It was modified."))
		}
	}

	ps.Containers, output = assessRunAsNonRoot(ps.Containers, pol, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessRunAsNonRoot(ps.InitContainers, pol, output)
	}

	user := utils.RandomUser()
	if pol.RunAsUser == true {
		if ps.SecurityContext.RunAsUser == nil {
			ps.SecurityContext.RunAsUser = new(int64)
			*ps.SecurityContext.RunAsUser = user
			output = append(output, fmt.Sprintf("RunAsUser does not match for pod. Assigning random user value."))
		} else {
			if *ps.SecurityContext.RunAsUser == 0 {
				*ps.SecurityContext.RunAsUser = user
				output = append(output, fmt.Sprintf("RunAsUser does not match for pod. Assigning random user value."))
			}
		}
	}

	ps.Containers, output = assessRunAsUser(ps.Containers, pol, user, output)

	if ps.InitContainers != nil {
		ps.InitContainers, output = assessRunAsUser(ps.InitContainers, pol, user, output)
	}

	return ps, output
}


func assessPrivileged(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.Privileged != nil {
			if pol.Privileged == false && *container.SecurityContext.Privileged != pol.Privileged {
				output = append(output, fmt.Sprintf("Privileged does not match in container %v. Setting it to %v.", container.Name, pol.Privileged))
				*container.SecurityContext.Privileged = pol.Privileged
			}
		}	
	}
	return containers, output
}

func assessHostProcess(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.WindowsOptions != nil {
			if container.SecurityContext.WindowsOptions.HostProcess != nil {
				if pol.HostProcess == false && *container.SecurityContext.WindowsOptions.HostProcess != pol.HostProcess {
					output = append(output, fmt.Sprintf("HostProcess does not match in container %v. Setting it to %v.", container.Name, pol.HostProcess))
					*container.SecurityContext.WindowsOptions.HostProcess = pol.HostProcess
				}
			}	
		}
	}
	return containers, output
}


func assessCapabilitiesAdd(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.Capabilities == nil {
			container.SecurityContext.Capabilities = &corev1.Capabilities{
				Add:  []corev1.Capability{}, 
				Drop: []corev1.Capability{}, 
			}
		} else if container.SecurityContext.Capabilities.Add == nil {
			container.SecurityContext.Capabilities.Add = []corev1.Capability{}
		}
		
		newCapabilities := []corev1.Capability{}
		for _,capability := range(container.SecurityContext.Capabilities.Add) {
			if (utils.ContainsValue(pol.CapabilitiesAdd, "ALL") || utils.ContainsValue(pol.CapabilitiesAdd, string(capability))) {
				newCapabilities = append(newCapabilities, capability)
			} else {
				output = append(output, fmt.Sprintf("Capability: %v not allowed in container %v.", string(capability), container.Name))
			}
		}
		container.SecurityContext.Capabilities.Add = newCapabilities
		
		
	}
	return containers, output
}

func assessCapabilitiesDrop(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}

		if container.SecurityContext.Capabilities == nil {
			container.SecurityContext.Capabilities = &corev1.Capabilities{
				Add:  []corev1.Capability{}, 
				Drop: []corev1.Capability{}, 
			}
		} else if container.SecurityContext.Capabilities.Drop == nil {
			container.SecurityContext.Capabilities.Drop = []corev1.Capability{}
		}
		
		if utils.ContainsValue(pol.CapabilitiesDrop, "ALL") {
			container.SecurityContext.Capabilities.Drop = []corev1.Capability{"ALL"}
			output = append(output, fmt.Sprintf("Dropped all capabilities in container %v.", container.Name))
		} else {
			for _, capability := range(pol.CapabilitiesDrop) {
				if !utils.CapabilityInList(container.SecurityContext.Capabilities.Drop, capability) {
					container.SecurityContext.Capabilities.Drop = append(container.SecurityContext.Capabilities.Drop, corev1.Capability(capability))
					output = append(output, fmt.Sprintf("Dropped capability: %v in container %v.", string(capability), container.Name))
				}
			}
		}
		
	} 
	
	return containers, output
}

func assessProcMount(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.ProcMount != nil {
			if  *container.SecurityContext.ProcMount != corev1.ProcMountType(pol.ProcMount) && corev1.ProcMountType(pol.ProcMount) != "" {
				output = append(output, fmt.Sprintf("ProcMount does not match in container %v. Setting it to %v.", container.Name, pol.ProcMount))
				*container.SecurityContext.ProcMount  = corev1.ProcMountType(pol.ProcMount) 
			}
		}
	}
	return containers, output
}

func assessSeccomp(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.SeccompProfile != nil {
			if !utils.ContainsValue(pol.Seccomp, string(container.SecurityContext.SeccompProfile.Type)) {
				output = append(output, fmt.Sprintf("Seccomp profile not allowed in container %v. Setting it to %v.", container.Name, "Default"))
				container.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileType("Default")
			}
		}
	}
	return containers, output
}

func assessAllowPrivilegeEscalation(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		}
		if container.SecurityContext.AllowPrivilegeEscalation != nil {
			if pol.AllowPrivilegeEscalation == false && *container.SecurityContext.AllowPrivilegeEscalation != pol.Privileged {
				output = append(output, fmt.Sprintf("AllowPrivilegeEscalation does not match in container %v. Setting it to %v.", container.Name, pol.AllowPrivilegeEscalation))
				*container.SecurityContext.AllowPrivilegeEscalation = pol.AllowPrivilegeEscalation
			}
		}	
	}
	return containers, output
}

func assessRunAsNonRoot(containers []corev1.Container, pol policy.Policy, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		} 

		if pol.RunAsNonRoot == true  && container.SecurityContext.RunAsNonRoot != nil {
			if *container.SecurityContext.RunAsNonRoot == false {
				output = append(output, fmt.Sprintf("RunAsNonRoot does not match in container %v. Setting it to %v.", container.Name, pol.RunAsNonRoot))
				*container.SecurityContext.RunAsNonRoot = pol.RunAsNonRoot
			}
		}
	}
	return containers, output
}

func assessRunAsUser(containers []corev1.Container, pol policy.Policy, user int64, output []string) ([]corev1.Container, []string) {
	for _, container := range(containers) {
		if container.SecurityContext == nil {
			container.SecurityContext = &corev1.SecurityContext{}
		} 
		if pol.RunAsUser == true  && container.SecurityContext.RunAsUser != nil {
			if *container.SecurityContext.RunAsUser == 0 {
				output = append(output, fmt.Sprintf("RunAsUser does not match in container %v. Setting it to %v.", container.Name, user))
				*container.SecurityContext.RunAsUser = user
			}
		}
	}
	return containers, output
}