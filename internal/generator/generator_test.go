package generator

import (
	"testing"
	"edurra/manifest-hardening/internal/policy"
	"edurra/manifest-hardening/internal/utils"
	corev1 "k8s.io/api/core/v1"
)


func TestAssessPrivileged(t *testing.T) {
	policy1 := policy.Policy{Privileged: false}
	policy2 := policy.Policy{Privileged: false}
	container1 := corev1.Container{Name: "container1"}
	privilegedFalse := false
	privilegedTrue := true
	container1.SecurityContext = &corev1.SecurityContext{Privileged: &privilegedFalse}
	container2 := corev1.Container{Name: "container2"}
	container2.SecurityContext = &corev1.SecurityContext{Privileged: &privilegedTrue}
	
	containers := []corev1.Container{container1, container2}

	result1 := assessPrivileged(containers, policy1)


	for _, c := range(result1) {
		if *c.SecurityContext.Privileged != false {
			t.Fatalf("TestAssessPrivileged returned %v for %v", *c.SecurityContext.Privileged, c.Name)
		} 
	}

	result2 := assessPrivileged(containers, policy2)

	for i, c := range(result2) {
		if result2[i].SecurityContext.Privileged != c.SecurityContext.Privileged {
			t.Fatalf("TestAssessPrivileged returned %v for %v", *c.SecurityContext.Privileged, c.Name)
		} 
	}
}

func TestAssessCapabilitiesAdd(t *testing.T) {
	policy1 := policy.Policy{CapabilitiesAdd: []string{"ALL"}}
	policy2 := policy.Policy{CapabilitiesAdd: []string{"NET_ADMIN", "CHOWN"}}
	policy3 := policy.Policy{CapabilitiesAdd: []string{}}

	container1 := corev1.Container{Name: "container1"}
	capabilitiesAdd1 := []corev1.Capability{"NET_ADMIN", "FOWNER"}
	capabilitiesAdd2 := []corev1.Capability{""}
	container1.SecurityContext = &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: capabilitiesAdd1}}
	container2 := corev1.Container{Name: "container2"}
	container2.SecurityContext = &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: capabilitiesAdd2}}
	
	container3 := corev1.Container{Name: "container3"}

	containers := []corev1.Container{container1, container2, container3}

	result1 := assessCapabilitiesAdd(containers, policy1)

	for i, c := range(result1) {

		if containers[i].SecurityContext == nil {
			if c.SecurityContext != nil {
				t.Fatalf("TestAssessCapabilititesAdd not nil for %v", c.Name)
			}
		} else if !utils.CapabilititesEqual(c.SecurityContext.Capabilities.Add, containers[i].SecurityContext.Capabilities.Add) {
			t.Fatalf("TestAssessCapabilititesAdd returned %v for %v", utils.CapabilititesToString(c.SecurityContext.Capabilities.Add), c.Name)
		}

	}

	result2 := assessCapabilitiesAdd(containers, policy2)

	for i, c := range(result2) {

		if containers[i].SecurityContext == nil {
			if c.SecurityContext != nil {
				t.Fatalf("TestAssessCapabilititesAdd not nil for %v", c.Name)
			}
		} else {
			for _, cap := range(c.SecurityContext.Capabilities.Add) {
				if !utils.ContainsValue(policy2.CapabilitiesAdd, string(cap)) {
					t.Fatalf("TestAssessCapabilititesAdd returned %v for container %v", string(cap), c.Name)
				}
			}
		}
	}

	result3 := assessCapabilitiesAdd(containers, policy3)

	for i, c := range(result3) {

		if containers[i].SecurityContext == nil {
			if c.SecurityContext != nil {
				t.Fatalf("TestAssessCapabilititesAdd not nil for %v", c.Name)
			}
		} else {
			if len(c.SecurityContext.Capabilities.Add) > 0 {
				t.Fatalf("TestAssessCapabilititesAdd not empty for %v", c.Name)
			}
		}
	}
	
}