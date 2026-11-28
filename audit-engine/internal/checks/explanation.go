package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func evidenceNumber(value any) (float64, bool) {
	if value == nil {
		return 0, false
	}

	number, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(value)), 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

func evidenceText(f Finding, key string) string {
	value, _ := f.Evidence[key].(string)
	return strings.TrimSpace(value)
}

func hasPositiveEvidence(f Finding, key string) bool {
	value, ok := evidenceNumber(f.Evidence[key])
	return ok && value > 0
}

func hasValidKeyWindow(f Finding) bool {
	validAfter := evidenceText(f, "valid_after_time")
	validBefore := evidenceText(f, "valid_before_time")

	if validAfter == "" && validBefore == "" {
		return true
	}

	now := time.Now().UTC()

	if validAfter != "" {
		start, err := time.Parse(time.RFC3339, validAfter)
		if err != nil || now.Before(start) {
			return false
		}
	}

	if validBefore != "" {
		end, err := time.Parse(time.RFC3339, validBefore)
		if err != nil || !now.Before(end) {
			return false
		}
	}

	return true
}

func generatedExplanation(f Finding) *FindingExplanation {
	if f.Status != StatusWarning && f.Status != StatusCritical && f.Status != StatusError {
		return nil
	}

	switch {
	case f.ID == "GCP001":
		role := evidenceText(f, "role")
		members := evidenceStrings(f.Evidence["members"])
		if (role != "roles/owner" && role != "roles/editor") || len(members) == 0 {
			return nil
		}

		roleName := "Editor"
		if role == "roles/owner" {
			roleName = "Owner"
		}

		return &FindingExplanation{
			WhyItMatters: "Project-level " + roleName + " access grants broad permissions. If an assigned identity is compromised or misused, the impact may extend across multiple project resources.",
			TechnicalExplanation: fmt.Sprintf(
				"The collected IAM binding assigns %s to %d member(s). Review the listed members and any IAM condition to understand the effective access.",
				role, len(members),
			),
			BusinessImpact:       "A compromised or misused privileged identity could affect project resources, data, or services. The actual impact depends on the resources and permissions available.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Reducing permissions to the minimum required limits the scope of actions an identity can perform if it is misused or compromised.",
		}

	case f.ID == "GCP003":
		principals := evidenceStrings(f.Evidence["public_principals"])
		if len(principals) == 0 {
			return nil
		}

		role := evidenceText(f, "role")
		if role == "" {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters: "The IAM binding includes a public principal, which can make the permissions in that binding available beyond individually named identities.",
			TechnicalExplanation: fmt.Sprintf(
				"The collected binding grants %s to these public principal(s): %s. Any IAM condition must also be evaluated to determine when the binding applies.",
				role, strings.Join(principals, ", "),
			),
			BusinessImpact:       "If the binding is effective for unintended callers, project resources or data covered by the granted role may be accessible outside the intended audience. Actual accessibility has not been established by this finding alone.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Removing unnecessary public principals and using specific identities reduces unintended access while preserving required application functionality.",
		}

	case f.ID == "GCP002":
		keyName := evidenceText(f, "key_name")
		disabled, hasDisabled := f.Evidence["disabled"].(bool)
		if keyName == "" || !hasDisabled || disabled || !hasValidKeyWindow(f) {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "An active user-managed service-account key is a credential that can be copied and used outside the normal workload identity flow.",
			TechnicalExplanation: "The inventory identifies an enabled user-managed service-account key. Any supplied validity timestamps are consistent with it being active. The evidence does not establish that the key has been exposed or misused.",
			BusinessImpact:       "If the key is copied by an unauthorized party, it could be used to authenticate as the service account and access resources permitted to that identity.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Workload identity or service-account impersonation avoids distributing long-lived key material. Where keys remain necessary, restricted storage, rotation, and activity monitoring reduce exposure.",
		}

	case strings.HasPrefix(f.ID, "APPSEC-VULN-"):
		vulnerabilityID := evidenceText(f, "vulnerability_id")
		pkg := evidenceText(f, "package")
		version := evidenceText(f, "version")
		if vulnerabilityID == "" || pkg == "" || version == "" {
			return nil
		}

		fixedVersion := evidenceText(f, "fixed_version")
		technical := fmt.Sprintf(
			"The scanner identified vulnerability %s in package %s version %s.",
			vulnerabilityID, pkg, version,
		)
		if fixedVersion != "" {
			technical += " The scanner reports " + fixedVersion + " as the fixed version."
		}

		return &FindingExplanation{
			WhyItMatters:         "A known vulnerability in an application dependency may expose the application to a weakness described by the vulnerability advisory.",
			TechnicalExplanation: technical,
			BusinessImpact:       "Depending on the vulnerability and whether the affected code path is reachable, exploitation could affect application confidentiality, integrity, or availability. Exploitability has not been established by the dependency finding alone.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Moving to a scanner-reported fixed version, after compatibility and regression testing, removes the identified vulnerable dependency version from the application build.",
		}

	case f.ID == "DCK002":
		if !hasPositiveEvidence(f, "unhealthy_count") {
			return nil
		}

		count, _ := evidenceNumber(f.Evidence["unhealthy_count"])
		return &FindingExplanation{
			WhyItMatters:         "One or more containers are failing their configured health checks. This can indicate that an application process or one of its dependencies is not operating as expected.",
			TechnicalExplanation: fmt.Sprintf("The Docker inventory reports %.0f unhealthy container(s). A health-check failure is an observed status; the underlying cause requires inspection of container health-check output and logs.", count),
			BusinessImpact:       "If an unhealthy container serves production traffic or a required background task, users or dependent services may experience degraded functionality or failed operations.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Inspecting health-check output and logs helps identify the underlying fault before deciding whether configuration changes, dependency repairs, or a controlled restart are appropriate.",
		}

	case f.ID == "DCK003":
		if !hasPositiveEvidence(f, "stopped_count") {
			return nil
		}

		count, _ := evidenceNumber(f.Evidence["stopped_count"])
		return &FindingExplanation{
			WhyItMatters:         "The collected Docker inventory contains stopped containers. Some may be intentionally stopped, but others may represent workloads that did not start or remain running as expected.",
			TechnicalExplanation: fmt.Sprintf("The inventory reports %.0f stopped, exited, created, or dead container(s). Their intended lifecycle and restart policies are not established by this count.", count),
			BusinessImpact:       "If a stopped container is responsible for a required application, worker, or scheduled task, its absence may interrupt that function.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Confirming the intended state and reviewing exit status, logs, and restart policy avoids restarting containers that are deliberately stopped.",
		}

	case f.ID == "DCK004":
		if evidenceText(f, "error") == "" {
			return nil
		}
		daemonAvailable, ok := f.Evidence["daemon_available"].(bool)
		if !ok || !daemonAvailable {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "The Docker daemon is reachable, but one or more inventory operations failed. This reduces the completeness of the auditor's view of the Docker environment.",
			TechnicalExplanation: "The recorded collection error indicates that some Docker inventory data could not be retrieved. Counts in the report may therefore be incomplete.",
			BusinessImpact:       "Unseen containers, images, networks, or volumes may prevent a complete operational or security assessment. This finding does not establish that a workload is unavailable.",
			ImpactConfidence:     "evidence_backed",
			RemediationRationale: "Resolving the collection error and repeating the inventory check improves assessment coverage and helps ensure that subsequent findings are based on complete data.",
		}

	case f.ID == "DCK006":
		used, ok := evidenceNumber(f.Evidence["filesystem_used_percent"])
		if !ok || used < 80 || evidenceText(f, "docker_root_dir") == "" {
			return nil
		}

		technical := fmt.Sprintf("The filesystem backing Docker's data directory is reported as %.0f%% used.", used)
		impact := "As available space decreases, Docker operations that need filesystem capacity may fail. This could affect image pulls, container writes, or workload operation if the filesystem becomes full."
		if used >= 90 {
			technical += " This meets the critical threshold of 90%."
		} else {
			technical += " This meets the warning threshold of 80%."
		}

		return &FindingExplanation{
			WhyItMatters:         "Docker depends on free filesystem capacity for container writable layers, logs, images, and other data.",
			TechnicalExplanation: technical,
			BusinessImpact:       impact,
			ImpactConfidence:     "potential",
			RemediationRationale: "Monitoring growth and identifying the source of disk consumption early provides time to plan safe capacity changes or reviewed cleanup without deleting data blindly.",
		}

	case f.ID == "K8S003":
		if !strings.EqualFold(evidenceText(f, "phase"), "failed") {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "The Kubernetes API reports this pod in the Failed phase, meaning it did not complete its expected lifecycle successfully.",
			TechnicalExplanation: "The pod phase is recorded as Failed. Pod events, container termination details, and logs are needed to identify the cause.",
			BusinessImpact:       "If the pod belongs to a required application or workload and replacement capacity is insufficient, application functionality or processing capacity may be reduced.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Inspecting events and container logs identifies whether the failure is caused by application errors, resource constraints, configuration, or dependencies before remediation.",
		}

	case f.ID == "K8S004":
		if !strings.EqualFold(evidenceText(f, "phase"), "pending") {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "The pod has not reached Running or Succeeded, so Kubernetes has not yet brought that workload instance into its expected running state.",
			TechnicalExplanation: "The API reports the pod phase as Pending. Scheduling events, resource requests, node capacity, and volume attachment status can help identify why it has not progressed.",
			BusinessImpact:       "If the pod is needed to meet application capacity or run a required task, delayed scheduling may reduce capacity or delay processing.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Checking scheduling events and resource availability helps address the actual constraint instead of changing deployment settings without evidence.",
		}

	case f.ID == "K8S005":
		restarts, ok := evidenceNumber(f.Evidence["restart_count"])
		if !ok || restarts < 5 {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "Repeated container restarts can indicate that a workload is repeatedly exiting or failing its startup or health checks.",
			TechnicalExplanation: fmt.Sprintf("The pod has a recorded restart count of %.0f. This count does not by itself identify the cause of the restarts.", restarts),
			BusinessImpact:       "If restarts continue, the workload may be intermittently unavailable or provide reduced capacity, depending on its role and redundancy.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Reviewing current and previous container logs, pod events, probes, and resource limits helps identify and correct the cause of repeated restarts.",
		}

	case f.ID == "K8S006":
		desired, desiredOK := evidenceNumber(f.Evidence["desired_replicas"])
		ready, readyOK := evidenceNumber(f.Evidence["ready_replicas"])
		if !desiredOK || !readyOK || desired <= ready || desired <= 0 {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "The deployment has fewer ready replicas than desired, so it is not currently meeting its configured replica target.",
			TechnicalExplanation: fmt.Sprintf("The deployment reports %.0f ready replicas out of %.0f desired replicas.", ready, desired),
			BusinessImpact:       "The workload may have less capacity or redundancy than intended. If remaining replicas cannot handle demand or fail, users may experience degraded service or interruption.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Reviewing pod readiness, scheduling, deployment events, and resource availability helps restore the intended replica count and resilience.",
		}

	case f.ID == "K8S007":
		reasons := evidenceStrings(f.Evidence["exposure_reasons"])
		serviceType := evidenceText(f, "type")
		if len(reasons) == 0 || serviceType == "" {
			return nil
		}

		return &FindingExplanation{
			WhyItMatters:         "The service has a configuration that can make it reachable from outside the Kubernetes cluster.",
			TechnicalExplanation: fmt.Sprintf("The collected service configuration is type %s, with exposure indicator(s): %s.", serviceType, strings.Join(reasons, ", ")),
			BusinessImpact:       "If the service is reachable from untrusted networks and lacks appropriate access controls, its application functionality may be exposed to unintended callers. Actual reachability and authorization have not been tested by this finding.",
			ImpactConfidence:     "potential",
			RemediationRationale: "Confirming the intended audience, network restrictions, firewall rules, and authentication controls helps ensure that external access is limited to approved clients.",
		}
	}

	return nil
}

func applyExplanation(f *Finding) {
	if f == nil || f.Explanation != nil {
		return
	}
	f.Explanation = generatedExplanation(*f)
}
