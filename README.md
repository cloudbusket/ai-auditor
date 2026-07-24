# ai-auditor
AI audit of Cloud Infrstructures

# CloudBusket AI Auditor

**CloudBusket AI Auditor** is an enterprise infrastructure auditing framework written in Go.

It collects detailed inventory from Linux hosts, cloud platforms, Docker, Kubernetes and infrastructure services to build a complete picture of a system before performing security, compliance and optimization analysis.

The project is designed to become an AI-powered Infrastructure Assessment Engine capable of identifying operational issues, security risks, performance bottlenecks and cloud cost optimization opportunities.

---

# Features

## Host Inventory

Collects detailed operating system information including

* Hostname
* Linux Distribution
* Kernel Version
* CPU Information
* Memory
* Disk Inventory
* Network Interfaces
* Virtualization
* Running Services
* System Metadata

---

## Cloud Inventory

Automatically detects cloud provider.

Current support

* Google Cloud Platform
* AWS (planned)
* Microsoft Azure (planned)

Collected information includes

* Project / Subscription
* Instance Name
* Instance ID
* Region
* Zone
* Machine Type
* Internal IP
* External IP
* Service Account
* Labels
* Tags

---

## Docker Inventory

Collects Docker daemon information including

* Docker Version
* API Version
* Engine Information
* Containers
* Images
* Networks
* Volumes

Upcoming improvements

* Container CPU Usage
* Memory Usage
* Restart Count
* Mounted Volumes
* Exposed Ports
* Health Status
* Image Size
* Dangling Images
* Network Utilization
* Volume Usage

---

## Kubernetes Inventory (In Progress)

Planned inventory

* Cluster Information
* Nodes
* Pods
* Deployments
* StatefulSets
* DaemonSets
* Services
* Ingress
* Persistent Volumes
* Persistent Volume Claims
* Storage Classes
* Namespaces

---

## Future AI Engine

The inventory engine will become the data source for an AI Infrastructure Auditor capable of

* Infrastructure Health Assessment
* DevOps Best Practice Validation
* Security Auditing
* CIS Benchmark Validation
* Kubernetes Best Practices
* Docker Hardening
* Cloud Architecture Review
* Cloud Cost Optimization
* AI Generated Recommendations
* Automated Postmortem Assistance
* Root Cause Analysis

---

# Project Structure

```
audit-engine/

cmd/
    inventory.go
    host.go
    cloud.go
    docker.go
    services.go

internal/

    inventory/
        host collectors

    cloud/
        cloud metadata collectors

    docker/
        docker inventory

    kubernetes/
        kubernetes inventory

    scanner/
        future security scanners

    reporters/
        report generation

    plugins/
        custom plugins
```

---

# Current Commands

## Full Inventory

```bash
auditor inventory
```

Returns

* Host
* Cloud
* Docker
* Services

---

## Host

```bash
auditor host
```

Returns

* OS
* CPU
* Memory
* Kernel
* Disk
* Network
* Services

---

## Cloud

```bash
auditor cloud
```

Returns cloud metadata only.

---

## Docker

```bash
auditor docker
```

Returns Docker inventory.

---

## Services

```bash
auditor services
```

Lists all running systemd services.

---

# Building

```bash
git clone https://github.com/cloudbusket/ai-auditor.git

cd audit-engine

go mod tidy

go build -o bin/auditor .
```

Run

```bash
./bin/auditor inventory
```

---

# Roadmap

## Phase 1

* ✅ Host Inventory
* ✅ Cloud Metadata
* ✅ Docker Version
* ✅ Running Services

---

## Phase 2

* Docker Runtime Inventory
* Kubernetes Inventory
* Cloud Resource Inventory
* Process Inventory

---

## Phase 3

Infrastructure Checks

* Disk Usage
* CPU Utilization
* Memory Utilization
* Network Health
* Service Health
* Docker Health
* Kubernetes Health

---

## Phase 4

Security Auditing

* CIS Linux
* Docker Bench
* Kubernetes Bench
* SSH Hardening
* Firewall Validation
* Package Vulnerabilities

---

## Phase 5

AI Infrastructure Auditor

Natural language infrastructure analysis.

Examples

> Why is this server slow?

> Why is disk usage 98%?

> Why are containers restarting?

> Is my Kubernetes cluster secure?

> Suggest cloud cost optimization.

---

# Long Term Vision

CloudBusket AI Auditor aims to become a complete AI-powered infrastructure auditing platform capable of replacing multiple traditional infrastructure assessment tools by combining inventory collection, security auditing, DevOps best practices, cloud optimization and large language model reasoning into a single platform.

---

# License

MIT License

