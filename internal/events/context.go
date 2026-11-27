package events

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// RuntimeContext holds static information collected at startup.
type RuntimeContext struct {
	// Identity
	Hostname         string
	MachineID        string
	ContainerID      string
	ContainerImage   string
	ContainerRuntime string
	K8sNamespace     string
	K8sPod           string
	K8sNode          string
	K8sCluster       string

	// Network
	IPv4Addresses    []string
	IPv6Addresses    []string
	PrimaryInterface string
	MACAddress       string

	// OS
	OS            string
	OSVersion     string
	OSDistro      string
	KernelVersion string
	Arch          string

	// Platform
	PlatformVariant string
	FSBackend       string
	NetBackend      string
	ProcessBackend  string
	IPCBackend      string

	// Version
	AgentshVersion     string
	AgentshCommit      string
	AgentshBuildTime   string
	EventSchemaVersion string
}

// DetectRuntimeContext collects all static context at startup.
func DetectRuntimeContext() *RuntimeContext {
	ctx := &RuntimeContext{
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		EventSchemaVersion: "1.0",
	}

	ctx.Hostname, _ = os.Hostname()
	ctx.MachineID = detectMachineID()
	ctx.ContainerID, ctx.ContainerRuntime = detectContainer()
	ctx.ContainerImage = os.Getenv("AGENTSH_CONTAINER_IMAGE")

	// Kubernetes detection
	ctx.K8sNamespace = os.Getenv("KUBERNETES_NAMESPACE")
	if ctx.K8sNamespace == "" {
		ctx.K8sNamespace = os.Getenv("POD_NAMESPACE")
	}
	ctx.K8sPod = os.Getenv("KUBERNETES_POD_NAME")
	if ctx.K8sPod == "" && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		ctx.K8sPod = os.Getenv("HOSTNAME")
	}
	ctx.K8sNode = os.Getenv("KUBERNETES_NODE_NAME")
	ctx.K8sCluster = os.Getenv("KUBERNETES_CLUSTER_NAME")

	ctx.IPv4Addresses, ctx.IPv6Addresses, ctx.PrimaryInterface, ctx.MACAddress = detectNetworkInfo()
	ctx.OSVersion, ctx.OSDistro = detectOSVersion()
	ctx.KernelVersion = detectKernelVersion()

	return ctx
}

func detectMachineID() string {
	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
		if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func detectContainer() (containerID, runtime string) {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		runtime = "docker"
	}

	// Check cgroup for container ID
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "docker") ||
				strings.Contains(line, "containerd") ||
				strings.Contains(line, "crio") {
				parts := strings.Split(line, "/")
				if len(parts) > 0 {
					containerID = parts[len(parts)-1]
					if len(containerID) >= 12 {
						containerID = containerID[:12]
					}
				}
			}
		}
	}

	if runtime == "" && os.Getenv("CONTAINER_RUNTIME") != "" {
		runtime = os.Getenv("CONTAINER_RUNTIME")
	}

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if runtime == "" {
			runtime = "containerd"
		}
	}

	return
}

func detectNetworkInfo() (ipv4, ipv6 []string, primaryIface, macAddr string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			if ip.To4() != nil {
				ipv4 = append(ipv4, ip.String())
				if primaryIface == "" {
					primaryIface = iface.Name
					macAddr = iface.HardwareAddr.String()
				}
			} else {
				ipv6 = append(ipv6, ip.String())
			}
		}
	}

	return
}

func detectOSVersion() (version, distro string) {
	switch runtime.GOOS {
	case "linux":
		if f, err := os.Open("/etc/os-release"); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					version = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				}
				if strings.HasPrefix(line, "ID=") {
					distro = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
				}
			}
		}
	}
	return
}

func detectKernelVersion() string {
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("uname", "-r").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}
