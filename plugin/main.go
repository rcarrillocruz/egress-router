package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

type ClusterConf struct {
	CloudProvider string `json:"cloudProvider"`
}

type NetConf struct {
	types.NetConf

	InterfaceType string            `json:"interfaceType"`
	InterfaceArgs map[string]string `json:"interfaceArgs"`

	IP       *IP           `json:"ip"`
	PodIP    map[string]IP `json:"podIP"`
	IPConfig *IPConfig     `json:"ipConfig"`
}

type IP struct {
	Addresses    []string `json:"addresses"`
	Gateway      string   `json:"gateway"`
	Destinations []string `json:"destinations"`
}

type IPConfig struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Overrides *IP    `json:"overrides"`
}

func loadNetConf(cluster *ClusterConf, bytes []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	if err := fillNetConfDefaults(conf, cluster); err != nil {
		return nil, err
	}
	if err := validateNetConf(conf); err != nil {
		return nil, err
	}

	return conf, nil
}

func fillNetConfDefaults(conf *NetConf, cluster *ClusterConf) error {
	if conf.InterfaceType == "" {
		if cluster.CloudProvider == "" {
			conf.InterfaceType = "macvlan"
		} else {
			return fmt.Errorf("must specify explicit interfaceType for cloud provider %q", cluster.CloudProvider)
		}
	}

	switch conf.InterfaceType {
	case "macvlan":
		for key, value := range conf.InterfaceArgs {
			if key == "master" || key == "mode" {
				continue
			} else {
				return fmt.Errorf("unrecognized interfaceArgs value %q for interfaceType %q", key, conf.InterfaceType)
			}
		}
	case "ipvlan":
		for key, value := range conf.InterfaceArgs {
			if key == "master" {
				continue
			} else {
				return fmt.Errorf("unrecognized interfaceArgs value %q for interfaceType %q", key, conf.InterfaceType)
			}
		}
	default:
		return fmt.Errorf("unrecognized interfaceType %q", conf.InterfaceType)
	}

	return nil
}

func validateNetConf(conf *NetConf) error {
	if conf.IP == nil && conf.PodIP == nil && conf.IPConfig == nil {
		return fmt.Errorf("exactly 1 of 'ip', 'podIP', or 'ipConfig' must be set")
	}

	if conf.IPConfig != nil {
		if conf.IP != nil || conf.PodIP != nil {
			return fmt.Errorf("exactly 1 of 'ip', 'podIP', or 'ipConfig' must be set")
		}
		var err error
		conf.IP, conf.PodIP, err = loadIPConfig(conf.IPConfig)
		if err != nil {
			return err
		}
	}
	if conf.PodIP != nil {
		if conf.IP != nil {
			return fmt.Errorf("exactly 1 of 'ip', 'podIP', or 'ipConfig' must be set")
		}
		for podName, ipc := range conf.PodIP {
			if podNameMatches(podName, FIXME_THIS_POD_NAME) {
				if conf.IP != nil {
					return fmt.Errorf("multiple configurations in 'podIP' matching pod name %q", FIXME_THIS_POD_NAME)
				}
				conf.IP = &ipc
			}
		}
		if conf.IP == nil {
			return fmt.Errorf("no configuration in 'podIP' matching pod name %q", FIXME_THIS_POD_NAME)
		}
	}
	if err := validateIP(conf.IP); err != nil {
		return err
	}

	return nil
}

func validateIP(ip *IP) error {
	if len(ip.Addresses) == 0 {
		return fmt.Errorf("must specify at least one IP address")
	}
	var got4, got6 bool
	for _, addr := range ip.Addresses {
		var ipaddr *net.IP
		_, net, err := net.ParseCIDR(addr)
		if err == nil {
			ipaddr = &net.IP
		} else {
			ipaddr = net.ParseIP(addr)
		}
		if ipaddr == nil {
			return fmt.Errorf("%q is not a valid IP address", addr)
		}
		if ipaddr.To4() != nil {
			got4 = true
		} else {
			got6 = true
		}
	}
	if ip.Gateway != "" {
		gw := net.ParseIP(ip.Gateway)
		if gw == nil {
			return fmt.Errorf("%q is not a valid IP address", ip.Gateway)
		}
		if gw.To4() != nil {
			if !got4 {
				return fmt.Errorf("gateway %q is IPv4 but no IPv4 addresess configured", ip.Gateway)
			}
		} else {
			if !got6 {
				return fmt.Errorf("gateway %q is IPv6 but no IPv6 addresess configured", ip.Gateway)
			}
		}
	}
	for _, cidr := range ip.Destinations {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%q is not a valid CIDR block", cidr)
		}
	}

	return nil
}

func loadIPConfig(ipc *IPConfig) (*IP, map[string]IP, error) {
	if ipc.Namespace == "" {
		ipc.Namespace = FIXME_POD_NAMESPACE
	}

	cm := FIXME_GET_CONFIG_MAP

	if cm.Data["ip"] != "" {
		if cm.Data["podIP"] != "" {
			return nil, nil, fmt.Errorf("ConfigMap %s/%s contains both 'ip' and 'podIP'", ipc.Namespace, ipc.Name)
		}
		ip := &IP{}
		if err := json.Unmarshal([]byte(cm.Data["ip"]), ip); err != nil {
			return nil, nil, fmt.Errorf("failed to parse 'ip' in ConfigMap %s/%s: %v", ipc.Namespace, ipc.Name, err)
		}
		return ip, nil, nil
	} else if cm.Data["podIP"] != "" {
		podIP := map[string]IP{}
		if err := json.Unmarshal([]byte(cm.Data["podIP"]), podIP); err != nil {
			return nil, nil, fmt.Errorf("failed to parse 'podIP' in ConfigMap %s/%s: %v", ipc.Namespace, ipc.Name, err)
		}
		return nil, podIP, nil
	} else {
		return nil, nil, fmt.Errorf("ConfigMap %s/%s contains neither 'ip' nor 'podIP'", ipc.Namespace, ipc.Name)
	}
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "FIXME about/version string")
}

func cmdCheck(args *skel.CmdArgs) error {
	ipamConf, _, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Get PrevResult from stdin... store in RawPrevResult
	n, err := loadNetConf(&ClusterConf{}, args.StdinData)
	if err != nil {
		return err
	}

	// Parse previous result.
	if n.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(n); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	// Each configured IP should be found in result.IPs
	for _, rangeset := range ipamConf.Addresses {
		for _, ips := range result.IPs {
			// Ensure values are what we expect
			if rangeset.Address.IP.Equal(ips.Address.IP) {
				if rangeset.Gateway == nil {
					break
				} else if rangeset.Gateway.Equal(ips.Gateway) {
					break
				}
				return fmt.Errorf("static: Failed to match addr %v on interface %v", ips.Address.IP, args.IfName)
			}
		}
	}

	return nil
}

// canonicalizeIP makes sure a provided ip is in standard form
func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

// LoadIPAMConfig creates IPAMConfig using json encoded configuration provided
// as `bytes`. At the moment values provided in envArgs are ignored so there
// is no possibility to overload the json configuration using envArgs
func LoadIPAMConfig(bytes []byte, envArgs string) (*IPAMConfig, string, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", err
	}

	if n.IPAM == nil {
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// Validate all ranges
	numV4 := 0
	numV6 := 0

	for i := range n.IPAM.Addresses {
		ip, addr, err := net.ParseCIDR(n.IPAM.Addresses[i].AddressStr)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CIDR %s: %s", n.IPAM.Addresses[i].AddressStr, err)
		}
		n.IPAM.Addresses[i].Address = *addr
		n.IPAM.Addresses[i].Address.IP = ip

		if err := canonicalizeIP(&n.IPAM.Addresses[i].Address.IP); err != nil {
			return nil, "", fmt.Errorf("invalid address %d: %s", i, err)
		}

		if n.IPAM.Addresses[i].Address.IP.To4() != nil {
			n.IPAM.Addresses[i].Version = "4"
			numV4++
		} else {
			n.IPAM.Addresses[i].Version = "6"
			numV6++
		}
	}

	if envArgs != "" {
		e := IPAMEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, "", err
		}

		if e.IP != "" {
			for _, item := range strings.Split(string(e.IP), ",") {
				ipstr := strings.TrimSpace(item)

				ip, subnet, err := net.ParseCIDR(ipstr)
				if err != nil {
					return nil, "", fmt.Errorf("invalid CIDR %s: %s", ipstr, err)
				}

				addr := Address{Address: net.IPNet{IP: ip, Mask: subnet.Mask}}
				if addr.Address.IP.To4() != nil {
					addr.Version = "4"
					numV4++
				} else {
					addr.Version = "6"
					numV6++
				}
				n.IPAM.Addresses = append(n.IPAM.Addresses, addr)
			}
		}

		if e.GATEWAY != "" {
			for _, item := range strings.Split(string(e.GATEWAY), ",") {
				gwip := net.ParseIP(strings.TrimSpace(item))
				if gwip == nil {
					return nil, "", fmt.Errorf("invalid gateway address: %s", item)
				}

				for i := range n.IPAM.Addresses {
					if n.IPAM.Addresses[i].Address.Contains(gwip) {
						n.IPAM.Addresses[i].Gateway = gwip
					}
				}
			}
		}
	}

	// CNI spec 0.2.0 and below supported only one v4 and v6 address
	if numV4 > 1 || numV6 > 1 {
		for _, v := range types020.SupportedVersions {
			if n.CNIVersion == v {
				return nil, "", fmt.Errorf("CNI version %v does not support more than 1 address per family", n.CNIVersion)
			}
		}
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, n.CNIVersion, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	ipamConf, confVersion, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	result := &current.Result{}
	result.DNS = ipamConf.DNS
	result.Routes = ipamConf.Routes
	for _, v := range ipamConf.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Version: v.Version,
			Address: v.Address,
			Gateway: v.Gateway})
	}

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Nothing required because of no resource allocation in static plugin.
	return nil
}
