package ufwhandler

type TrackedContainer struct {
	Name               string
	IPAddressMapV4     map[string]string
	IPAddressMapV6     map[string]string
	Labels             map[string]string
	UfwInboundRulesV4  []UfwRule
	UfwInboundRulesV6  []UfwRule
	UfwOutboundRulesV4 []UfwRule
	UfwOutboundRulesV6 []UfwRule
}

type UfwRule struct {
	CIDR    string
	Port    string
	Proto   string
	Comment string
}
