package ufwhandler

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
)

func checkIP(ip string) (bool, bool) {
	ipParsed := net.ParseIP(ip)
	validIP := ipParsed != nil
	isIPv6 := validIP && ipParsed.To4() == nil
	return net.ParseIP(ip) != nil, isIPv6
}

func checkCIDR(cidr string) (bool, bool) {
	ipParsed, _, err := net.ParseCIDR(cidr)
	validIP := err == nil
	isIPv6 := validIP && ipParsed.To4() == nil
	return err == nil, isIPv6
}

func createAllowInRules(ufwRules *[]UfwRule, containerIPs *map[string]string, containerName string, containerID string) {
	for _, rule := range *ufwRules {
		for dnetwork, containerIP := range *containerIPs {
			// Checking if an IP Exists
			if containerIP == "" {
				continue
			}
			cmd := exec.Command("sudo", "ufw", "route", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", containerIP, "port", rule.Port, "comment", containerName+":"+containerID+rule.Comment)
			log.Info().Msg("ufw-docker-automated: Adding inbound rule (docker network :" + dnetwork + "): " + cmd.String())

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			if err != nil || stderr.String() != "" {
				log.Error().Err(err).Msg("ufw error: " + stderr.String())
			} else {
				log.Info().Msg("ufw: " + stdout.String())
			}
		}
	}
}

func createAllowOutRules(ufwRules *[]UfwRule, containerIPs *map[string]string, containerName string, containerID string) {
	for _, rule := range *ufwRules {
		var cmd *exec.Cmd

		for dnetwork, containerIP := range *containerIPs {
			// Checking if an IP Exists
			if containerIP == "" {
				continue
			}
			if rule.Port == "" {
				cmd = exec.Command("sudo", "ufw", "route", "allow", "from", containerIP, "to", rule.CIDR, "comment", containerName+":"+containerID+rule.Comment)
			} else {
				cmd = exec.Command("sudo", "ufw", "route", "allow", "from", containerIP, "to", rule.CIDR, "port", rule.Port, "comment", containerName+":"+containerID+rule.Comment)
			}
			log.Info().Msg("ufw-docker-automated: Adding outbound rule (docker network :" + dnetwork + "): " + cmd.String())

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			if err != nil || stderr.String() != "" {
				log.Error().Err(err).Msg("ufw error: " + stderr.String())
			} else {
				log.Info().Msg("ufw: " + stdout.String())
			}
		}
	}
}

func createDenyOutRules(containerIPs *map[string]string, containerName string, containerID string) {
	for dnetwork, containerIP := range *containerIPs {
		cmd := exec.Command("sudo", "ufw", "route", "deny", "from", containerIP, "to", "any", "comment", containerName+":"+containerID)
		log.Info().Msg("ufw-docker-automated: Adding outbound rule (docker network :" + dnetwork + "): " + cmd.String())

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()

		if err != nil || stderr.String() != "" {
			log.Error().Err(err).Msg("ufw error: " + stderr.String())
		} else {
			log.Info().Msg("ufw: " + stdout.String())
		}
	}
}

func CreateUfwRule(ch <-chan *types.ContainerJSON, c *cache.Cache) {
	for container := range ch {
		containerName := strings.Replace(container.Name, "/", "", 1) // container name appears with prefix "/"
		containerID := container.ID[:12]
		containerIPv4s := map[string]string{}
		containerIPv6s := map[string]string{}
		// Works for both docker-compose and docker run
		for networkName, network := range container.NetworkSettings.Networks {
			containerIPv4s[networkName] = network.IPAddress
			containerIPv6s[networkName] = network.GlobalIPv6Address
		}

		if len(containerIPv4s) == 0 && len(containerIPv6s) == 0 {
			log.Error().Msg("ufw-docker-automated: Couldn't detect the container IP address.")
			continue
		}

		cachedContainer := TrackedContainer{
			Name:           containerName,
			IPAddressMapV4: containerIPv4s,
			IPAddressMapV6: containerIPv6s,
			Labels:         container.Config.Labels,
		}

		c.Set(containerID, &cachedContainer, cache.NoExpiration)

		// Handle inbound rules
		for port, portMaps := range container.HostConfig.PortBindings {

			// List is non empty if port is published
			if len(portMaps) > 0 {
				ufwRulesV4 := []UfwRule{}
				ufwRulesV6 := []UfwRule{}
				if container.Config.Labels["UFW_ALLOW_FROM"] != "" {
					ufwAllowFromLabelParsed := strings.Split(container.Config.Labels["UFW_ALLOW_FROM"], ";")

					for _, allowFrom := range ufwAllowFromLabelParsed {
						ip := strings.Split(allowFrom, "-")

						// First element should be always valid IP Address or CIDR
						validIP, isIPv6 := checkIP(ip[0])
						if !validIP {
							validIP, isIPv6 = checkCIDR(ip[0])
							if !validIP {
								log.Printf("ufw-docker-automated: Address %s is not valid!\n", ip[0])
								continue
							}
						}
						var ufwRuleToUse *[]UfwRule
						if isIPv6 {
							ufwRuleToUse = &ufwRulesV6
						} else {
							ufwRuleToUse = &ufwRulesV4
						}

						// Example: 172.10.5.0-LAN or 172.10.5.0-80
						//          fe80::1-Lan or fe80::1-80
						if len(ip) == 2 {
							if _, err := strconv.Atoi(ip[1]); err == nil {
								// case: 172.10.5.0-80
								// case: fe80::1-80
								*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Port: ip[1], Proto: port.Proto()})
							} else {
								// case: 172.10.5.0-LAN
								// case: fe80::1-Lan
								*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Port: port.Port(), Proto: port.Proto(), Comment: fmt.Sprintf(" %s", ip[1])})
							}
							// Example: 172.10.5.0-80-LAN
							// Example: fe80::1-80-Lan
						} else if len(ip) == 3 {
							*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Port: ip[1], Proto: port.Proto(), Comment: fmt.Sprintf(" %s", ip[2])})
						} else {
							// Example: 172.10.5.0
							// Example: fe80::1-80
							*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Port: port.Port(), Proto: port.Proto()})
						}
					}
				} else {
					ufwRulesV4 = append(ufwRulesV4, UfwRule{CIDR: "any", Port: port.Port(), Proto: port.Proto()})
					ufwRulesV6 = append(ufwRulesV6, UfwRule{CIDR: "any", Port: port.Port(), Proto: port.Proto()})
				}

				// Seperate IPv4 and v6 incase if we ever need to do them diffrently.
				createAllowInRules(&ufwRulesV4, &containerIPv4s, containerName, containerID)
				createAllowInRules(&ufwRulesV6, &containerIPv6s, containerName, containerID)

				// Seperate rules for deleting later.
				cachedContainer.UfwInboundRulesV4 = append(cachedContainer.UfwInboundRulesV4, ufwRulesV4...)
				cachedContainer.UfwInboundRulesV6 = append(cachedContainer.UfwInboundRulesV6, ufwRulesV6...)
				// ufw route allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
				// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
			}
		}

		// Handle outbound rules
		if container.Config.Labels["UFW_DENY_OUT"] == "TRUE" {

			if container.Config.Labels["UFW_ALLOW_TO"] != "" {
				ufwRulesV4 := []UfwRule{}
				ufwRulesV6 := []UfwRule{}
				ufwAllowToLabelParsed := strings.Split(container.Config.Labels["UFW_ALLOW_TO"], ";")

				for _, allowTo := range ufwAllowToLabelParsed {
					ip := strings.Split(allowTo, "-")

					// First element should be always valid IP Address or CIDR
					validIP, isIPv6 := checkIP(ip[0])
					if !validIP {
						validIP, isIPv6 = checkCIDR(ip[0])
						if !validIP {
							log.Printf("ufw-docker-automated: Address %s is not valid!\n", ip[0])
							continue
						}
					}
					var ufwRuleToUse *[]UfwRule
					if isIPv6 {
						ufwRuleToUse = &ufwRulesV6
					} else {
						ufwRuleToUse = &ufwRulesV4
					}

					// Example: 172.10.5.0-LAN or 172.10.5.0-80
					//          fe80::1-Lan or fe80::1-80
					if len(ip) == 2 {
						if _, err := strconv.Atoi(ip[1]); err == nil {
							// case: 172.10.5.0-80
							// case: fe80::1-80
							*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Port: ip[1]})
						} else {
							// case: 172.10.5.0-LAN
							// case: fe80::1-LAN
							*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Comment: fmt.Sprintf(" %s", ip[1])})
						}
						// Example: 172.10.5.0-80-LAN
						// Example: fe80::1-80-Lan
					} else if len(ip) == 3 {
						*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0], Port: ip[1], Comment: fmt.Sprintf(" %s", ip[2])})
					} else {
						// Example: 172.10.5.0
						// Example: fe80::1
						*ufwRuleToUse = append(*ufwRuleToUse, UfwRule{CIDR: ip[0]})
					}
				}

				// Seperate IPv4 and v6 incase if we ever need to do them diffrently.
				createAllowOutRules(&ufwRulesV4, &containerIPv4s, containerName, containerID)
				createAllowOutRules(&ufwRulesV6, &containerIPv6s, containerName, containerID)

				// Seperate rules for deleting later.
				cachedContainer.UfwOutboundRulesV4 = append(cachedContainer.UfwOutboundRulesV4, ufwRulesV4...)
				cachedContainer.UfwOutboundRulesV6 = append(cachedContainer.UfwOutboundRulesV6, ufwRulesV6...)
			}

			// Handle deny all out
			createDenyOutRules(&containerIPv4s, containerName, containerID)
			createDenyOutRules(&containerIPv6s, containerName, containerID)
		}
	}
}
