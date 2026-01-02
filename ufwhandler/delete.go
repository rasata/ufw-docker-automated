package ufwhandler

import (
	"bytes"
	"os/exec"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
)

func deleteAllowInRules(container *TrackedContainer, UfwInboundRules *[]UfwRule, IPAddressMap *map[string]string, id string) {
	for _, rule := range *UfwInboundRules {
		for dnetwork, containerIP := range *IPAddressMap {
			cmd := exec.Command("sudo", "ufw", "route", "delete", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", containerIP, "port", rule.Port, "comment", container.Name+":"+id+rule.Comment)
			log.Info().Msg("ufw-docker-automated: Deleting inbound rule (docker network :" + dnetwork + "): " + cmd.String())

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

func deleteAllowOutRules(container *TrackedContainer, UfwOutbound *[]UfwRule, IPAddressMap *map[string]string, id string) {
	for _, rule := range *UfwOutbound {
		for dnetwork, containerIP := range *IPAddressMap {
			var cmd *exec.Cmd
			if rule.Port == "" {
				cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", containerIP, "to", rule.CIDR, "comment", container.Name+":"+id+rule.Comment)
			} else {
				cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", containerIP, "to", rule.CIDR, "port", rule.Port, "comment", container.Name+":"+id+rule.Comment)
			}
			log.Info().Msg("ufw-docker-automated: Deleting outbound rule (docker network :" + dnetwork + "): " + cmd.String())

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

func deleteDenyOutRules(container *TrackedContainer, IPAddressMap *map[string]string, id string) {
	if container.Labels["UFW_DENY_OUT"] == "TRUE" {
		for dnetwork, containerIP := range *IPAddressMap {
			cmd := exec.Command("sudo", "ufw", "route", "delete", "deny", "from", containerIP, "to", "any", "comment", container.Name+":"+id)
			log.Info().Msg("ufw-docker-automated: Deleting outbound rule (docker network :" + dnetwork + "): " + cmd.String())

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

func DeleteUfwRule(containerID <-chan string, c *cache.Cache) {
	for id := range containerID {

		if cachedContainer, found := c.Get(id); found {
			container := cachedContainer.(*TrackedContainer)
			// Handle inbound rules
			// Seperate IPv4 and v6 incase if we ever need to do them diffrently.
			deleteAllowInRules(container, &container.UfwInboundRulesV4, &container.IPAddressMapV4, id)
			deleteAllowInRules(container, &container.UfwInboundRulesV6, &container.IPAddressMapV6, id)
			// Handle outbound rules
			deleteAllowOutRules(container, &container.UfwOutboundRulesV4, &container.IPAddressMapV4, id)
			deleteAllowOutRules(container, &container.UfwOutboundRulesV6, &container.IPAddressMapV6, id)
			// Handle deny all out
			deleteDenyOutRules(container, &container.IPAddressMapV4, id)
			deleteDenyOutRules(container, &container.IPAddressMapV6, id)
		} else {
			log.Warn().Msg("ufw-docker-automated: Container information not found in cache.")
			continue
		}
	}
}
