package vt

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"net/http"
	"os"
	"strings"
)

func rDNS(ip string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ip+".in-addr.arpa."), dns.TypePTR)
	c := new(dns.Client)
	resp, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			domains = append(domains, strings.TrimSuffix(ptr.Ptr, "."))
		}
	}
	return domains, nil
}

func getGeolocation(ip string) (IPDetail, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, os.Getenv("IPINFO_TOKEN"))
	resp, err := http.Get(url)
	if err != nil {
		return IPDetail{}, err
	}
	defer resp.Body.Close()
	var geo IPDetail
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return IPDetail{}, err
	}

	return IPDetail{Country: geo.Country, ASN: geo.ASN}, nil
}

//func reverseIP(ip string) string {
//	parts := strings.Split(ip, ".")
//	if len(parts) != 4 {
//		return ""
//	}
//	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
//
//}
