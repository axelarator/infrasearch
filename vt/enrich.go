package vt

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"net/http"
	"os"
	"strings"
)

func getGeolocation(ip string) (DownloadedIP, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, os.Getenv("IPINFO_TOKEN"))
	resp, err := http.Get(url)
	if err != nil {
		return DownloadedIP{}, err
	}
	defer resp.Body.Close()
	var geo DownloadedIP
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return DownloadedIP{}, err
	}
	return DownloadedIP{Country: geo.Country, ASN: geo.ASN}, nil

}

func rDNS(ip string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ip+".in-addr.arpa."), dns.TypePTR)
	c := new(dns.Client)
	resp, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	domains := make([]string, 0)
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			domains = append(domains, strings.TrimSuffix(ptr.Ptr, "."))
		}
	}
	return domains, nil
}
