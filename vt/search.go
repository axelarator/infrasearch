package vt

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

func (s *Client) HostSearch(q string) (IPData, error) {

	url := fmt.Sprintf("%s/ip_addresses/%s/downloaded_files?limit=10", BaseUrl, q)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", os.Getenv("VT_KEY"))

	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()

	var ret HostSearch
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil || len(ret.Data) == 0 {
		return IPData{NoData: "No downloaded files found"}, nil
	}

	//hashToIPs := IPData{Hashes: make(map[string]HashInfo)}
	var downloads []HashInfo
	var ipDetails []IPDetail

	for _, value := range ret.Data {
		sha256 := value.Attributes.Sha256
		threatLabel := value.Attributes.PopularThreatClassification.SuggestedThreatLabel
		name := ""
		if len(value.Attributes.Names) > 0 {
			name = value.Attributes.Names[0]
		}
		analysisCount := value.Attributes.LastAnalysisStats.Malicious + value.Attributes.LastAnalysisStats.Undetected
		maliciousScore := fmt.Sprintf("%v / %v", value.Attributes.LastAnalysisStats.Malicious, analysisCount)

		ips, err := s.HashSearch(sha256)
		if err != nil {
			continue
		}
		// rDNS lookups to enrich IPs

		for _, ip := range ips {
			domains, _ := rDNS(ip)
			geoInfo, _ := getGeolocation(ip)

			ipDetails = append(ipDetails, IPDetail{
				IPs:             ip,
				ResolvedDomains: domains,
				Country:         geoInfo.Country,
				ASN:             geoInfo.ASN,
			})
		}

		downloads = append(downloads, HashInfo{
			Hash:                 sha256,
			Score:                maliciousScore,
			Name:                 name,
			SuggestedThreatLabel: threatLabel,
			IPs:                  ipDetails,
		})
	}

	return IPData{IP: q, Hashes: downloads}, nil
}

// next part is for downloaded files > ITW IPs

func (s *Client) HashSearch(h string) ([]string, error) {
	url := fmt.Sprintf("%s/files/%s/itw_ips?limit=10", BaseUrl, h)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", os.Getenv("VT_KEY"))

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()

	var ret HashSearch
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	var ips []string
	for _, value := range ret.Data {
		ips = append(ips, value.Id)
	}
	return ips, nil
}

// IPFile reads through a file to assign ips to a slice
func IPFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

func (s *Client) BulkSearch(ips []string) TopLevel {
	var wg sync.WaitGroup
	resultChan := make(chan IPData, len(ips))
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			data, err := s.HostSearch(ip)
			if err != nil {
				data = IPData{NoData: "Error retrieving data"}
			}
			resultChan <- data
		}(ip)
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	var results []IPData
	for result := range resultChan {
		results = append(results, result)
	}
	//printCorrelation(results)
	return TopLevel{IPs: results}

}

// This is for a customized output taking specific parts from the JSON output

func printCorrelation(results []IPData) {
	ipSet := make(map[string]struct{})
	for _, data := range results {
		ipSet[data.IP] = struct{}{}
	}

	for _, data := range results {
		for _, download := range data.Hashes {
			for _, downloader := range download.IPs {
				fmt.Printf("%s has correlation with %s\n", data.IP, downloader.IPs)
			}
		}
	}
}
