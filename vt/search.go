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
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return IPData{IP: q, Hashes: []HashInfo{}}, nil
	}
	if len(ret.Data) == 0 {
		return IPData{IP: q, Hashes: []HashInfo{}}, nil
	}
	var downloads []HashInfo

	for _, value := range ret.Data {
		sha256 := value.Attributes.Sha256
		filename := ""
		if len(value.Attributes.Names) > 0 {
			filename = value.Attributes.Names[0]
		}
		threatLabel := value.Attributes.PopularThreatClassification.SuggestedThreatLabel
		analysisCount := value.Attributes.LastAnalysisStats.Malicious + value.Attributes.LastAnalysisStats.Undetected
		maliciousScore := fmt.Sprintf("%v / %v", value.Attributes.LastAnalysisStats.Malicious, analysisCount)
		ips, scores, err := s.HashSearch(sha256)
		if err != nil {
			continue
		}
		var downloadedBy []DownloadedIP
		for i, ip := range ips {
			domains, _ := rDNS(ip)
			geoInfo, _ := getGeolocation(ip)
			downloadedBy = append(downloadedBy, DownloadedIP{
				IPs:             ip,
				Score:           scores[i],
				ResolvedDomains: domains,
				Country:         geoInfo.Country,
				ASN:             geoInfo.ASN,
			})
		}

		downloads = append(downloads, HashInfo{
			Hash:                 sha256,
			Score:                maliciousScore,
			Name:                 filename,
			SuggestedThreatLabel: threatLabel,
			IPs:                  downloadedBy,
		})
	}
	return IPData{IP: q, Hashes: downloads}, nil
}

// next part is for downloaded files > ITW IPs

func (s *Client) HashSearch(h string) ([]string, []string, error) {
	url := fmt.Sprintf("%s/files/%s/itw_ips?limit=10", BaseUrl, h)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", os.Getenv("VT_KEY"))

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()

	var ret HashSearch
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, nil, err
	}
	var ips []string
	var scores []string
	for _, value := range ret.Data {
		ips = append(ips, value.Id)
		// same logic to calculate malicious score for hashes
		analysisCount := value.Attributes.LastAnalysisStats.Malicious + value.Attributes.LastAnalysisStats.Suspicious +
			value.Attributes.LastAnalysisStats.Undetected + value.Attributes.LastAnalysisStats.Harmless
		maliciousScore := fmt.Sprintf("%v / %v", value.Attributes.LastAnalysisStats.Malicious, analysisCount)
		scores = append(scores, maliciousScore)

	}
	return ips, scores, nil
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

func (s *Client) BulkSearch(ips []string) FinalOutput {
	var wg sync.WaitGroup
	results := FinalOutput{IPs: []IPData{}}
	resultChan := make(chan IPData, len(ips))
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			data, _ := s.HostSearch(ip)
			resultChan <- data
		}(ip)
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	for result := range resultChan {
		results.IPs = append(results.IPs, result)
	}

	results.Overlaps = detectOverlaps(results)

	return results
}

func detectOverlaps(results FinalOutput) OverlapAnalysis {
	// final storage for output
	sharedHashes := make(map[string][]string)
	sharedDownloaded := make(map[string][]string)
	// temp output in for loops
	hashToIPs := make(map[string][]string)
	itwIPToHashes := make(map[string][]string)
	// loop through finaloutput
	for _, result := range results.IPs {
		// loop through found hashes
		for _, download := range result.Hashes {
			// each hash is a key, the value is the searched IP
			hashToIPs[download.Hash] = append(hashToIPs[download.Hash], result.IP)
			// now loop through all downloaded_by IPs
			for _, itw := range download.IPs {
				// each downloaded_by IP is a key, the vaue is the hash
				itwIPToHashes[itw.IPs] = append(itwIPToHashes[itw.IPs], download.Hash)
			}
		}
	}

	for hash, ipList := range hashToIPs {
		// looking for duplicates so there needs to be more than 1
		if len(ipList) > 1 {
			// hash gets mapped to the searched IP
			sharedHashes[hash] = ipList
		}
	}

	for ip, hashList := range itwIPToHashes {
		// if an ITW IP lists more than one hash, add to the slice
		if len(hashList) > 1 {
			sharedDownloaded[ip] = hashList
		}
	}

	return OverlapAnalysis{
		SharedHashes:     sharedHashes,
		SharedDownloaded: sharedDownloaded,
	}

}
