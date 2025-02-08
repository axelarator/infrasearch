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
		ips, err := s.HashSearch(sha256)
		if err != nil {
			continue
		}
		var downloadedBy []DownloadedIP
		for _, ip := range ips {
			domains, _ := rDNS(ip)
			geoInfo, _ := getGeolocation(ip)
			downloadedBy = append(downloadedBy, DownloadedIP{
				IPs:             ip,
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

func (s *Client) BulkSearch(ips []string) FinalOutput {
	var wg sync.WaitGroup
	results := FinalOutput{IPs: []IPData{}}
	resultChan := make(chan IPData, len(ips))
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			data, _ := s.HostSearch(ip)
			//if err != nil {
			//	data = IPData{NoData: "Error retrieving data"}
			//}
			resultChan <- data
		}(ip)
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	//var results []IPData
	for result := range resultChan {
		results.IPs = append(results.IPs, result)
	}
	//printCorrelation(results)
	return results

}

//func (s *Client) BuildFinalOutput(inputIPs []string) (FinalOutput, error) {
//	var finalData FinalOutput
//	finalData.IPs = make([]IPData, 0)
//
//	for _, ip := range inputIPs {
//		ipEntry := IPData{
//			IP:     ip,
//			Hashes: make([]HashInfo, 0),
//		}
//		hostData, err := s.HostSearch(ip)
//		if err != nil {
//			fmt.Printf("Error retrieving host data for ip %s: %v", ip, err)
//			finalData.IPs = append(finalData.IPs, ipEntry)
//			continue
//		}
//		//if hostData == nil {
//		//	continue
//		//}
//		//if len(hostData.Data) == 0 {
//		//	finalData.IPs = append(finalData.IPs, ipEntry)
//		//	continue
//		//}
//
//		for _, file := range hostData.Data {
//			attr := file.Attributes
//			hash := attr.Sha256
//			score := attr.LastAnalysisStats
//			total := score.Harmless + score.Malicious + score.Suspicious + score.Timeout + score.Undetected
//			//if total > 0 {
//			//	scoreStr = fmt.Sprintf("%d / %d", score.Malicious+score.Suspicious, total)
//			//} else {
//			//	scoreStr = "0 / 0"
//			//}
//			scoreStr := fmt.Sprintf("%d / %d", score.Malicious+score.Suspicious, total)
//
//			filename := ""
//			if len(attr.Names) > 0 {
//				filename = attr.Names[0]
//			}
//			threatName := attr.PopularThreatClassification.SuggestedThreatLabel
//
//			hashResult, err := s.HashSearch(hash)
//			if err != nil {
//				fmt.Printf("Error retrieving hash for ip %s: %v", ip, err)
//				continue
//			}
//			downloadedBy := make([]DownloadedIP, 0)
//			// Use this if duplicates appear
//			//downloadedBy := make([]DownloadedIP, 0)
//			//seenIPs := make(map[string]bool)
//
//			for _, itwIP := range hashResult.Data {
//				//if seenIPs[itwIP.Id] {
//				//	continue
//				//}
//				geo, geoErr := getGeolocation(itwIP.Id)
//				rdns, _ := rDNS(itwIP.Id)
//				if geoErr != nil {
//					downloadedBy = append(downloadedBy, DownloadedIP{
//						IPs: itwIP.Id,
//						//ResolvedDomains: []string{},
//						//Country:         "",
//						//ASN:             "",
//					})
//				} else {
//					downloadedBy = append(downloadedBy, DownloadedIP{
//						IPs:             itwIP.Id,
//						ResolvedDomains: rdns,
//						Country:         geo.Country,
//						ASN:             geo.ASN,
//					})
//				}
//			}
//			downloadEntry := HashInfo{
//				Hash:                 hash,
//				Score:                scoreStr,
//				Name:                 filename,
//				SuggestedThreatLabel: threatName,
//				IPs:                  downloadedBy,
//			}
//			ipEntry.Hashes = append(ipEntry.Hashes, downloadEntry)
//		}
//		finalData.IPs = append(finalData.IPs, ipEntry)
//	}
//	return finalData, nil
//}
