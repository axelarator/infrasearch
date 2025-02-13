package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"infrasearch/vt"
	"log"
	"os"
	"strings"
)

func main() {
	apiKey := os.Getenv("VT_KEY")
	v, err := vt.New(apiKey)
	if err != nil {
		log.Fatal(err)
	}
	if os.Getenv("VT_KEY") == "" && os.Getenv("IPINFO_KEY") == "" {
		_, err := fmt.Fprintln(os.Stderr, "Please set VT_KEY and IPINFO_KEY environment variable")
		if err != nil {
			return
		}
		fmt.Println("export VT_KEY=<VT_KEY>")
		fmt.Println("export IPINFO_KEY=<IPINFO_KEY>")
		return
	}
	var ips []string

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <ip> || <filename.txt>")
		os.Exit(0)
	}
	input := os.Args[1]
	if strings.Contains(input, ".txt") {
		ips, _ = vt.IPFile(input)
	} else {
		ips = []string{input}
	}

	//results := v.BulkSearch(ips)
	finalData := v.BulkSearch(ips)

	// JSON things
	jsonOutput, err := json.MarshalIndent(finalData, "", "  ")
	if err != nil {
		errorJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Println(string(errorJSON))
		return
	}
	fmt.Println(string(jsonOutput))
	writeErr := os.WriteFile("out.json", jsonOutput, 0644)
	if writeErr != nil {
		log.Fatal(writeErr)
	}

	// CSV things
	csvFile, err := os.Create("out.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()
	writer.Write([]string{"Searched IP", "Files Downloaded", "Malicious File Score", "Filename", "Threat Name",
		"Downloaded From", "Malicious IP Score", "Country", "ASN", "Resolved Domain"})

	for _, result := range finalData.IPs {
		for _, download := range result.Hashes {
			for _, itw := range download.IPs {
				writer.Write([]string{
					result.IP,
					download.Hash,
					download.Score,
					download.Name,
					download.SuggestedThreatLabel,
					itw.IPs,
					itw.Score,
					itw.Country,
					itw.ASN,
					strings.Join(itw.ResolvedDomains, ", "),
				})
			}
		}
	}
}

/*
	Some JQ notes
	jq '.[]' out.json : standard JQ output
	jq '[.[].ips] | add' out.json : will flatten the list to just IPs
	jq '[.[].ips] | add | unique' out.json : removes duplicates and sorts
	jq '{(.ips[].ip): [.ips[].downloads[].downloaded_by[].ip] | unique}' out.json: the best output
	jq 'reduce .ips[].downloads[] as $d ({}; .[$d.hash] = [$d.downloaded_by[].ip])' out.json : organize IPs by hashes
*/
