# infrasearch
infrasearch is a way to search for IPs and potentially uncover related IPs whether they're in the same network range or separate.
By searching an IP in VirusTotal, occassionaly there are downloaded hashes if it's known to distribute malware. Taking those hashes and pivoting on In The Wild (ITW) IPs can uncover additional hosts who were seen downloading that same malware. 

Using the transitive property of these three values, a confident (albeit false positive prone) assessment can be made that "List of IPs" have similarities with "ITW IPs" and can be used to uncover additional infrastructure not yet observed.

`List of IPs -> downloaded malware <-> ITW IPs`

# Prerequisites
- Go version <= 1.23.6 if not using a compiled release.
- A VirusTotal Enterprise account is *required*
- IPInfo account (free tier is fine)
These are read as environment variables so set them before running
## VirusTotal Enterprise API Key
MacOS/Linux

`export VT_KEY=<VT_KEY>`

Windows

`set VT_KEY=<VT_KEY>`

## IPInfo API Key
MacOS/Linux

`export IPINFO_KEY=<IPINFO_KEY>`

Windows

`set IPINFO_KEY=<IPINFO_KEY>`

## Some JQ notes
This will organize the output to quickly view SHA256 hashes and IPs that were also seeing downloading this hash.

`jq 'reduce .ips[].downloads[] as $d ({}; .[$d.hash] = [$d.downloaded_by[].ip])' out.json`
```json
{
  "87effdf835590f85db589768b14adae2f76b59b2f33fae0300aef50575e6340d": [
    [
      "46.246.6.15",
      "46.246.82.6",
      "46.246.86.4"
    ]
  ],
  "59ac44a6fa99c427a34c311b0bca3829c0851489f12c6c7c5eee5a8754b5c811": [
    [
      "46.246.6.15",
      "46.246.82.6",
      ...
    ]
  ]
}
```
This will organize the output so it shows the searched IP and possibly related IPs 

`jq '{(.ips[].ip): [.ips[].downloads[].downloaded_by[].ip] | unique}' out.json`
```json
{
  "46.246.82.6": [
    "1.0.64.137",
    "1.11.70.16",
    ...
  ]
}
```

# Getting Started
You can clone this repo and execute main without having to build it yourself. 
Either provide a single IP or a TXT file with one IP per line.
```
git clone https://github.com/axelarator/infrasearch && cd infrasearch
go run main.go <ip>
go run main.go <file.txt>
```
