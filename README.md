# infrasearch
infrasearch searches for IPs and attempts to uncover related IPs from VirusTotal using a correlation between downloaded files and in the wild (ITW) IPs. 
By searching an IP in VirusTotal, there exists a subset of data called "Downloaded Files" which show files downlaoded from that IP. 
Taking those hashes and pivoting on ITW IPs can uncover additional hosts who were seen downloading that same malware. 

Using the transitive property of these three values, a confident (albeit false positive prone) assessment can be made 
that "List of IPs" have similarities with "ITW IPs" and can be used to uncover additional infrastructure not yet observed.

`List of IPs -> Downloaded Files <-> ITW IPs`

# Prerequisites
- Go version <= 1.23.6 if not using a compiled release. 
  - [Download](https://go.dev/dl/)
- A VirusTotal Enterprise account is *required*
- IPInfo account (free tier is fine)
  - [IPInfo](https://ipinfo.io/)

## API Keys
These are read as environment variables so set them before running
### VirusTotal Enterprise API Key
MacOS/Linux

`export VT_KEY=<VT_KEY>`

Windows

`set VT_KEY=<VT_KEY>`

### IPInfo API Key
MacOS/Linux

`export IPINFO_KEY=<IPINFO_KEY>`

Windows

`set IPINFO_KEY=<IPINFO_KEY>`

# Getting Started
You can clone this repo and execute main without having to build it yourself. This requires Golang to be installed

Either provide a single IP or a TXT file with one IP per line.
```
git clone https://github.com/axelarator/infrasearch && cd infrasearch
go run main.go <ip>
go run main.go <file.txt>
```
The recommended approach is to download a binary from the [Releases](https://github.com/axelarator/infrasearch/releases/tag/v1.0.0) section
```
./infrasearch <ip>
./infrasearch <file.txt>
```

The output is printed along with creating an `out.json` and `out.csv` file in the directory in which it was run.

From there, the output can be parsed using `jq`. Below are some more complex queries to make sense of the data. 

## Some JQ notes
This will organize the output to quickly view SHA256 hashes and IPs that were also seeing downloading this hash.

`jq 'reduce .ips[].downloads[] as $d ({}; .[$d.hash] = [$d.downloaded_by[].ip])' out.json`
```json
{
  "87effd...": [
    [
      "46.246.6.15",
      "46.246.82.6",
      "46.246.86.4"
    ]
  ],
  "59ac4...": [
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
## Overlaps
At the bottom of the output is a separate struct called `overlaps` which aims to help summarize the data.
In it are two more structs, `shared_hashes` and `shared_downloads`

### shared_hashes
This will tell you if the same file was downloaded by multiple IPs.
The IPs in this output are those that are being searched for from `ips.txt`.

In this example below, the search was for those two IPs which were both found to download the same hash.
```json
"shared_hashes": {
      "7c912...": [
        "152.32.138.108",
        "15.235.130.160"
      ]
},
```

### shared_downloaded
This will tell you if an IP exists in the ITW section of the results multiple times.
In the example below, each IP listed means it exists within each hash's "downloaded_by" slice.
```json
"shared_downloaded": {
      "15.235.130.160": [
        "7c912...",
        "52277...",
        "7c912..."
      ],
      "152.32.138.108": [
        "cd313...",
        "7c912...",
        "ddb2b...",
        "7c912..."
      ]
    }
```

## Finding New Hosts
To illustrate a more complete example of how this tool can be useful, below is a semi redacted output after searching for
two IPs. In the overlaps struct, it shows a very different IP. Again, this `shared_downloaded` struct means that in each
of the three hashes "downloaded_by" structs, that 2.59 IP was also seen downloading the file.
```json
{
  "ips": [
    {
      "ip": "88.151.192.71",
      "downloads": [
        {...},
        {...}
      ]
    },
    {
      "ip": "88.151.192.50",
      "downloads": [
        {...}
  ],
  "overlaps": {
    "shared_downloaded": {
      "2.59.163.172": [
        "f8bd5...",
        "4b005...",
        "1118a..."
      ],
      "88.151.192.50": [
        "f8bd5...",
        "c3c12...",
        "4b005...",
        "1118a...",
        "e3c50...",
        "5e760..."
      ]
    }
  }
}

```
Looking into that IP further revealed it previously acted as an open directory serving Windows executables and PDFs.
The files are detected as **SmokeLoader** samples and the infrastructure uncovered was involved in a [campaign targeting 
Ukraine's Auto & Banking Industries](https://hunt.io/blog/smokeloader-malware-found-in-open-directories-targeting-ukraine-s-auto-banking-industries).