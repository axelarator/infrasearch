package vt

type HostSearch struct {
	Data []struct {
		Id    string `json:"id"`
		Type  string `json:"type"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Attributes struct {
			Tlsh             string   `json:"tlsh"`
			Authentihash     string   `json:"authentihash"`
			AvailableTools   []string `json:"available_tools"`
			TypeTag          string   `json:"type_tag"`
			FirstSeenItwDate int      `json:"first_seen_itw_date,omitempty"`
			UniqueSources    int      `json:"unique_sources"`
			Exiftool         struct {
				MIMEType                 string `json:"MIMEType"`
				Subsystem                string `json:"Subsystem"`
				MachineType              string `json:"MachineType"`
				TimeStamp                string `json:"TimeStamp"`
				FileType                 string `json:"FileType"`
				PEType                   string `json:"PEType"`
				CodeSize                 string `json:"CodeSize"`
				InitializedDataSize      string `json:"InitializedDataSize"`
				ImageFileCharacteristics string `json:"ImageFileCharacteristics"`
				FileTypeExtension        string `json:"FileTypeExtension"`
				LinkerVersion            string `json:"LinkerVersion"`
				SubsystemVersion         string `json:"SubsystemVersion"`
				EntryPoint               string `json:"EntryPoint"`
				OSVersion                string `json:"OSVersion"`
				ImageVersion             string `json:"ImageVersion"`
				UninitializedDataSize    string `json:"UninitializedDataSize"`
				FileSubtype              string `json:"FileSubtype,omitempty"`
				FileVersionNumber        string `json:"FileVersionNumber,omitempty"`
				LanguageCode             string `json:"LanguageCode,omitempty"`
				InternalName             string `json:"InternalName,omitempty"`
				CharacterSet             string `json:"CharacterSet,omitempty"`
				FileVersion              string `json:"FileVersion,omitempty"`
				FileFlagsMask            string `json:"FileFlagsMask,omitempty"`
				ProductVersion           string `json:"ProductVersion,omitempty"`
				FileOS                   string `json:"FileOS,omitempty"`
				ProductName              string `json:"ProductName,omitempty"`
				ProductVersionNumber     string `json:"ProductVersionNumber,omitempty"`
				ObjectFileType           string `json:"ObjectFileType,omitempty"`
				OriginalFileName         string `json:"OriginalFileName,omitempty"`
				LegalCopyright           string `json:"LegalCopyright,omitempty"`
				FileDescription          string `json:"FileDescription,omitempty"`
				CompanyName              string `json:"CompanyName,omitempty"`
				LegalTrademarks          string `json:"LegalTrademarks,omitempty"`
				Comments                 string `json:"Comments,omitempty"`
				AssemblyVersion          string `json:"AssemblyVersion,omitempty"`
			} `json:"exiftool"`
			Detectiteasy struct {
				Filetype string `json:"filetype"`
				Values   []struct {
					Info    string `json:"info,omitempty"`
					Version string `json:"version"`
					Type    string `json:"type"`
					Name    string `json:"name"`
				} `json:"values"`
			} `json:"detectiteasy,omitempty"`
			TimesSubmitted      int      `json:"times_submitted"`
			Names               []string `json:"names"`
			CreationDate        int      `json:"creation_date,omitempty"`
			Reputation          int      `json:"reputation"`
			FirstSubmissionDate int      `json:"first_submission_date"`
			TotalVotes          struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			LastAnalysisDate int      `json:"last_analysis_date"`
			MeaningfulName   string   `json:"meaningful_name"`
			Tags             []string `json:"tags"`
			Size             int      `json:"size"`
			Ssdeep           string   `json:"ssdeep"`
			Downloadable     bool     `json:"downloadable"`
			PeInfo           struct {
				Timestamp       int    `json:"timestamp,omitempty"`
				Imphash         string `json:"imphash"`
				MachineType     int    `json:"machine_type"`
				EntryPoint      int    `json:"entry_point"`
				ResourceDetails []struct {
					Lang     string  `json:"lang"`
					Chi2     float64 `json:"chi2"`
					Filetype string  `json:"filetype"`
					Entropy  float64 `json:"entropy"`
					Sha256   string  `json:"sha256"`
					Type     string  `json:"type"`
				} `json:"resource_details,omitempty"`
				ResourceLangs struct {
					NEUTRAL   int `json:"NEUTRAL"`
					ENGLISHUS int `json:"ENGLISH US,omitempty"`
					GERMAN    int `json:"GERMAN,omitempty"`
					ENGLISHUK int `json:"ENGLISH UK,omitempty"`
				} `json:"resource_langs,omitempty"`
				ResourceTypes struct {
					RTMANIFEST  int `json:"RT_MANIFEST,omitempty"`
					RTICON      int `json:"RT_ICON,omitempty"`
					RTVERSION   int `json:"RT_VERSION,omitempty"`
					RTGROUPICON int `json:"RT_GROUP_ICON,omitempty"`
					RTRCDATA    int `json:"RT_RCDATA,omitempty"`
					RTSTRING    int `json:"RT_STRING,omitempty"`
					RTMENU      int `json:"RT_MENU,omitempty"`
				} `json:"resource_types,omitempty"`
				Sections []struct {
					Chi2           float64 `json:"chi2"`
					VirtualAddress int     `json:"virtual_address"`
					Entropy        float64 `json:"entropy"`
					RawSize        int     `json:"raw_size"`
					Flags          string  `json:"flags"`
					VirtualSize    int     `json:"virtual_size"`
					Md5            string  `json:"md5"`
					Name           string  `json:"name,omitempty"`
				} `json:"sections"`
				CompilerProductVersions []string `json:"compiler_product_versions,omitempty"`
				RichPeHeaderHash        string   `json:"rich_pe_header_hash,omitempty"`
				ImportList              []struct {
					LibraryName       string   `json:"library_name"`
					ImportedFunctions []string `json:"imported_functions"`
				} `json:"import_list"`
				Overlay struct {
					Chi2     float64 `json:"chi2"`
					Filetype string  `json:"filetype"`
					Entropy  float64 `json:"entropy"`
					Offset   int     `json:"offset"`
					Md5      string  `json:"md5"`
					Size     int     `json:"size"`
				} `json:"overlay,omitempty"`
				Exports []string `json:"exports,omitempty"`
				Debug   []struct {
					TypeStr   string `json:"type_str"`
					Timestamp string `json:"timestamp"`
					Size      int    `json:"size"`
					Type      int    `json:"type"`
					Offset    int    `json:"offset"`
				} `json:"debug,omitempty"`
			} `json:"pe_info"`
			Vhash      string `json:"vhash"`
			Filecondis struct {
				RawMd5 string `json:"raw_md5"`
				Dhash  string `json:"dhash"`
			} `json:"filecondis"`
			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
				PopularThreatName    []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"popular_threat_name,omitempty"`
				PopularThreatCategory []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"popular_threat_category"`
			} `json:"popular_threat_classification"`
			CrowdsourcedIdsStats struct {
				High   int `json:"high"`
				Medium int `json:"medium"`
				Low    int `json:"low"`
				Info   int `json:"info"`
			} `json:"crowdsourced_ids_stats,omitempty"`
			LastModificationDate int `json:"last_modification_date"`
			LastAnalysisStats    struct {
				Malicious        int `json:"malicious"`
				Suspicious       int `json:"suspicious"`
				Undetected       int `json:"undetected"`
				Harmless         int `json:"harmless"`
				Timeout          int `json:"timeout"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Failure          int `json:"failure"`
				TypeUnsupported  int `json:"type-unsupported"`
			} `json:"last_analysis_stats"`
			Sha256         string `json:"sha256"`
			ThreatSeverity struct {
				Version             int    `json:"version"`
				ThreatSeverityLevel string `json:"threat_severity_level"`
				ThreatSeverityData  struct {
					PopularThreatCategory                     string `json:"popular_threat_category"`
					NumGavDetections                          int    `json:"num_gav_detections,omitempty"`
					BelongsToBadCollection                    bool   `json:"belongs_to_bad_collection,omitempty"`
					IsMatchedByCrowdsourcedYaraWithDetections bool   `json:"is_matched_by_crowdsourced_yara_with_detections,omitempty"`
					NumAvDetections                           int    `json:"num_av_detections,omitempty"`
				} `json:"threat_severity_data"`
				LastAnalysisDate string `json:"last_analysis_date"`
				LevelDescription string `json:"level_description"`
			} `json:"threat_severity"`
			Magika          string `json:"magika"`
			TypeDescription string `json:"type_description"`
			Md5             string `json:"md5"`
			Magic           string `json:"magic"`
			TypeExtension   string `json:"type_extension"`
			Trid            []struct {
				FileType    string  `json:"file_type"`
				Probability float64 `json:"probability"`
			} `json:"trid"`
			Sha1               string `json:"sha1"`
			SigmaAnalysisStats struct {
				Critical int `json:"critical"`
				High     int `json:"high"`
				Medium   int `json:"medium"`
				Low      int `json:"low"`
			} `json:"sigma_analysis_stats,omitempty"`
			LastSubmissionDate int      `json:"last_submission_date"`
			TypeTags           []string `json:"type_tags"`
			MalwareConfig      struct {
				Families []struct {
					Family  string `json:"family"`
					Configs []struct {
						HostInfo struct {
							Mutexes []string `json:"mutexes"`
						} `json:"host_info,omitempty"`
						Tool        string `json:"tool"`
						ImplantInfo struct {
							Version     string   `json:"version,omitempty"`
							CampaignIds []string `json:"campaign_ids,omitempty"`
						} `json:"implant_info,omitempty"`
						NetInfo struct {
							Connections []struct {
								Host         string   `json:"host"`
								Categories   []string `json:"categories"`
								Url          string   `json:"url,omitempty"`
								ProtocolTags []string `json:"protocol_tags,omitempty"`
							} `json:"connections"`
						} `json:"net_info,omitempty"`
						TxtConfigs []string `json:"txt_configs,omitempty"`
					} `json:"configs"`
					AltNames []string `json:"alt_names,omitempty"`
				} `json:"families"`
			} `json:"malware_config,omitempty"`
			SignatureInfo struct {
				Verified    string `json:"verified,omitempty"`
				SigningDate string `json:"signing date,omitempty"`
				X509        []struct {
					ValidUsage       string `json:"valid usage"`
					ThumbprintSha256 string `json:"thumbprint_sha256"`
					Name             string `json:"name"`
					Algorithm        string `json:"algorithm"`
					ThumbprintMd5    string `json:"thumbprint_md5"`
					ValidFrom        string `json:"valid from"`
					ValidTo          string `json:"valid to"`
					SerialNumber     string `json:"serial number"`
					CertIssuer       string `json:"cert issuer"`
					Thumbprint       string `json:"thumbprint"`
				} `json:"x509,omitempty"`
				Signers               string `json:"signers,omitempty"`
				CounterSignersDetails []struct {
					Status       string `json:"status"`
					ValidUsage   string `json:"valid usage"`
					Name         string `json:"name"`
					Algorithm    string `json:"algorithm"`
					ValidFrom    string `json:"valid from"`
					ValidTo      string `json:"valid to"`
					SerialNumber string `json:"serial number"`
					CertIssuer   string `json:"cert issuer"`
					Thumbprint   string `json:"thumbprint"`
				} `json:"counter signers details,omitempty"`
				CounterSigners string `json:"counter signers,omitempty"`
				SignersDetails []struct {
					Status       string `json:"status"`
					ValidUsage   string `json:"valid usage"`
					Name         string `json:"name"`
					Algorithm    string `json:"algorithm"`
					ValidFrom    string `json:"valid from"`
					ValidTo      string `json:"valid to"`
					SerialNumber string `json:"serial number"`
					CertIssuer   string `json:"cert issuer"`
					Thumbprint   string `json:"thumbprint"`
				} `json:"signers details,omitempty"`
				Description  string `json:"description,omitempty"`
				FileVersion  string `json:"file version,omitempty"`
				OriginalName string `json:"original name,omitempty"`
				Product      string `json:"product,omitempty"`
				Comments     string `json:"comments,omitempty"`
				InternalName string `json:"internal name,omitempty"`
				Copyright    string `json:"copyright,omitempty"`
			} `json:"signature_info,omitempty"`
			CrowdsourcedYaraResults []struct {
				RulesetId   string `json:"ruleset_id"`
				RulesetName string `json:"ruleset_name"`
				RuleName    string `json:"rule_name"`
				MatchDate   int    `json:"match_date"`
				Description string `json:"description,omitempty"`
				Author      string `json:"author"`
				Source      string `json:"source"`
			} `json:"crowdsourced_yara_results,omitempty"`
			MainIcon struct {
				RawMd5 string `json:"raw_md5"`
				Dhash  string `json:"dhash"`
			} `json:"main_icon,omitempty"`
			Packers struct {
				PEiD string `json:"PEiD"`
			} `json:"packers,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
	Meta struct {
		Count  int    `json:"count"`
		Cursor string `json:"cursor"`
	} `json:"meta"`
	Links struct {
		Self string `json:"self"`
		Next string `json:"next"`
	} `json:"links"`
}

type HashSearch struct {
	Data []struct {
		Id    string `json:"id"`
		Type  string `json:"type"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Attributes struct {
			Reputation int `json:"reputation"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			LastAnalysisDate    int      `json:"last_analysis_date"`
			Tags                []string `json:"tags"`
			ThreatNames         []string `json:"threat_names"`
			Title               string   `json:"title"`
			FirstSubmissionDate int      `json:"first_submission_date"`
			HasContent          bool     `json:"has_content"`
			Categories          struct {
				AlphaMountainAi        string `json:"alphaMountain.ai,omitempty"`
				DrWeb                  string `json:"Dr.Web,omitempty"`
				Sophos                 string `json:"Sophos,omitempty"`
				Webroot                string `json:"Webroot,omitempty"`
				ForcepointThreatSeeker string `json:"Forcepoint ThreatSeeker,omitempty"`
				XcitiumVerdictCloud    string `json:"Xcitium Verdict Cloud,omitempty"`
				BitDefender            string `json:"BitDefender,omitempty"`
			} `json:"categories"`
			Tld               string `json:"tld,omitempty"`
			Url               string `json:"url"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastFinalUrl         string `json:"last_final_url"`
			TimesSubmitted       int    `json:"times_submitted"`
			LastSubmissionDate   int    `json:"last_submission_date"`
			LastModificationDate int    `json:"last_modification_date"`
			ThreatSeverity       struct {
				Version             string `json:"version"`
				ThreatSeverityLevel string `json:"threat_severity_level"`
				ThreatSeverityData  struct {
					NumDetections                  int  `json:"num_detections,omitempty"`
					HasBadCommunicatingFilesHigh   bool `json:"has_bad_communicating_files_high"`
					HasBadCommunicatingFilesMedium bool `json:"has_bad_communicating_files_medium"`
					BelongsToBadCollection         bool `json:"belongs_to_bad_collection,omitempty"`
				} `json:"threat_severity_data"`
				LastAnalysisDate string `json:"last_analysis_date"`
				LevelDescription string `json:"level_description"`
			} `json:"threat_severity"`
			LastHttpResponseCode    int `json:"last_http_response_code,omitempty"`
			LastHttpResponseHeaders struct {
				Server                   string `json:"server,omitempty"`
				XAkamaiFwdAuthSha        string `json:"x-akamai-fwd-auth-sha,omitempty"`
				XAkamaiFwdAuthSign       string `json:"x-akamai-fwd-auth-sign,omitempty"`
				XAkamaiTransformed       string `json:"x-akamai-transformed,omitempty"`
				TimingAllowOrigin        string `json:"timing-allow-origin,omitempty"`
				Vary                     string `json:"vary,omitempty"`
				StrictTransportSecurity  string `json:"strict-transport-security,omitempty"`
				AccessControlAllowOrigin string `json:"access-control-allow-origin,omitempty"`
				ContentEncoding          string `json:"content-encoding,omitempty"`
				P3P                      string `json:"p3p,omitempty"`
				ServerTiming             string `json:"server-timing,omitempty"`
				XAkamaiFwdAuthData       string `json:"x-akamai-fwd-auth-data,omitempty"`
				XApplicationContext      string `json:"x-application-context,omitempty"`
				ContentType              string `json:"content-type,omitempty"`
				Date                     string `json:"date,omitempty"`
				EagleeyeTraceid          string `json:"eagleeye-traceid,omitempty"`
				Link                     string `json:"link,omitempty"`
				ContentEncoding1         string `json:"Content-Encoding,omitempty"`
				ContentLength            string `json:"Content-Length,omitempty"`
				ContentType1             string `json:"Content-Type,omitempty"`
				Date1                    string `json:"Date,omitempty"`
				Vary1                    string `json:"Vary,omitempty"`
				CacheControl             string `json:"Cache-Control,omitempty"`
				Connection               string `json:"Connection,omitempty"`
				ContentSecurityPolicy    string `json:"Content-Security-Policy,omitempty"`
				Expires                  string `json:"Expires,omitempty"`
				Server1                  string `json:"Server,omitempty"`
			} `json:"last_http_response_headers,omitempty"`
			LastHttpResponseContentLength int      `json:"last_http_response_content_length,omitempty"`
			OutgoingLinks                 []string `json:"outgoing_links,omitempty"`
			RedirectionChain              []string `json:"redirection_chain,omitempty"`
			LastHttpResponseContentSha256 string   `json:"last_http_response_content_sha256,omitempty"`
			Favicon                       struct {
				RawMd5 string `json:"raw_md5"`
				Dhash  string `json:"dhash"`
			} `json:"favicon,omitempty"`
			CrowdsourcedContext []struct {
				Severity  string `json:"severity"`
				Timestamp int    `json:"timestamp"`
				Details   string `json:"details"`
				Title     string `json:"title"`
				Source    string `json:"source"`
			} `json:"crowdsourced_context,omitempty"`
		} `json:"attributes"`
		ContextAttributes struct {
			Url string `json:"url"`
		} `json:"context_attributes"`
	} `json:"data"`
	Meta struct {
		Count int `json:"count"`
	} `json:"meta"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

type FinalOutput struct {
	IPs []IPData `json:"ips"`
}

type IPData struct {
	IP     string     `json:"ip"`
	Hashes []HashInfo `json:"downloads,omitempty"`
	NoData string     `json:"no_data,omitempty"`
}
type HashInfo struct {
	Hash                 string         `json:"hash,omitempty"`
	Score                string         `json:"score,omitempty"`
	Name                 string         `json:"filename,omitempty"`
	SuggestedThreatLabel string         `json:"threat_name,omitempty"`
	IPs                  []DownloadedIP `json:"downloaded_by,omitempty"`
}
type DownloadedIP struct {
	IPs             string   `json:"ip,omitempty"`
	ResolvedDomains []string `json:"resolved_domains,omitempty"`
	Country         string   `json:"country,omitempty"`
	ASN             string   `json:"org,omitempty"`
}
