package vt

const BaseUrl = "https://www.virustotal.com/api/v3/"

type Client struct {
	apiKey string
}

func New(apiKey string) (*Client, error) {
	return &Client{apiKey: apiKey}, nil
}
