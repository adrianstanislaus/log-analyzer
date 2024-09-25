package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Configuration
var (
	vtApiKey  = os.Getenv("VT_API_KEY")
	otxApiKey = os.Getenv("OTX_API_KEY")
)

const (
	vtApiUrl    = "https://www.virustotal.com/api/v3/ip_addresses/"
	otxApiUrl   = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
	sshdLogPath = "input000.txt"
)

// API Response Struct
type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

type OTXResponse struct {
	PulseInfo struct {
		Count int `json:"count"`
	} `json:"pulse_info"`
}

// Output Structs
type Provider struct {
	Provider string `json:"provider"`
	Verdict  string `json:"verdict"`
	Score    string `json:"score,omitempty"`
}

type Indicator struct {
	Value     string     `json:"value"`
	Type      string     `json:"type"`
	Providers []Provider `json:"providers"`
}

type Result struct {
	Indicators []Indicator `json:"indicators"`
}

func main() {
	ips, err := parseSSHDLogs(sshdLogPath)
	if err != nil {
		log.Println("Error Parsing SSHD Logs file:", err)
		return
	}
	log.Printf("Total IoC: %d", len(ips))
	result := Result{Indicators: []Indicator{}}

	for i, ip := range ips {
		log.Printf("check IP %s | %d/%d", ip, i+1, len(ips))
		indicator, err := checkIOC(ip)
		if err != nil {
			log.Println("Error CheckIOC:", err)
			return
		}
		result.Indicators = append(result.Indicators, indicator)
	}

	// Print results as JSON
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Println("Error marshalling JSON:", err)
		return
	}
	fmt.Println(string(jsonOutput))
}

// Parsing SSHD Logs
func parseSSHDLogs(logPath string) ([]string, error) {
	file, err := os.Open(logPath)
	if err != nil {
		log.Println("Error opening file:", err)
		return nil, err
	}
	defer file.Close()

	var ips []string
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "sshd") {
			ip := ipRegex.FindString(line)
			if ip != "" && !slices.Contains(ips, ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

// Execute each IoC providers API and parse those as Indicators
func checkIOC(ip string) (Indicator, error) {
	provider := []Provider{}

	vtResult, err := checkVirusTotal(ip)
	if err != nil {
		log.Println("VirusTotal Result Error -- skipping | ", err)
	} else {
		vtProvider := Provider{
			Provider: "VirusTotal",
			Verdict:  getVerdict(vtResult.Malicious > 0),
			Score:    fmt.Sprintf("%d/%d", vtResult.Malicious, vtResult.Malicious+vtResult.Timeout+vtResult.Harmless+vtResult.Undetected+vtResult.Suspicious),
		}
		provider = append(provider, vtProvider)
	}

	otxResult, err := checkOTX(ip)
	if err != nil {
		log.Println("OTX Result Error -- skipping |", err)
	} else {
		otxProvider := Provider{
			Provider: "OTX",
			Verdict:  getVerdict(otxResult > 0),
		}
		provider = append(provider, otxProvider)
	}

	indicator := Indicator{
		Value:     ip,
		Type:      "ip",
		Providers: provider,
	}
	return indicator, nil
}

// Simpilify verdict based on boolean verification
func getVerdict(isMalicious bool) string {
	if isMalicious {
		return "malicious"
	}
	return "not malicious"
}

// Call VirusTotal API
func checkVirusTotal(ip string) (struct{ Malicious, Harmless, Undetected, Suspicious, Timeout int }, error) {
	if vtApiUrl == "" || vtApiKey == "" {
		return struct{ Malicious, Harmless, Undetected, Suspicious, Timeout int }{0, 0, 0, 0, 0}, errors.New("invalid api url or api key")
	}
	url := vtApiUrl + ip
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", vtApiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return struct{ Malicious, Harmless, Undetected, Suspicious, Timeout int }{0, 0, 0, 0, 0}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return struct{ Malicious, Harmless, Undetected, Suspicious, Timeout int }{0, 0, 0, 0, 0}, errors.New(string(body))
	}

	var vtResp VTResponse
	if err := json.Unmarshal(body, &vtResp); err != nil { // Parse []byte to the go struct pointer
		log.Println("Can not unmarshal JSON")
	}

	return struct{ Malicious, Harmless, Undetected, Suspicious, Timeout int }{
		vtResp.Data.Attributes.LastAnalysisStats.Malicious,
		vtResp.Data.Attributes.LastAnalysisStats.Harmless,
		vtResp.Data.Attributes.LastAnalysisStats.Undetected,
		vtResp.Data.Attributes.LastAnalysisStats.Suspicious,
		vtResp.Data.Attributes.LastAnalysisStats.Timeout,
	}, nil
}

// Call OTX API
func checkOTX(ip string) (int, error) {
	url := otxApiUrl + ip
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", otxApiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error checking OTX:", err)
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, errors.New(string(body))
	}
	var otxResp OTXResponse
	if err := json.Unmarshal(body, &otxResp); err != nil { // Parse []byte to the go struct pointer
		log.Println("Can not unmarshal JSON")
	}
	return otxResp.PulseInfo.Count, nil
}
