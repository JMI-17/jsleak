package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
	"regexp"
	"os"
	"bufio"
	"sync"
	"flag"
	"net/url"
	"strings"
)

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	},
}

func request(fullurl string, statusCode bool) string {
	req, err := http.NewRequest("GET", fullurl, nil)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	req.Header.Add("User-Agent", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()
	 if statusCode && resp.StatusCode != 404 {
	 	fmt.Printf("[Linkfinder] %s : %d\n", fullurl,  resp.StatusCode)
	 }

	var bodyString string
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		bodyString = string(bodyBytes)
	}
	return bodyString
}

func regexGrep(content string, Burl string) {
	regex_map := map[string]string{
		"Slack Token" : `(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,
		"RSA private key" : `-----BEGIN RSA PRIVATE KEY-----`,
		"SSH (DSA) private key" : `-----BEGIN DSA PRIVATE KEY-----`,
		"SSH (EC) private key" : `-----BEGIN EC PRIVATE KEY-----`,
		"PGP private key block" : `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		"AWS API Key" : `AKIA[0-9A-Z]{16}`,
		"Amazon MWS Auth Token" : `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
		"AWS AppSync GraphQL Key" : `da2-[a-z0-9]{26}`,
		"Facebook Access Token" : `EAACEdEose0cBA[0-9A-Za-z]+`,
		"Facebook OAuth" : `[fF][aA][cC][eE][bB][oO][oO][kK].*['|"][0-9a-f]{32}['|"]`,
		"GitHub" : `[gG][iI][tT][hH][uU][bB].*['|"][0-9a-zA-Z]{35,40}['|"]`,
		"Generic API Key" : `[aA][pP][iI]_?[kK][eE][yY].*['|"][0-9a-zA-Z]{32,45}['|"]`,
		"Generic Secret" : `[sS][eE][cC][rR][eE][tT].*['|"][0-9a-zA-Z]{32,45}['|"]`,
		"Google API Key" : `AIza[0-9A-Za-z\-_]{35}`,
		"Google Cloud Platform API Key" : `AIza[0-9A-Za-z\-_]{35}`,
		"Google Cloud Platform OAuth" : `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
		"Google Drive API Key" : `AIza[0-9A-Za-z\-_]{35}`,
		"Google Drive OAuth" : `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
		"Google (GCP) Service-account" : `"type": "service_account"`,
		"Google Gmail API Key" : `AIza[0-9A-Za-z\-_]{35}`,
		"Google Gmail OAuth" : `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
		"Google OAuth Access Token" : `ya29\.[0-9A-Za-z\-_]+`,
		"Google YouTube API Key" : `AIza[0-9A-Za-z\-_]{35}`,
		"Google YouTube OAuth" : `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
		"Heroku API Key" : `[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
		"MailChimp API Key" : `[0-9a-f]{32}-us[0-9]{1,2}`,
		"Mailgun API Key" : `key-[0-9a-zA-Z]{32}`,
		"Password in URL" : `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]`,
		"PayPal Braintree Access Token" : `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
		"Picatic API Key" : `sk_live_[0-9a-z]{32}`,
		"Slack Webhook" : `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
		"Stripe API Key" : `sk_live_[0-9a-zA-Z]{24}`,
		"Stripe Restricted API Key" : `rk_live_[0-9a-zA-Z]{24}`,
		"Square Access Token" : `sq0atp-[0-9A-Za-z\-_]{22}`,
		"Square OAuth Secret" : `sq0csp-[0-9A-Za-z\-_]{43}`,
		"Telegram Bot API Key" : `[0-9]+:AA[0-9A-Za-z\-_]{33}`,
		"Twilio API Key" : `SK[0-9a-fA-F]{32}`,
		"Twitter Access Token" : `[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
		"Twitter OAuth" : `[tT][wW][iI][tT][tT][eE][rR].*['|"][0-9a-zA-Z]{35,44}['|"]`,				
	}

	for key, element := range regex_map {
		r := regexp.MustCompile(element)
		matches := r.FindAllString(content, -1)
		for _, v := range matches {
			fmt.Println("[+] Found " + "[" + key + "]" + "	[" + v + "]" + "	[" + Burl + "]")
		}
	}


}

func linkFinder(content, baseURL string, completeURL, statusCode bool) {
    linkRegex := `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`

    r := regexp.MustCompile(linkRegex)
    matches := r.FindAllString(content, -1)

    base, err := url.Parse(baseURL)
    if err != nil {
        fmt.Println("")
    }

    for _, v := range matches {
        cleanedMatch := strings.Trim(v, `"'`)
        link, err := url.Parse(cleanedMatch)
        if err != nil {
            continue
        }
        if completeURL {
            link = base.ResolveReference(link)
        }
        if statusCode {
            request(link.String(), true)
        } else {
            fmt.Printf("[+] Found link: [%s] in [%s] \n", link.String(),  base.String())
        }
    }
}


func main() {
	var concurrency int
	var enableLinkFinder, completeURL, checkStatus, enableSecretFinder bool
	flag.BoolVar(&enableLinkFinder, "l", false, "Enable linkFinder")
	flag.BoolVar(&completeURL, "e", false, "Complete Scope Url or not")
	flag.BoolVar(&checkStatus, "k", false, "Check status or not")
	flag.BoolVar(&enableSecretFinder, "s", false, "Enable secretFinder")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.Parse()
	urls := make(chan string, 10)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls <- sc.Text()
		}
		close(urls)
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}()

	wg := sync.WaitGroup{}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for vUrl := range urls {
				res := request(vUrl, false)
				
				if enableSecretFinder {
					regexGrep(res, vUrl)
				}
				if enableLinkFinder {
					linkFinder(res, vUrl, false, false)
				}
				if completeURL {
					linkFinder(res, vUrl, true, false)
				}
				if checkStatus {
					linkFinder(res, vUrl, true, true)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
