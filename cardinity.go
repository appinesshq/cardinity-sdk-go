package cardinity

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const baseURL = "https://api.cardinity.com/v1/"

// Cardinity gives access to the Cardinity API.
type Cardinity struct {
	log log.Logger

	// ConsumerKey is the OAuth1 consumer key for the Cardinity service.
	ConsumerKey string

	// ConsumerSecret is the OAuth1 consumer secret for the Cardinity service.
	ConsumerSecret string

	// Debug enables debug mode when set to true.
	Debug bool
}

// New returns an initialized APi wrapper.
func New(consumerKey, consumerSecret string) *Cardinity {
	return &Cardinity{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
	}
}

// APIError contains an API error response.
type APIError struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Errors []struct {
		Field    string `json:"field"`
		Rejected string `json:"rejected"`
		Message  string `json:"message"`
	} `json:"errors"`
}

// Error implements the error interface.
func (err *APIError) Error() string {
	s := fmt.Sprintf("%s: %s (%s)", err.Title, err.Detail, err.Type)
	if len(err.Errors) == 0 {
		return strings.ToLower(s)
	}

	b := bytes.Buffer{}
	b.WriteString(s)
	for _, e := range err.Errors {
		b.WriteString(fmt.Sprintf("\n%s: %s %s", e.Field, e.Message, e.Rejected))
	}

	return strings.ToLower(b.String())
}

func oAuthString(key, secret, method, uri string) string {
	ts := time.Now().UTC().Unix()
	nonce := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%d", ts))))[:32]

	p := url.Values{}
	p.Add("oauth_consumer_key", key)
	p.Add("oauth_signature_method", "HMAC-SHA1")
	p.Add("oauth_timestamp", fmt.Sprintf("%d", ts))
	p.Add("oauth_nonce", nonce)
	p.Add("oauth_version", "1.0")
	s := fmt.Sprintf("%s&%s&%s", strings.ToUpper(method), url.QueryEscape(uri), p.Encode())
	p.Add("oauth_signature", Sign(secret, s, ""))

	return p.Encode()
}

func (c *Cardinity) do(req *http.Request, v interface{}) ([]byte, error) {
	// Set request headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("OAuth", oAuthString(c.ConsumerKey, c.ConsumerSecret, req.Method, req.URL.String()))

	// Make API request.
	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "making request")
	}
	defer res.Body.Close()

	// Check for API error.
	if res.StatusCode >= 400 {
		e := APIError{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			// Couldn't decode API error, return unexpected error with
			// information from the status.
			return nil, fmt.Errorf("unexpected error: %s", res.Status)
		}

		// Return APIError
		return nil, &e
	}

	// If v is not provided, simply return the body in bytes.
	if v == nil {
		return ioutil.ReadAll(res.Body)
	}

	// JSON decode the body to v.
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		return nil, errors.Wrap(err, "decoding json")
	}

	return nil, nil
}
