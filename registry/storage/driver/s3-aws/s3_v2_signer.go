package s3

// Source: https://github.com/pivotal-golang/s3cli

// Copyright (c) 2013 Damien Le Berrigaud and Nick Wade

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/middleware"

	awssigner "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	log "github.com/sirupsen/logrus"
)

type signer struct {
	// Values that must be populated from the request
	Request      *http.Request
	Time         time.Time
	Credentials  *aws.Credentials
	Query        url.Values
	stringToSign string
	signature    string
}

var s3ParamsToSign = map[string]bool{
	"acl":                          true,
	"location":                     true,
	"logging":                      true,
	"notification":                 true,
	"partNumber":                   true,
	"policy":                       true,
	"requestPayment":               true,
	"torrent":                      true,
	"uploadId":                     true,
	"uploads":                      true,
	"versionId":                    true,
	"versioning":                   true,
	"versions":                     true,
	"response-content-type":        true,
	"response-content-language":    true,
	"response-expires":             true,
	"response-cache-control":       true,
	"response-content-disposition": true,
	"response-content-encoding":    true,
	"website":                      true,
	"delete":                       true,
}

// setv2Handlers will setup v2 signature signing on the S3 driver
func setv2Handlers(s *middleware.Stack) error {
	s.Build.Add(
		&ParseRequestURL{},
		middleware.After,
	)

	s.Finalize.Remove("Signing")
	s.Finalize.Add(
		awssigner.NewSignHTTPRequestMiddleware(awssigner.SignHTTPRequestMiddlewareOptions{
			Signer: &V2Signer{},
		}),
		middleware.After,
	)
	s.Finalize.Add(
		&BuildContentLength{},
		middleware.After,
	)
	return nil
}

type ParseRequestURL struct {}

func (p *ParseRequestURL) ID() string {
	return "Parsing request URL"
}

func (p *ParseRequestURL) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.BuildOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected request middleware type %T", in.Request)
	}
	parsedURL, err := url.Parse(req.Request.URL.String())
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}
	req.Request.URL.Opaque = parsedURL.Path
	return next.HandleBuild(ctx, in)
}

func SeekerLen(v any) (int64, error) {
	if rsc, ok := v.(*s3manager.ReaderSeekerCloser); ok {
		return rsc.GetLen()
	}

	s, ok := v.(io.Seeker)
	if !ok {
		return -1, nil
	}

	cur, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	end, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	if _, err := s.Seek(cur, io.SeekStart); err != nil {
		return 0, err
	}

	return end - cur, nil
}

type BuildContentLength struct {}

func (b *BuildContentLength) ID() string {
	return "Building Content-Length"
}

func (p *BuildContentLength) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected request middleware type %T", in.Request)
	}
	var length int64

	if slength := req.Request.Header.Get("Content-Length"); slength != "" {
		length, _ = strconv.ParseInt(slength, 10, 64)
	} else {
		if req.Request.Body != nil {
			var err error
			length, err = SeekerLen(req.Request.Body)
			if err != nil {
				return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("failed to get request body's length: %s", err.Error())
			}
		}
	}

	if length > 0 {
		req.Request.ContentLength = length
		req.Request.Header.Set("Content-Length", fmt.Sprintf("%d", length))
	} else {
		req.Request.ContentLength = 0
		req.Request.Header.Del("Content-Length")
	}
	return next.HandleFinalize(ctx, in)
}

type V2Signer struct {}

// Sign requests with signature version 2.
//
// Will sign the requests with the service config's Credentials object
// Signing is skipped if the credentials is the credentials.AnonymousCredentials
// object.
func (s *V2Signer) SignHTTP(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(*awssigner.SignerOptions)) error {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if ac, _ := (&aws.AnonymousCredentials{}).Retrieve(ctx); creds.Source == ac.Source {
		return nil
	}

	accessKey := creds.AccessKeyID
	var (
		md5, ctype, date, xamz string
		xamzDate               bool
		sarray                 []string
		smap                   map[string]string
		sharray                []string
	)

	headers := req.Header
	params := req.URL.Query()
	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return err
	}
	host, canonicalPath := parsedURL.Host, parsedURL.Path
	req.Header["Host"] = []string{host}
	req.Header["date"] = []string{signingTime.In(time.UTC).Format(time.RFC1123)}
	if creds.SessionToken != "" {
		req.Header["x-amz-security-token"] = []string{creds.SessionToken}
	}

	smap = make(map[string]string)
	for k, v := range headers {
		k = strings.ToLower(k)
		switch k {
		case "content-md5":
			md5 = v[0]
		case "content-type":
			ctype = v[0]
		case "date":
			if !xamzDate {
				date = v[0]
			}
		default:
			if strings.HasPrefix(k, "x-amz-") {
				vall := strings.Join(v, ",")
				smap[k] = k + ":" + vall
				if k == "x-amz-date" {
					xamzDate = true
					date = ""
				}
				sharray = append(sharray, k)
			}
		}
	}
	if len(sharray) > 0 {
		sort.StringSlice(sharray).Sort()
		for _, h := range sharray {
			sarray = append(sarray, smap[h])
		}
		xamz = strings.Join(sarray, "\n") + "\n"
	}

	expires := false
	if v, ok := params["Expires"]; ok {
		expires = true
		date = v[0]
		params["AWSAccessKeyId"] = []string{accessKey}
	}

	sarray = sarray[0:0]
	for k, v := range params {
		if s3ParamsToSign[k] {
			for _, vi := range v {
				if vi == "" {
					sarray = append(sarray, k)
				} else {
					sarray = append(sarray, k+"="+vi)
				}
			}
		}
	}
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		canonicalPath = canonicalPath + "?" + strings.Join(sarray, "&")
	}

	stringToSign := strings.Join([]string{
		req.Method,
		md5,
		ctype,
		date,
		xamz + canonicalPath,
	}, "\n")
	hash := hmac.New(sha1.New, []byte(creds.SecretAccessKey))
	hash.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	if expires {
		params["Signature"] = []string{signature}
	} else {
		headers["Authorization"] = []string{"AWS " + accessKey + ":" + signature}
	}

	req.URL.RawQuery = params.Encode()

	log.WithFields(log.Fields{
		"string-to-sign": stringToSign,
		"signature":      signature,
	}).Debugln("request signature")
	return nil
}
