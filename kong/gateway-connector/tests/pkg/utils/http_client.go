/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package utils

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// SimpleHTTPClient is a wrapper around Go's standard HTTP client
type SimpleHTTPClient struct {
	Client          *http.Client
	lastRequest     *http.Request
	Timeout         time.Duration
	EventualTimeout time.Duration
}

// NewSimpleHTTPClient creates a simple http client
func NewSimpleHTTPClient() *SimpleHTTPClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return &SimpleHTTPClient{
		Client:          client,
		Timeout:         15 * time.Second,
		EventualTimeout: 15 * time.Second,
	}
}

// SetHeaders sets headers on the HTTP request
func SetHeaders(headers map[string]string, req *http.Request) {
	for key, value := range headers {
		req.Header.Add(key, value)
	}
}

// DoGet sends an HTTP GET request
func (client *SimpleHTTPClient) DoGet(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	SetHeaders(headers, req)
	client.lastRequest = req
	return client.Client.Do(req)
}

// DoPost sends an HTTP POST request with a payload
func (client *SimpleHTTPClient) DoPost(url string, headers map[string]string, payload string, contentType string) (*http.Response, error) {
	body := bytes.NewBuffer([]byte(payload))
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	SetHeaders(headers, req)
	client.lastRequest = req
	return client.Client.Do(req)
}

// DoOptions sends an HTTP OPTIONS request to the specified URL
func (client *SimpleHTTPClient) DoOptions(url string, headers map[string]string, payload string, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodOptions, url, nil)
	if err != nil {
		return nil, err
	}

	SetHeaders(headers, req)

	if payload != "" {
		var body io.Reader = strings.NewReader(payload)
		if headers["Content-Encoding"] == "gzip" {
			var compressedBody bytes.Buffer
			gzipWriter := gzip.NewWriter(&compressedBody)
			_, err := gzipWriter.Write([]byte(payload))
			if err != nil {
				return nil, err
			}
			gzipWriter.Close()
			body = &compressedBody
		}

		req.Body = ioutil.NopCloser(body)
		req.ContentLength = int64(len(payload))
		req.Header.Set("Content-Type", contentType)

		if headers["Content-Encoding"] == "gzip" {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}

	return client.Client.Do(req)
}

// DoHead sends an HTTP HEAD request to the specified URL
func (client *SimpleHTTPClient) DoHead(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	SetHeaders(headers, req)
	return client.Client.Do(req)
}

// DoDelete sends an HTTP DELETE request to the specified URL
func (client *SimpleHTTPClient) DoDelete(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil, err
	}

	SetHeaders(headers, req)
	return client.Client.Do(req)
}

// DoPut sends an HTTP PUT request to the specified URL with a payload
func (client *SimpleHTTPClient) DoPut(url string, headers map[string]string, payload string, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		return nil, err
	}

	SetHeaders(headers, req)

	var body io.Reader = strings.NewReader(payload)
	if headers["Content-Encoding"] == "gzip" {
		var compressedBody bytes.Buffer
		gzipWriter := gzip.NewWriter(&compressedBody)
		_, err := gzipWriter.Write([]byte(payload))
		if err != nil {
			return nil, err
		}
		gzipWriter.Close()
		body = &compressedBody
	}

	req.Body = ioutil.NopCloser(body)
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", contentType)

	if headers["Content-Encoding"] == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}

	return client.Client.Do(req)
}

// DoPostWithMultipart performs a POST request with a multipart body
func (client *SimpleHTTPClient) DoPostWithMultipart(url string, body io.Reader) (*http.Response, error) {
	return client.doPostWithMultipartWithHeaders(url, body, map[string]string{})
}

// doPostWithMultipartWithHeaders performs a POST request with a multipart body and custom headers
func (client *SimpleHTTPClient) doPostWithMultipartWithHeaders(url string, body io.Reader, header map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	client.lastRequest = req
	return client.Client.Do(req)
}

// MultipartFilePart structure
type MultipartFilePart struct {
	Name string
	File *os.File
	Text string
}

// DoPostWithMultipartFiles performs a POST request with multiple file parts and custom headers
func (client *SimpleHTTPClient) DoPostWithMultipartFiles(url string, fileParts []MultipartFilePart, header map[string]string) (*http.Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for _, filePart := range fileParts {
		if filePart.File != nil {
			part, err := writer.CreateFormFile(filePart.Name, filePart.File.Name())
			if err != nil {
				return nil, err
			}
			_, err = io.Copy(part, filePart.File)
			if err != nil {
				return nil, err
			}
		} else if filePart.Text != "" {
			err := writer.WriteField(filePart.Name, filePart.Text)
			if err != nil {
				return nil, err
			}
		}
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	for key, value := range header {
		req.Header.Set(key, value)
	}

	client.lastRequest = req
	return client.Client.Do(req)
}

// DoPutWithMultipart performs a PUT request with a single file and custom headers
func (client *SimpleHTTPClient) DoPutWithMultipart(url string, file *os.File, header map[string]string) (*http.Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", file.Name())
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, err
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPut, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	for key, value := range header {
		req.Header.Set(key, value)
	}

	client.lastRequest = req
	return client.Client.Do(req)
}

// GetResponsePayload extracts the response body as a string
func GetResponsePayload(response *http.Response) (string, error) {
	if response.Body != nil {
		defer response.Body.Close()
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
	return "", nil
}

// ExecuteLastRequestForEventualConsistentResponse retries the last request for a consistent response
func (client *SimpleHTTPClient) ExecuteLastRequestForEventualConsistentResponse(successResponseCode int, nonAcceptableCodes []int) (*http.Response, error) {
	counter := 0
	var response *http.Response
	for counter < int(client.EventualTimeout.Seconds()) {
		counter++
		time.Sleep(1 * time.Second)
		var err error
		response, err = client.Client.Do(client.lastRequest)
		if err != nil {
			return nil, err
		}

		if response.StatusCode == successResponseCode {
			return response, nil
		}

		if ContainsInteger(nonAcceptableCodes, response.StatusCode) {
			return response, nil
		}
	}
	return nil, fmt.Errorf("could not receive expected response within time")
}
