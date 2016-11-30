package main

import (
  "encoding/json"
  "encoding/xml"
  "log"
  "net/http"
  "strings"
)

type ECSBucket struct {
  Api string `json:"bucket_api"`
  Endpoint string `json:"bucket_endpoint"`
  Password string `json:"bucket_password"`
  Name string `json:"bucket_name"`
  ReplicationGroup string `json:"bucket_replication_group"`
  MetadataSearch string `json:"bucket_metadata_search"`
  EnableADO bool `json:"bucket_enable_ado"`
  EnableFS bool `json:"bucket_enable_fs"`
  EnableCompliance bool `json:"bucket_enable_compliance"`
  EnableEncryption bool `json:"bucket_enable_encryption"`
}

// Create a new bucket
func CreateBucket(w http.ResponseWriter, r *http.Request) *appError {
  decoder := json.NewDecoder(r.Body)
  var ecsBucket ECSBucket
  err := decoder.Decode(&ecsBucket)
  if err != nil {
    return &appError{err: err, status: http.StatusBadRequest, json: "Can't decode JSON data"}
  }
  headers := make(map[string][]string)
  if ecsBucket.ReplicationGroup != "" {
    headers["x-emc-vpool"] = []string{ecsBucket.ReplicationGroup}
  }
  if ecsBucket.MetadataSearch != "" {
    headers["x-emc-metadata-search"] = []string{ecsBucket.MetadataSearch}
  }
  if ecsBucket.EnableADO {
    headers["x-emc-is-stale-allowed"] = []string{"true"}
  } else {
    headers["x-emc-is-stale-allowed"] = []string{"false"}
  }
  if ecsBucket.EnableFS {
    headers["x-emc-file-system-access-enabled"] = []string{"true"}
  } else {
    headers["x-emc-file-system-access-enabled"] = []string{"false"}
  }
  if ecsBucket.EnableCompliance {
    headers["x-emc-compliance-enabled"] = []string{"true"}
  } else {
    headers["x-emc-compliance-enabled"] = []string{"false"}
  }
  if ecsBucket.EnableEncryption {
    headers["x-emc-server-side-encryption-enabled"] = []string{"true"}
  } else {
    headers["x-emc-server-side-encryption-enabled"] = []string{"false"}
  }
  var bucketCreateResponse Response
  if ecsBucket.Api == "s3" {
    s3, err := getS3(r)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
    bucketCreateResponse, err = s3Request(s3, ecsBucket.Name, "PUT", "/", headers, "")
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: err.Error()}
    }
    if bucketCreateResponse.Code == 200  {
      rendering.JSON(w, http.StatusOK, ecsBucket.Name)
    } else {
      return &appError{err: err, status: http.StatusInternalServerError, xml: bucketCreateResponse.Body}
    }
  } else if ecsBucket.Api == "swift" {
    s3, err := getS3(r)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
    bucketCreateResponse, err = swiftRequest(ecsBucket.Endpoint, s3.AccessKey, ecsBucket.Password, ecsBucket.Name, "PUT", "/", headers, "")
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: err.Error()}
    }
    if bucketCreateResponse.Code >= 200 && bucketCreateResponse.Code < 300  {
      rendering.JSON(w, http.StatusOK, ecsBucket.Name)
    } else {
      return &appError{err: err, status: http.StatusInternalServerError, xml: bucketCreateResponse.Body}
    }
  } else if ecsBucket.Api == "atmos" {
    s3, err := getS3(r)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
    bucketCreateResponse, err = atmosRequest(ecsBucket.Endpoint, s3.AccessKey, s3.SecretKey, "", "PUT", "/rest/subtenant", headers, "")
    if err != nil {
      log.Print(err)
      return &appError{err: err, status: http.StatusInternalServerError, json: err.Error()}
    }
    if bucketCreateResponse.Code >= 200 && bucketCreateResponse.Code < 300  {
      rendering.JSON(w, http.StatusOK, bucketCreateResponse.ResponseHeaders["Subtenantid"][0])
    } else {
      return &appError{err: err, status: http.StatusInternalServerError, xml: bucketCreateResponse.Body}
    }
  }

  return nil
}

// Retrieve the list of buckets owned by this object user
func ListBuckets(w http.ResponseWriter, r *http.Request) *appError {
  s3, err := getS3(r)
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
  }
  response, _ := s3Request(s3, "", "GET", "/", make(map[string][]string), "")
  listBucketsResp := &ListBucketsResp{}
  xml.NewDecoder(strings.NewReader(response.Body)).Decode(listBucketsResp)
  buckets := []string{}
  for _, bucket := range listBucketsResp.Buckets {
    buckets = append(buckets, bucket.Name)
  }
  rendering.JSON(w, http.StatusOK, buckets)

  return nil
}
