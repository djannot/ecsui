package main

import (
  "bytes"
  "crypto/tls"
  "encoding/json"
  "encoding/xml"
  "io/ioutil"
  "log"
  "net/http"
  "net/url"
  "os"
  "strings"
  "strconv"
  "time"
  cfenv "github.com/cloudfoundry-community/go-cfenv"
  "github.com/codegangsta/negroni"
  "github.com/gorilla/mux"
  "github.com/gorilla/sessions"
  "github.com/unrolled/render"
)

var rendering *render.Render
var store = sessions.NewCookieStore([]byte("session-key"))
var config Config

type Response struct {
  Code int
  Body string
  RequestHeaders http.Header
  ResponseHeaders http.Header
}

type appError struct {
	err error
	status int
	json string
	template string
  xml string
	binding interface{}
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  if e := fn(w, r); e != nil {
		log.Print(e.err)
		if e.status != 0 {
			if e.json != "" {
				rendering.JSON(w, e.status, e.json)
			} else if e.xml != "" {
				rendering.XML(w, e.status, e.xml)
			} else {
				rendering.HTML(w, e.status, e.template, e.binding)
			}
		}
  }
}

func RecoverHandler(next http.Handler) http.Handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    defer func() {
      if err := recover(); err != nil {
        log.Printf("panic: %+v", err)
        http.Error(w, http.StatusText(500), 500)
      }
    }()
    next.ServeHTTP(w, r)
  }
	return http.HandlerFunc(fn)
}

func LoginMiddleware(h http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/app") {
      h.ServeHTTP(w, r)
    } else {
      session, err := store.Get(r, "session-name")
      if err != nil {
        rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
      }
      if _, ok := session.Values["AccessKey"]; ok {
        h.ServeHTTP(w, r)
      } else {
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
      }
    }
  })
}

func main() {
  // Read the config file
  configFile, err := ioutil.ReadFile("./config.json")
  if err != nil {
    log.Fatal("Can't open the configuration file: ", err)
  }
  /*
  configFile, err := Asset("config.json")
  if err != nil {
    log.Fatal("Can't open the configuration file: ", err)
  }
  */
  json.Unmarshal(configFile, &config)

  // To be compatible with Cloud Foundry
  var port = ""
  _, err = cfenv.Current()
  if(err != nil) {
    port = "80"
  } else {
    port = os.Getenv("PORT")
  }
  // See http://godoc.org/github.com/unrolled/render
  rendering = render.New(render.Options{Directory: "app/templates"})
  // See http://www.gorillatoolkit.org/pkg/mux
  router := mux.NewRouter()
  router.HandleFunc("/", Index)
  router.Handle("/api/v1/credentials", appHandler(Credentials)).Methods("GET")
  router.Handle("/api/v1/buckets", appHandler(ListBuckets)).Methods("GET")
  router.Handle("/api/v1/examples", appHandler(GetExamples)).Methods("GET")
  router.Handle("/api/v1/bucket", appHandler(CreateBucket)).Methods("POST")
  router.Handle("/api/v1/metadatasearch", appHandler(MetadataSearch)).Methods("POST")
  router.Handle("/api/v1/searchmetadata", appHandler(SearchMetadata)).Methods("POST")
  router.Handle("/api/v1/apis", appHandler(Apis)).Methods("POST")
  router.HandleFunc("/login", Login)
  router.HandleFunc("/logout", Logout)
  router.PathPrefix("/app/").Handler(http.StripPrefix("/app/", http.FileServer(http.Dir("app"))))
	n := negroni.Classic()
	n.UseHandler(RecoverHandler(LoginMiddleware(router)))
	n.Run(":" + port)
	log.Printf("Listening on port " + port)
}

// To parse GET /object/secret-keys output
type UserSecretKeysResult struct {
  XMLName xml.Name `xml:"user_secret_keys"`
  SecretKey1 string `xml:"secret_key_1"`
  SecretKey2 string `xml:"secret_key_2"`
}

type UserSecretKeyResult struct {
  XMLName xml.Name `xml:"user_secret_key"`
  SecretKey string `xml:"secret_key"`
}

// Login using an AD or object user
func Login(w http.ResponseWriter, r *http.Request) {
  // If informaton received from the form
  if r.Method == "POST" {
    session, err := store.Get(r, "session-name")
    if err != nil {
      rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
    }
    r.ParseForm()
    authentication := r.FormValue("authentication")
    user := r.FormValue("user")
    password := r.FormValue("password")
    endpoint := r.FormValue("endpoint")
    // For AD authentication, needs to retrieve the S3 secret key from ECS using the ECS management API
    if authentication == "ad" {
      url, err := url.Parse(endpoint)
      if err != nil{
          rendering.HTML(w, http.StatusOK, "login", "Check the endpoint")
      }
      hostname := url.Host
      if strings.Contains(hostname, ":") {
        hostname = strings.Split(hostname, ":")[0]
      }
      tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
      }
      client := &http.Client{Transport: tr}
      // Get an authentication token from ECS
      req, _ := http.NewRequest("GET", "https://" + hostname + ":4443/login", nil)
      req.SetBasicAuth(user, password)
      resp, err := client.Do(req)
      if err != nil{
          log.Print(err)
      }
      if resp.StatusCode == 401 {
        rendering.HTML(w, http.StatusOK, "login", "Check your crententials and that you're allowed to generate a secret key on ECS")
      } else {
        // Get the secret key from ECS
        req, _ = http.NewRequest("GET", "https://" + hostname + ":4443/object/secret-keys", nil)
        headers := map[string][]string{}
        headers["X-Sds-Auth-Token"] = []string{resp.Header.Get("X-Sds-Auth-Token")}
        req.Header = headers
        resp, err = client.Do(req)
        if err != nil{
            log.Print(err)
        }
        buf := new(bytes.Buffer)
        buf.ReadFrom(resp.Body)
        secretKey := ""
        userSecretKeysResult := &UserSecretKeysResult{}
        xml.NewDecoder(buf).Decode(userSecretKeysResult)
        secretKey = userSecretKeysResult.SecretKey1
        // If a secret key doesn't exist yet for this object user, needs to generate it
        if secretKey == "" {
          req, _ = http.NewRequest("POST", "https://" + hostname + ":4443/object/secret-keys", bytes.NewBufferString("<secret_key_create_param></secret_key_create_param>"))
          headers["Content-Type"] = []string{"application/xml"}
          req.Header = headers
          resp, err = client.Do(req)
          if err != nil{
              log.Print(err)
          }
          buf = new(bytes.Buffer)
          buf.ReadFrom(resp.Body)
          userSecretKeyResult := &UserSecretKeyResult{}
          xml.NewDecoder(buf).Decode(userSecretKeyResult)
          secretKey = userSecretKeyResult.SecretKey
        }
        session.Values["AccessKey"] = user
        session.Values["SecretKey"] = secretKey
        session.Values["Endpoint"] = endpoint
        err = sessions.Save(r, w)
        if err != nil {
          rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
        }
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
      }
    // For an object user authentication, use the credentials as-is
    } else {
      session.Values["AccessKey"] = user
      session.Values["SecretKey"] = password
      session.Values["Endpoint"] = endpoint
      err = sessions.Save(r, w)
      if err != nil {
        rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
      }
      http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
    }
  } else {
    rendering.HTML(w, http.StatusOK, "login", nil)
  }
}

// Logout
func Logout(w http.ResponseWriter, r *http.Request) {
  session, err := store.Get(r, "session-name")
  if err != nil {
    rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
  }
  delete(session.Values, "AccessKey")
  delete(session.Values, "SecretKey")
  delete(session.Values, "Endpoint")
  err = sessions.Save(r, w)
  http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Main page
func Index(w http.ResponseWriter, r *http.Request) {
  rendering.HTML(w, http.StatusOK, "index", nil)
}

// Returned an S3 struct to be used to execute S3 requests
func getS3(r *http.Request) (S3, error) {
  session, err := store.Get(r, "session-name")
  if err != nil {
    return S3{}, err
  }
  s3 := S3{
    EndPointString: session.Values["Endpoint"].(string),
    AccessKey: session.Values["AccessKey"].(string),
    SecretKey: session.Values["SecretKey"].(string),
    Namespace: "",
  }
  return s3, nil
}

type ECSBucket struct {
  Api string `json:"bucket_api"`
  Endpoint string `json:"bucket_endpoint"`
  User string `json:"bucket_user"`
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
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
    if bucketCreateResponse.Code == 200  {
      rendering.JSON(w, http.StatusOK, ecsBucket.Name)
    } else {
      return &appError{err: err, status: http.StatusInternalServerError, xml: bucketCreateResponse.Body}
    }
  } else if ecsBucket.Api == "swift" {
    bucketCreateResponse, err = swiftRequest(ecsBucket.Endpoint, ecsBucket.User, ecsBucket.Password, ecsBucket.Name, "PUT", "/", headers, "")
    log.Print(bucketCreateResponse)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
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
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
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

// Retrieve the examples loaded from the config.json file
func GetExamples(w http.ResponseWriter, r *http.Request) *appError {
  rendering.JSON(w, http.StatusOK, config.Examples)

  return nil
}

// Get the credentials for the object user
func Credentials(w http.ResponseWriter, r *http.Request) *appError {
  session, err := store.Get(r, "session-name")
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
  }
  rendering.JSON(w, http.StatusOK, struct {
    AccessKey string `json:"access-key"`
    SecretKey string `json:"secret-key"`
    Endpoint string `json:"endpoint"`
  } {
    AccessKey: session.Values["AccessKey"].(string),
    SecretKey: session.Values["SecretKey"].(string),
    Endpoint: session.Values["Endpoint"].(string),
  })

  return nil
}

type Query struct {
  Bucket string `json:"search_bucket"`
  Query string `json:"search_query"`
  MaxKeys string `json:"search_max_keys"`
  SortedBy string `json:"search_sorted_by"`
  ReturnAllMetadata bool `json:"search_return_all_metadata"`
  Marker string `json:"search_marker"`
}

// Execute the metadata search
func MetadataSearch(w http.ResponseWriter, r *http.Request) *appError {
  s3, err := getS3(r)
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
  }
  decoder := json.NewDecoder(r.Body)
  var query Query
  err = decoder.Decode(&query)
  if err != nil {
    return &appError{err: err, status: http.StatusBadRequest, json: "Can't decode JSON data"}
  }
  path := "/?query=" + strings.Replace(query.Query, "%20", " ", -1)
  if query.Marker != "" {
    path += "&marker=" + query.Marker
  }
  if query.MaxKeys != "" {
    path += "&max-keys=" + query.MaxKeys
  }
  if query.SortedBy != "" {
    path += "&sorted=" + query.SortedBy
  }
  if query.ReturnAllMetadata {
    path += "&attributes=ALL"
  }
  bucketQueryResponse, err := s3Request(s3, query.Bucket, "GET", path, make(map[string][]string), "")
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
  }
  if bucketQueryResponse.Code == 200 {
    bucketQueryResult := &BucketQueryResult{}
    xml.NewDecoder(strings.NewReader(bucketQueryResponse.Body)).Decode(bucketQueryResult)
    // Generate a shared URL for each object returned by the metadata search
    if len(bucketQueryResult.EntryLists) > 0 {
      expires := time.Now().Add(time.Second*24*3600)
      for i, item := range bucketQueryResult.EntryLists {
        if item.ObjectName[len(item.ObjectName)-1:] != "/" {
          headers := make(map[string][]string)
          preparedS3Request, _ := prepareS3Request(s3, query.Bucket, "GET", query.Bucket + "/" + item.ObjectName + "?Expires=" + strconv.FormatInt(expires.Unix(), 10), headers, true)
          values := url.Values{}
          values = preparedS3Request.Params
          bucketQueryResult.EntryLists[i].Url = strings.Split(preparedS3Request.Url, "?")[0] + "?" + values.Encode()
        }
      }
    }
    rendering.JSON(w, http.StatusOK, bucketQueryResult)
  } else {
    return &appError{err: err, status: http.StatusInternalServerError, xml: bucketQueryResponse.Body}
  }

  return nil
}

// Retrieve information about metadata indexed for a bucket
func SearchMetadata(w http.ResponseWriter, r *http.Request) *appError {
  s3, err := getS3(r)
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
  }
  decoder := json.NewDecoder(r.Body)
  var s map[string]string
  err = decoder.Decode(&s)
  if err != nil {
    return &appError{err: err, status: http.StatusBadRequest, json: "Can't decode JSON data"}
  }
  bucket := s["search_bucket"]
  bucketSearchMetadataResponse, err := s3Request(s3, bucket, "GET", "/?searchmetadata", make(map[string][]string), "")
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
  }
  bucketSearchMetadataResult := &BucketSearchMetadataResult{}
  xml.NewDecoder(strings.NewReader(bucketSearchMetadataResponse.Body)).Decode(bucketSearchMetadataResult)
  rendering.JSON(w, http.StatusOK, bucketSearchMetadataResult)

  return nil
}

type ApisQuery struct {
  Api string `json:"apis_api"`
  Endpoint string `json:"apis_endpoint"`
  User string `json:"apis_user"`
  Password string `json:"apis_password"`
  Bucket string `json:"apis_bucket"`
  Container string `json:"apis_container"`
  Subtenant string `json:"apis_subtenant"`
  Path string `json:"apis_path"`
  Range string `json:"apis_range"`
  Data string `json:"apis_data"`
  Method string `json:"apis_method"`
  Headers map[string][]string `json:"apis_headers"`
}

type HttpResponse struct {
  Method string `json:"method"`
  Path string `json:"path"`
  Code int `json:"code"`
  RequestHeaders map[string][]string `json:"request_headers"`
  ResponseHeaders map[string][]string `json:"response_headers"`
  Body string `json:"body"`
}

// Execute the API request
func Apis(w http.ResponseWriter, r *http.Request) *appError {
  decoder := json.NewDecoder(r.Body)
  var apisQuery ApisQuery
  err := decoder.Decode(&apisQuery)
  if err != nil {
    return &appError{err: err, status: http.StatusBadRequest, json: "Can't decode JSON data"}
  }
  headers := make(map[string][]string)
  if len(apisQuery.Headers) > 0 {
    headers = apisQuery.Headers
  }
  if apisQuery.Range != "" {
    headers["Range"] = []string{apisQuery.Range}
  }
  var response Response
  if apisQuery.Api == "s3" {
    s3, err := getS3(r)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
    response, err = s3Request(s3, apisQuery.Bucket, apisQuery.Method, apisQuery.Path, headers, apisQuery.Data)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
  } else if apisQuery.Api == "swift" {
    response, err = swiftRequest(apisQuery.Endpoint, apisQuery.User, apisQuery.Password, apisQuery.Container, apisQuery.Method, apisQuery.Path, headers, apisQuery.Data)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
  } else if apisQuery.Api == "atmos" {
    s3, err := getS3(r)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
    response, err = atmosRequest(apisQuery.Endpoint, s3.AccessKey, s3.SecretKey, apisQuery.Subtenant, apisQuery.Method, apisQuery.Path, headers, apisQuery.Data)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
  } else if apisQuery.Api == "ecs" {
    response, err = ecsRequest(apisQuery.Endpoint, apisQuery.User, apisQuery.Password, apisQuery.Method, apisQuery.Path, headers, apisQuery.Data)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
    }
  }
  var httpResponse HttpResponse
  httpResponse.Method = apisQuery.Method
  httpResponse.Path = apisQuery.Path
  httpResponse.Code = response.Code
  httpResponse.RequestHeaders = response.RequestHeaders
  httpResponse.ResponseHeaders = response.ResponseHeaders
  httpResponse.Body = response.Body
  rendering.JSON(w, http.StatusOK, httpResponse)

  return nil
}
