$(document).ready(function() {
  $('[data-toggle="tooltip"]').tooltip();
  $('[data-toggle="popover"]').popover();
});


if (!String.prototype.encodeHTML) {
  String.prototype.encodeHTML = function () {
    return this.replace(/&/g, '&amp;')
               .replace(/</g, '&lt;')
               .replace(/>/g, '&gt;')
               .replace(/"/g, '&quot;')
               .replace(/'/g, '&apos;');
  };
}

jQuery.expr[':'].regex = function(elem, index, match) {
    var matchParams = match[3].split(','),
        validLabels = /^(data|css):/,
        attr = {
            method: matchParams[0].match(validLabels) ?
                        matchParams[0].split(':')[0] : 'attr',
            property: matchParams.shift().replace(validLabels,'')
        },
        regexFlags = 'ig',
        regex = new RegExp(matchParams.join('').replace(/^s+|s+$/g,''), regexFlags);
    return regex.test(jQuery(elem)[attr.method](attr.property));
}

function formatXml(xml) {
    var formatted = '';
    var reg = /(>)(<)(\/*)/g;
    xml = xml.replace(reg, '$1\r\n$2$3');
    var pad = 0;
    jQuery.each(xml.split('\r\n'), function(index, node) {
        var indent = 0;
        if (node.match( /.+<\/\w[^>]*>$/ )) {
            indent = 0;
        } else if (node.match( /^<\/\w/ )) {
            if (pad != 0) {
                pad -= 1;
            }
        } else if (node.match( /^<\w[^>]*[^\/]>.*$/ )) {
            indent = 1;
        } else {
            indent = 0;
        }

        var padding = '';
        for (var i = 0; i < pad; i++) {
            padding += '  ';
        }

        formatted += padding + node + '\r\n';
        pad += indent;
    });

    return formatted;
}

(function() {
  var app = angular.module('ECSUI', ['ngAnimate', 'ngSanitize']);

  app.value('loadingService', {
    loadingCount: 0,
    isLoading: function() { return loadingCount > 0; },
    requested: function() { loadingCount += 1; },
    responded: function() { loadingCount -= 1; }
  });

  app.factory('loadingInterceptor', ['$q', 'loadingService', function($q, loadingService) {
    return {
      request: function(config) {
        loadingService.requested();
        return config;
      },
      response: function(response) {
        loadingService.responded();
        return response;
      },
      responseError: function(rejection) {
        loadingService.responded();
        return $q.reject(rejection);
      },
    }
  }]);

  app.config(["$httpProvider", function ($httpProvider) {
    $httpProvider.interceptors.push('loadingInterceptor');
  }]);

  app.controller('MainController', ['$http', '$animate', '$scope', 'loadingService', 'mainService', function($http, $animate, $scope, loadingService, mainService) {
    $scope.main = mainService;
    loadingCount = 0;
    $scope.loadingService = loadingService;
    $scope.main.buckets = [];
    $scope.main.examples = {};
    $scope.main.credentials = {};
    $scope.main.metadata = {};
    $scope.main.metadata.markers = [];
    $scope.main.apis = {};
    $scope.main.apis.headers = {};
    $scope.main.apis.response = {};
    $scope.main.swiftextensions = {};
    $scope.main.swiftextensions.headers = {};
    $scope.main.swiftextensions.response = {};
    $scope.main.menu = "";
    $scope.main.api = "";
    $http.get('/api/v1/buckets').success(function(data) {
      $scope.main.buckets = data;
    }).
    error(function(data, status, headers, config) {
      $scope.main.messagetitle = "Error";
      $scope.main.messagebody = data;
      $('#message').modal('show');
    });
    $http.get('/api/v1/examples').success(function(data) {
      $scope.main.examples = data;
    }).
    error(function(data, status, headers, config) {
      $scope.main.messagetitle = "Error";
      $scope.main.messagebody = data;
      $('#message').modal('show');
    });
    $http.get('/api/v1/credentials').success(function(data) {
      $scope.main.credentials = data;
    }).
    error(function(data, status, headers, config) {
      $scope.main.messagetitle = "Error";
      $scope.main.messagebody = data;
      $('#message').modal('show');
    });
  }]);

  app.factory('mainService', function() {
    return {}
  });

  app.directive("mainMenu", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-menu.html"
    };
  });

  app.directive("mainMessage", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-message.html"
    };
  });

  app.directive("mainCredentials", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-credentials.html"
    };
  });

  app.directive("mainBucket", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-bucket.html",
      controller: ['$http', '$scope', 'mainService', function($http, $scope, mainService) {
        this.create = function(api) {
          $http.post('/api/v1/bucket', {
            bucket_api: api,
            bucket_endpoint: this.bucket_endpoint,
            bucket_user: this.bucket_user,
            bucket_password: this.bucket_password,
            bucket_name: this.bucket_name,
            bucket_replication_group: this.bucket_replication_group,
            bucket_metadata_search: this.bucket_metadata_search,
            bucket_enable_ado: this.bucket_enable_ado,
            bucket_enable_fs: this.bucket_enable_fs,
            bucket_enable_compliance: this.bucket_enable_compliance,
            bucket_enable_encryption: this.bucket_enable_encryption
          }).
            success(function(data, status, headers, config) {
              $scope.main.messagetitle = "Success";
              $scope.main.messagebody = "Bucket/container/subtenant " + data + " created";
              $('#message').modal({show: true});
              $http.get('/api/v1/buckets').success(function(data) {
                $scope.main.buckets = data;
              }).
              error(function(data, status, headers, config) {
                $scope.main.messagetitle = "Error";
                $scope.main.messagebody = data;
                $('#message').modal('show');
              });
            }).
            error(function(data, status, headers, config) {
              $scope.main.result = [];
              $scope.main.messagetitle = "Error";
              $scope.main.messagebody = data;
              $('#message').modal({show: true});
            });
        };
      }],
      controllerAs: "bucketCtrl"
    };
  });

  app.directive("mainMetadataSearch", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-metadata-search.html",
      controller: ['$http', '$scope', 'mainService', function($http, $scope, mainService) {
        this.search = function(marker) {
          if(marker) {
            $scope.main.metadata.markers.push(marker);
          } else {
            $scope.main.metadata.markers = [];
          }
          $http.post('/api/v1/metadatasearch', {
            search_bucket: this.search_bucket,
            search_query: this.search_query.replace(/ /g, "%20"),
            search_max_keys: this.search_max_keys,
            search_sorted_by: this.search_sorted_by,
            search_return_all_metadata: this.search_return_all_metadata,
            search_marker: marker
          }).
            success(function(data, status, headers, config) {
              $scope.main.metadata.result = data;
            }).
            error(function(data, status, headers, config) {
              $scope.main.metadata.result = [];
              $scope.main.messagetitle = "Error";
              $scope.main.messagebody = data;
              $('#message').modal({show: true});
            });
        };
        this.getMetadata = function() {
          $http.post('/api/v1/searchmetadata', {
            search_bucket: this.search_bucket
          }).
            success(function(data, status, headers, config) {
              $scope.main.searchmetadata = data;
            }).
            error(function(data, status, headers, config) {
              $scope.main.searchmetadata = [];
              $scope.main.messagetitle = "Error";
              $scope.main.messagebody = data;
              $('#message').modal({show: true});
            });
        };
      }],
      controllerAs: "metadataSearchCtrl"
    };
  });

  app.directive("mainMetadataResult", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-metadata-result.html"
    };
  });

  app.directive("mainApis", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-apis.html",
      controller: ['$http', '$scope', 'mainService', function($http, $scope, mainService) {
        this.apis_method = "GET";
        this.execute = function(api) {
          $scope.main.apis.response = {};
          var customHeaders = {};
          for (var key in $scope.main.apis.headers) {
            customHeaders[key] = [$("#apis_header_" + key).val()];
          }
          $http.post('/api/v1/apis', {
            apis_api: api,
            apis_endpoint: this.apis_endpoint,
            apis_user: this.apis_user,
            apis_password: this.apis_password,
            apis_bucket: this.apis_bucket,
            apis_container: this.apis_container,
            apis_subtenant: this.apis_subtenant,
            apis_path: this.apis_path,
            apis_range: this.apis_range,
            apis_data: this.apis_data,
            apis_method: this.apis_method,
            apis_headers: customHeaders
          }).
            success(function(data, status, headers, config) {
              $scope.main.apis.response = data;
              $scope.main.apis.response["body"] = "<pre><code>" + formatXml($scope.main.apis.response["body"]).encodeHTML() + "</code></pre>";
            }).
            error(function(data, status, headers, config) {
              $scope.main.messagetitle = "Error";
              $scope.main.messagebody = data;
              $('#message').modal({show: true});
            });
        };
        this.addHeader = function() {
          $scope.main.apis.headers[this.apis_custom_header] = "";
        };
        this.removeHeader = function() {
          delete $scope.main.apis.headers[this.apis_custom_header];
        };
        this.executeStep = function(i, j, api, execute) {
          //$('html, body').animate({scrollTop: $('#apis_request')}, 100);
          $scope.main.apis.response = {};
          var customHeaders = {};
          var expectedResponseCode = $("input[id^='api_examples_expected_response_code_" + i + "_" + j + "']").val();
          var responseCodeButton = $("#api_examples_response_code_" + i + "_" + j);
          responseCodeButton.removeClass("btn-success").removeClass("btn-danger");
          responseCodeButton.html("-");
          $("input[id^='api_examples_header_key_" + i + "_" + j + "']").each (function() {
            var key = $(this).val();
            var k = $(this).attr('id').substr($(this).attr('id').length - 1);
            var value = $("input[id^='api_examples_header_value_" + i + "_" + j + "_" + k + "']").val();
            customHeaders[key] = [value];
          });
          elements = {};
          elementsKeys = ["apis_container", "apis_subtenant", "api_examples_path_" + i + "_" + j, "api_examples_range_" + i + "_" + j, "api_examples_data_" + i + "_" + j]
          for(var l = 0; l < elementsKeys.length; l++) {
            elements[elementsKeys[l]] = $("#" + elementsKeys[l]).val();
          }
          var headersInput = $("input[id^='api_examples_header_key_" + i + "_" + j + "']");
          $("span[id^='api_examples_input_key_" + i + "_" + j + "']").each (function() {
            var inputKey = $(this).html();
            var inputK = $(this).attr('id').substr($(this).attr('id').length - 1);
            var inputValue = $("#api_examples_input_" + i + "_" + j + "_" + inputK).val();
            if(inputValue != "") {
              var regExp = new RegExp("X{3}" + inputKey + "X{3}","gm");
              for(var l = 0; l < elementsKeys.length; l++) {
                if($("#" + elementsKeys[l]).val()) {
                  elements[elementsKeys[l]] = elements[elementsKeys[l]].replace(regExp, inputValue);
                }
              }
              Object.keys(customHeaders).forEach(function (key) {
                customHeaders[key][0] = customHeaders[key][0].replace(regExp, inputValue);
              });
            }
          });
          if(execute) {
            $http.post('/api/v1/apis', {
              apis_api: api,
              apis_endpoint: $("#apis_endpoint").val(),
              apis_user: $("#apis_user").val(),
              apis_password: $("#apis_password").val(),
              apis_bucket: $("#apis_bucket").val(),
              apis_container: elements["apis_container"],
              apis_subtenant: elements["apis_subtenant"],
              apis_path: elements["api_examples_path_" + i + "_" + j],
              apis_range: elements["api_examples_range_" + i + "_" + j],
              apis_data: elements["api_examples_data_" + i + "_" + j],
              apis_method: $("#api_examples_method_" + i + "_" + j).val(),
              apis_headers: customHeaders
            }).
              success(function(data, status, headers, config) {
                $scope.main.apis.response = data;
                $scope.main.apis.response["body"] = "<pre><code>" + formatXml($scope.main.apis.response["body"]).encodeHTML() + "</code></pre>";
                if($scope.main.apis.response["code"] == expectedResponseCode) {
                  responseCodeButton.addClass("btn-success");
                } else {
                  responseCodeButton.addClass("btn-danger");
                }
                responseCodeButton.attr('data-content', formatXml($scope.main.apis.response["body"]).encodeHTML());
                responseCodeButton.html($scope.main.apis.response["code"]);
                //$('html, body').animate({scrollTop: $('#apis_request')}, 100);
              }).
              error(function(data, status, headers, config) {
                $scope.main.messagetitle = "Error";
                $scope.main.messagebody = data;
                $('#message').modal({show: true});
              });
          } else {
            $scope.main.messagetitle = "CLI";
            login = "";
            body = "";
            cli = "";
            if(api == "s3") {
              cli = "perl s3curl.pl --id=ecs_profile -- -X " + $("#api_examples_method_" + i + "_" + j).val();
            } else if((api == "ecs" || api =="swift")) {
              cli = "curl -k -X " + $("#api_examples_method_" + i + "_" + j).val();
            }
            if(elements["api_examples_data_" + i + "_" + j]) {
              body += `
                Create a file called data.txt with the following content:
                <ul class="list-group">
                  <li class="list-group-item">
                    ` + elements["api_examples_data_" + i + "_" + j].replace(/\n/, "<br />") + `
                  </li>
                </ul>
              `;
              cli += " -d @data.txt"
            }
            if(elements["api_examples_range_" + i + "_" + j] != "") {
              cli += " -H 'Range:" + elements["api_examples_range_" + i + "_" + j] + "'";
            }
            Object.keys(customHeaders).forEach(function (key) {
              cli += " -H '" + key + ":" + customHeaders[key][0] + "'";
            });
            if(api == "s3") {
              login += `
              Create a file .s3curl with 0600 permissions and the following conntent:
              <ul class="list-group">
                <li class="list-group-item">
                  %awsSecretAccessKeys = (<br />
                    ecs_profile => {<br />
                      id => '` + $scope.main.credentials['access-key'] + `',<br />
                      key => '` + $scope.main.credentials['secret-key'] + `'<br />
                    },<br />
                    @endpoints = ('` + $scope.main.credentials['endpoint'].split('/')[2].split(':')[0] + `', )
                  );
                </li>
              </ul>
              `;
              if($("#apis_bucket").val() == "") {
                cli += " -vv '" + $scope.main.credentials['endpoint'] + elements["api_examples_path_" + i + "_" + j] + "'";
              } else {
                cli += " -vv '" + $scope.main.credentials['endpoint'] + "/" + $("#apis_bucket").val() + elements["api_examples_path_" + i + "_" + j] + "'";
              }
            } else if(api == "swift") {
              login = `
                Execute the following commands to login:
                <ul class="list-group">
                  <li class="list-group-item">
                    export TOKEN=\`curl -s -k -i -H 'X-Auth-User:` + $("#apis_user").val() + `' -H 'X-Auth-Key:` + $("#apis_password").val() + `' ` + $("#apis_endpoint").val() + `/auth/v1.0 | grep -i X-Auth-Token | awk '{ print $2 }' | sed 's/^M//g'\`<br />
                    export STORAGEURL=\`curl -s -k -i -H 'X-Auth-User:` + $("#apis_user").val() + `' -H 'X-Auth-Key:` + $("#apis_password").val() + `' ` + $("#apis_endpoint").val() + `/auth/v1.0 | grep -i X-Storage-Url | awk '{ print $2 }' | sed 's/^M//g'\`
                  </li>
                </ul>
              `
              cli += " -H X-Auth-Token:$TOKEN $STORAGEURL" + elements["api_examples_path_" + i + "_" + j];
            } else if(api == "ecs") {
              login = `
                Execute the following command to login:
                <ul class="list-group">
                  <li class="list-group-item">
                    export TOKEN=\`curl -s -k -i -u ` + $("#apis_user").val() + `:` + $("#apis_password").val() + ` ` + $("#apis_endpoint").val() + `/login 2>&1 | grep -i X-Sds-Auth-Token | awk '{ print $2 }' | sed 's/^M//g'\`
                  </li>
                </ul>
              `
              cli += " -H \"X-SDS-AUTH-TOKEN:$TOKEN\" " + $("#apis_endpoint").val() + elements["api_examples_path_" + i + "_" + j] + " | xmllint --format -";
            }
            $scope.main.messagebody = login + body + `
              Then, run the following command:
              <ul class="list-group">
                <li class="list-group-item">
                  ` + cli + `
                </li>
              </ul>
            `;
            $('#message').modal({show: true});
          }
        };
        this.showResponse = function() {
          if($scope.main.apis.response['response_headers']) {
            $scope.main.messagetitle = "Response";
            //$scope.main.messagebody = "<pre><code>" + formatXml($scope.main.apis.response["body"]).encodeHTML() + "</code></pre>";;
            var content = `
            <h2>Response headers</h2>
            <table class="table">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
            `;
            Object.keys($scope.main.apis.response["response_headers"]).forEach (function(key) {
              content += "<tr><td>" + key + "</td>";
              content += "<td>" + $scope.main.apis.response["response_headers"][key][0] + "</td></tr>";
            });
            content += `
              </tbody>
            </table>
            <h2>Response body</h2>
            `;
            content += `<div class="wordbreak">` + formatXml($scope.main.apis.response["body"]) + `</div>`;
            $scope.main.messagebody = content;
            $('#message').modal({show: true});
          }
        };
      }],
      controllerAs: "apisCtrl"
    };
  });

  app.directive("mainApisExamples", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-apis-examples.html"
    };
  });

  app.directive("mainApisRequest", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-apis-request.html"
    };
  });

  app.directive("mainApisResponse", function() {
    return {
      restrict: 'E',
      templateUrl: "app/html/main-apis-response.html"
    };
  });

})();
