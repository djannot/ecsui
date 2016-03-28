/*
$(document).ready(function() {

});
*/

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
    $scope.main.credentials = {};
    $scope.main.metadata ={};
    $scope.main.metadata.markers = [];
    $scope.main.menu = "";
    $http.get('/api/v1/buckets').success(function(data) {
      $scope.main.buckets = data;
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
        this.create = function() {
          $http.post('/api/v1/bucket', {
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
              $scope.main.messagebody = "Bucket created";
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

})();
