ECSUI
==============



OVERVIEW
--------------

ECSUI is a web application developped in Golang and leveraging AngularJS

The goals of ECSUI are to:

- demonstrate some nice S3 features (versioning, lifecycle policy, …) and several unique ECS capabilities using either S3 or Swift (byte range, retentions, metadata search, …)
- simplify the usage of several REST APIs (S3, Swift, Atmos, ECS)
- provide a simple UI for the ECS metadata search features

More capabilities will be added in the future

BUILD
--------------

The Dockerfile can be used to create a Docker container for this web application.

Just run the following command in the folder that contains the Dockerfile: docker build -t ecsui .

RUN
--------------

To start the application, run:
docker run -p 8080:80 ecsui

The application will be available on http://\<ip of application host\>

LICENSING
--------------

Licensed under the Apache License, Version 2.0 (the “License”); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
