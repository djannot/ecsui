FROM google/golang
WORKDIR /go/src
RUN git clone https://djannot:f1f5cd1cc5370c2a935d843e92863a82ccad4c15@github.com/djannot/ecsui.git
WORKDIR /go/src/ecsui
RUN go get "github.com/cloudfoundry-community/go-cfenv"
RUN go get "github.com/codegangsta/negroni"
RUN go get "github.com/gorilla/mux"
RUN go get "github.com/gorilla/sessions"
RUN go get "github.com/unrolled/render"
RUN go build .
