FROM google/golang
WORKDIR /go/src
RUN git clone https://djannot:042bebfd8bdb7b0c0b905a899f24f29eb75d4e2d@github.com/djannot/ecsui.git
WORKDIR /go/src/ecsui
RUN go get "github.com/cloudfoundry-community/go-cfenv"
RUN go get "github.com/codegangsta/negroni"
RUN go get "github.com/gorilla/mux"
RUN go get "github.com/gorilla/sessions"
RUN go get "github.com/unrolled/render"
RUN go build .
