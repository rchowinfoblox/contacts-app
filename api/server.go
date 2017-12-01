package main

import (
        "crypto/tls"
        "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/infobloxopen/themis/pdp"
	"github.com/infobloxopen/themis/pep"
	pdpsvc "github.com/infobloxopen/themis/pdp-service"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

type ContactServer struct {
	verbose bool
	path	string
	db      *gorm.DB
	pepClnt pep.Client
	server  *http.Server
}

func NewContactServer(verbose bool, dsn, pdp, path string) (*ContactServer, error) {
	s := &ContactServer{verbose: verbose, path: path}
	db, err := gorm.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	pdpServers := []string{pdp}
	pepOpts := []pep.Option{}
	pepOpts = append(pepOpts, pep.WithRoundRobinBalancer(pdpServers...),)
        pepClient := pep.NewClient(pepOpts...)
        err = pepClient.Connect(pdpServers[0])
        if err != nil {
                return nil, fmt.Errorf("can't connect to pdp %s: %s", pdpServers[0], err)
        }
	fmt.Printf("Successfully connected to pdp %s\n", pdpServers[0])
        s.pepClnt = pepClient
        //defer pepClient.Close()

	// Migrate the schema
	db.AutoMigrate(&Contact{})

	s.db = db
	return s, nil
}

func (s *ContactServer) Serve(addr, certPath, keyPath, caPath string) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, func(w http.ResponseWriter, r *http.Request) {
		s.handleContacts(w, r)
	})
	mux.HandleFunc(s.path+"/", func(w http.ResponseWriter, r *http.Request) {
		s.handleContacts(w, r)
	})

	s.server = &http.Server{Addr: addr, Handler: mux}
	if certPath != "" && keyPath != "" {
		fmt.Printf("Creating TLS config from cert %q, key %q, ca %q\n", certPath, keyPath, caPath)
        	cfg, err := newTLSConfig(certPath, keyPath, caPath)
		if err != nil {
			panic(err)
		}
        	s.server.TLSConfig = cfg
	}
	
	if s.server.TLSConfig == nil {
		fmt.Printf("Serving HTTP on %s\n", addr);
		return s.server.ListenAndServe()
	} else {
		fmt.Printf("Serving HTTPS on %s\n", addr);
		return s.server.ListenAndServeTLS("","")
	}

}

func (s *ContactServer) writeError(w http.ResponseWriter, err error) {
	s.writeErrorStatus(w, err, http.StatusBadRequest)
}

func (s *ContactServer) writeErrorStatus(w http.ResponseWriter, err error, status int) {
        j, _ := json.Marshal(err.Error())
	w.WriteHeader(status)
	io.WriteString(w, `{"error":`)
	w.Write(j)
	io.WriteString(w, `}\n`)
}

func (s *ContactServer) writePayload(w http.ResponseWriter, payload interface{}) {
        j, err := json.Marshal(payload)
	if err != nil {
		s.writeErrorStatus(w, err, http.StatusInternalServerError)
		return
	}
	w.Write(j)
}

func ToResponseString(r *pdpsvc.Response) string {
	lines := []string{fmt.Sprintf("- effect: %s", r.Effect.String())}
	if len(r.Reason) > 0 {
		lines = append(lines, fmt.Sprintf("  reason: %q", r.Reason))
	}

	if len(r.Obligation) > 0 {
		lines = append(lines, "  obligation:")
		for _, attr := range r.Obligation {
			lines = append(lines, fmt.Sprintf("    - id: %q", attr.Id))
			lines = append(lines, fmt.Sprintf("      type: %q", attr.Type))
			lines = append(lines, fmt.Sprintf("      value: %q", attr.Value))
			lines = append(lines, "")
		}
	} else {
		lines = append(lines, "")
	}

	result := strings.Join(lines, "\n")
	return result
}

func (s *ContactServer) handleContacts(w http.ResponseWriter, r *http.Request) {
	// Need to read request body before calling ParseForm(),
	// otherwise ParseForm() will read and parse body
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, fmt.Errorf("ioutil.ReadAll error: %s", err))
		return
	}

	user := ""
	if authzList, existsFlag := r.Header["Authorization"]; existsFlag {
		if len(authzList) > 0 {
			basicList := strings.Split(authzList[0], " ")
			if len(basicList) == 2 && basicList[0] == "Basic" {
				userBytes, err := base64.URLEncoding.DecodeString(basicList[1])
				if err != nil {
					s.writeError(w, fmt.Errorf("base64.URLEncoding.DecodeString error: %s", err))
					return
				}
				userPass := strings.Split(string(userBytes), ":")
				if len(userPass) == 2 {
					user = userPass[0]
					pass := userPass[1]
					fmt.Printf("Auth header: user=%s pass=%s\n", user, pass)
				}
			}
		}
	}

	fmt.Printf("r.RequestURI=%v\n", r.RequestURI);
	err = r.ParseForm()
	if err != nil {
		s.writeError(w, fmt.Errorf("r.ParseForm error: %s", err))
		return
	}
	fmt.Printf("r.Header=%v\n", r.Header);
	fmt.Printf("r.Form=%v\n", r.Form);
	fmt.Printf("r.PostForm=%v\n", r.PostForm);

	if len(user) == 0 {
		user = "unknownuser"
		if userList, existsFlag := r.Form["user"]; existsFlag {
			if len(userList) > 0 {
				user = userList[0]
				fmt.Printf("url parm: user=%s\n", user)
			}
		}
	}

	operation := "write"
	if r.Method == http.MethodGet {
		operation = "read"
	}

	pdpAttrs := []*pdpsvc.Attribute{
		&pdpsvc.Attribute{
			Id:    "user",
			Type:  pdp.TypeKeys[pdp.TypeString],
			Value: user,
		},
		&pdpsvc.Attribute{
			Id:    "operation",
			Type:  pdp.TypeKeys[pdp.TypeString],
			Value: operation,
		},
	}
	pdpReq := pdpsvc.Request{Attributes: pdpAttrs}
	pdpResp := pdpsvc.Response{}
	err = s.pepClnt.Validate(pdpReq, &pdpResp)
	if err != nil {
		s.writeError(w, fmt.Errorf("pepClnt.Validate error: %s", err))
		return
	}
	if pdpResp.Effect != pdpsvc.Response_PERMIT {
		s.writeError(w, fmt.Errorf("No permission: %s", ToResponseString(&pdpResp)))
		return
	}

	switch m := r.Method; m {
	case http.MethodGet:
		s.handleContactsGet(w,r, requestBody)
	case http.MethodPost:
		s.handleContactsPost(w,r, requestBody)
	case http.MethodPut:
		s.handleContactsPut(w,r, requestBody)
	case http.MethodDelete:
		s.handleContactsDelete(w,r, requestBody)
	default:
		s.writeError(w, fmt.Errorf("Unhandled method %q", m))
	}
}

func (s *ContactServer) idFromPath(urlPath string) (int, error) {
	tail := strings.TrimPrefix(strings.TrimPrefix(urlPath, s.path), "/")
	fmt.Printf("idFromPath tail=%s\n", tail);
	id, err := strconv.Atoi(tail)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *ContactServer) handleContactsGet(w http.ResponseWriter, r *http.Request, b []byte) {
	payload := make(map[string]interface{})

	if r.URL.Path == s.path {
		var contacts []Contact
		if err := s.db.Find(&contacts).Error; err != nil {
			s.writeError(w, err)
			return
		}
		payload["contacts"] = &contacts
		s.writePayload(w, payload)
		return
	}

	id, err := s.idFromPath(r.URL.Path)
	if err != nil {
		s.writeError(w, fmt.Errorf("Could not get ID from %q", r.URL.Path))
		return
	}
	
	var contact Contact
	if err := s.db.Find(&contact, id).Error; err != nil {
		s.writeError(w, err)
		return
	}
	payload["contacts"] = &[]Contact{contact}
	s.writePayload(w, payload)
}

func (s *ContactServer) handleContactsPost(w http.ResponseWriter, r *http.Request, b []byte) {
	s.handleContactsPut(w,r,b)
}

func (s *ContactServer) handleContactsPut(w http.ResponseWriter, r *http.Request, b []byte) {
	var c Contact
	//b, err := ioutil.ReadAll(r.Body)
	//if err != nil {
	//	s.writeError(w, fmt.Errorf("ioutil.ReadAll error: %s", err))
	//	return
	//}

	fmt.Printf("handleContactsPut b=%s\n", b)
	err := json.Unmarshal(b, &c)
	if err != nil {
		s.writeError(w, fmt.Errorf("json.Unmarshal error: %s", err))
		return
	}

	if err:= s.db.Create(&c).Error; err != nil {
		s.writeError(w, fmt.Errorf("db.Create error: %s", err))
	}
	return
}

func (s *ContactServer) handleContactsDelete(w http.ResponseWriter, r *http.Request, b []byte) {
	id, err := s.idFromPath(r.URL.Path)
	if err != nil {
		s.writeError(w, fmt.Errorf("Could not get ID from %q", r.URL.Path))
		return
	}
	if err:= s.db.Delete(id).Error; err != nil {
		s.writeError(w, err)
	}
	return
}

func newTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
        cert, err := tls.LoadX509KeyPair(certPath, keyPath)
        if err != nil {
                return nil, fmt.Errorf("Could not load TLS cert: %s", err)
        }

        roots, err := loadRoots(caPath)
        if err != nil {
                return nil, err
        }
	
        return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots}, nil
}

func loadRoots(caPath string) (*x509.CertPool, error) {
        if caPath == "" {
                return nil, nil
        }

        roots := x509.NewCertPool()
        pem, err := ioutil.ReadFile(caPath)
        if err != nil {
                return nil, fmt.Errorf("Error reading %s: %s", caPath, err)
        }
        ok := roots.AppendCertsFromPEM(pem)
        if !ok {
                return nil, fmt.Errorf("Could not read root certs: %s", err)
        }
        return roots, nil
}
