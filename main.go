package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	daemon := flag.Bool("daemon", false, "Set to true do run in daemon mode. The certificate will be automatically renewed 30 days before it expires, and the corresponding .key and .crt file will be updated .")

	userFolder := flag.String("userFolder", "", "specify the full path of where to store the key and certificate")
	domain := flag.String("domain", "", "the domain name to create a certificate for")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, TLS user! Your config: %+v", r.TLS)
	})

	// Check if the folder for where to store the certificate
	// exist, if not exist create it.
	certDir := path.Join(*userFolder, *domain)
	_, err := os.Stat(certDir)
	if err != nil {
		err := os.MkdirAll(certDir, 0700)
		if err != nil {
			log.Printf("error: os.MkdirAll: %v\n", err)
			return
		}
	}

	// --- Prepare and start the web http and https servers.

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*domain),
		Cache:      autocert.DirCache(certDir),
	}

	server := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	go func() {
		h := certManager.HTTPHandler(nil)
		log.Fatal(http.ListenAndServe(":http", h))
	}()

	go func() {
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			log.Printf("error: ListenAndServe: %v\n", err)
			return
		}
	}()

	// --- Start up a client session to initiate the creation of the certificate.

	client := http.Client{
		Timeout: time.Second * 30,
	}

	url := fmt.Sprintf("https://%v", *domain)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("error: http.NewRequest: %v\n", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("error: client.Do: %v\n", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		if err != nil {
			log.Printf("error: http.StatusCode not 200: %v\n", err)
			return
		}
	}

	// --- Check and create crt/key files if LE file is created.

	// The cert+key are stored in a file named by the domain.
	certRealPath := path.Join(certDir, *domain)

	// Start checking that if an actual certificate have been
	// created or updated, and give notification on the file
	// updated when occured.
	fileUpdated := make(chan bool, 1)
	go checkFileUpdated(certRealPath, fileUpdated)

	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	for {
		select {
		case <-fileUpdated:
			fmt.Println(" * Debug: case updated")
			err := handleCertFiles(certRealPath)
			if err != nil {
				log.Printf("error: handleCertFiles:%v\n", err)
				os.Exit(1)
			}
		case <-sigCh:
			log.Printf("info: received signal to quit..\n")
			return
		}

		if !*daemon {
			break
		}
	}

}

// handleCertFiles will create the crt and key files based on
// the certificate received from LetsEncrypt.
func handleCertFiles(certRealPath string) error {
	// Open key+cert file for reading
	fhKeyCert, err := os.Open(certRealPath)
	if err != nil {
		return fmt.Errorf("error: failed to open cert file for reading: %v", err)
	}
	defer fhKeyCert.Close()

	// Create cert file for writing to.
	fhCert, err := os.OpenFile(certRealPath+".crt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error: failed to open key file for writing: %v", err)
	}
	defer fhCert.Close()

	// Create key file for writing to.
	fhKey, err := os.OpenFile(certRealPath+".key", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error: failed to open key file for writing: %v", err)
	}
	defer fhKey.Close()

	scanner := bufio.NewScanner(fhKeyCert)

	for scanner.Scan() {

		// Find Key, and write it to file.
		if strings.Contains(scanner.Text(), "BEGIN EC PRIVATE KEY") {

			_, err = fhKey.WriteString(scanner.Text() + "\n")
			if err != nil {
				return fmt.Errorf("error: failed to write key file: %v", err)
			}

			for scanner.Scan() {
				_, err := fhKey.WriteString(scanner.Text() + "\n")
				if err != nil {
					return fmt.Errorf("error: failed to write key file: %v", err)
				}

				if strings.Contains(scanner.Text(), "END EC PRIVATE KEY") {
					// Advance one scanner position, for the beginning of the cert
					scanner.Scan()
					break
				}
			}
		}

		// Find certs, and write them to file.
		if strings.Contains(scanner.Text(), "BEGIN CERTIFICATE") {

			_, err = fhCert.WriteString(scanner.Text() + "\n")
			if err != nil {
				return fmt.Errorf("error: failed to write cert file: %v", err)
			}

			for scanner.Scan() {
				_, err := fhCert.WriteString(scanner.Text() + "\n")
				if err != nil {
					return fmt.Errorf("error: failed to write cert file: %v", err)
				}

				if strings.Contains(scanner.Text(), "END CERTIFICATE") {
					// Advance one scanner position, for the beginning of the cert
					// scanner.Scan()
					break
				}
			}
		}

	}

	return nil
}

func checkFileUpdated(certRealPath string, fileUpdated chan bool) {

	err := waitUntilFind(certRealPath)
	if err != nil {
		log.Printf("error: waitUntilFind failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(" * cert file from lets encrypt found")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed fsnotify.NewWatcher %v\n", err)
		return
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		//Give a true value to updated so it reads the file the first time.
		fileUpdated <- true
		for {
			select {
			case event := <-watcher.Events:
				log.Printf("event: %v\n", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println(" * checkFileUpdated: modified file:", event.Name)
					//testing with an update chan to get updates
					fileUpdated <- true
				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(certRealPath)
	if err != nil {
		log.Fatalf("checkFileUpdated: watcher.Add: %v\n", err)
		os.Exit(1)
	}

	<-done
}

// Check that the file exists, if not wait a second
// and check again until found.
func waitUntilFind(filename string) error {
	for {
		time.Sleep(1 * time.Second)
		_, err := os.Stat(filename)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			} else {
				return err
			}
		}
		break
	}
	return nil
}
