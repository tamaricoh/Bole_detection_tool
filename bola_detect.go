package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Req       Req    `json:"req"`
	Rsp       Rsp    `json:"rsp"`
}

type Req struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	QSParams   string `json:"qs_params"`
	Headers    string `json:"headers"`
	ReqBodyLen int    `json:"req_body_len"`
	UserID     int    `json:"user_id"`
}

type Rsp struct {
	StatusCode   int   `json:"status_code"`
	StatusClass string `json:"status_class"`
	RspBodyLen  int    `json:"rsp_body_len"`
}

var (
	registerUsersCounter      int
	registerAdminsCounter     int
)

func detectBolaAttacks(logFilePath string) error {
	logData, err := os.Open(logFilePath)
	if err != nil {
		return fmt.Errorf("could not read log file: %v", err)
	}
	defer logData.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(logData)
	
	// Parse the log file into structured log entries
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 {
            spaceIndex1 := strings.Index(line, " ")
            if spaceIndex1 != -1 {
                // Look for the second space after the first space
                spaceIndex2 := strings.Index(line[spaceIndex1+1:], " ")
                if spaceIndex2 != -1 {
                    // Remove both the timestamp and everything up to the second space
                    line = line[spaceIndex1+spaceIndex2+2:] // Add 2 to account for the spaces
                }
            }
        }

		if len(line) > 0 && line[0] == '{' { // Check if the line looks like JSON
			var logEntry LogEntry
			err := json.Unmarshal([]byte(line), &logEntry)
			if err != nil {
				log.Printf("Error unmarshaling log entry: %v", err)
				continue
			}
			logs = append(logs, logEntry)
		}
	}
	
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	fmt.Println("Number of parsed logs:", len(logs))
	
	for _, logEntry := range logs {
		urlStr := logEntry.Req.URL
		// authHeader := logEntry.Req.Headers
	
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			fmt.Printf("Error parsing URL: %v\n", err)
			continue
		}
	
		if strings.Contains(parsedURL.Path, "/balance") {
			handleBalance(logEntry, parsedURL)
		}

		if parsedURL.Path == "/getusers" || parsedURL.Path == "/accounts" {
			handleAdminAccess(logEntry, parsedURL)
		}
	}

	return nil
}

func handleAdminAccess(logEntry LogEntry, parsedURL *url.URL) {
	if logEntry.Rsp.StatusCode == 403 {
		fmt.Printf("Unauthorized access attempt: request type: %s, endpoint: %s. A regular user is trying to perform admin actions.\n", logEntry.Req.Method, parsedURL.Path)
	}
}

func handleBalance(logEntry LogEntry, parsedURL *url.URL) {
	queryParams := parsedURL.Query()
	userID := queryParams.Get("user_id")
	if logEntry.Rsp.StatusCode == 403 {
		if userID != "" {
			fmt.Printf("Unauthorized access attempt: Someone without authorization tried to get the balance of the account belonging to user_id: %s\n", userID)
		} else {
			fmt.Println("Unauthorized access attempt: Someone without authorization tried to access the balance endpoint, but no user_id was provided in the query.")
		}
	}
}


func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <logfile_path>")
	}
	logFilePath := os.Args[1]
	
	err := detectBolaAttacks(logFilePath)
	if err != nil {
		log.Fatalf("Error detecting BOLA attacks: %v", err)
	}
}
