package importer

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

type PasswordEntry struct {
	Name     string
	URL      string
	Username string
	Password string
	Note     string
}

func ParseChromePasswordCSV(filePath string) ([]PasswordEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	if len(header) < 4 {
		return nil, fmt.Errorf("invalid CSV format: expected at least 4 columns (name, url, username, password)")
	}

	var entries []PasswordEntry

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV record: %w", err)
		}

		if len(record) == 0 || (record[0] == "" && len(record) == 1) {
			continue
		}

		entry := PasswordEntry{
			Name:     strings.TrimSpace(record[0]),
			URL:      strings.TrimSpace(record[1]),
			Username: strings.TrimSpace(record[2]),
			Password: strings.TrimSpace(record[3]),
		}

		if len(record) > 4 {
			entry.Note = strings.TrimSpace(record[4])
		}

		if entry.Password == "" && entry.Username == "" {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}


func FormatSecretName(entry PasswordEntry, index int, includeUsername bool) string {

	name := entry.Name
	if name == "" {
		name = entry.URL
	}

	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimPrefix(name, "www.")
	if idx := strings.Index(name, "/"); idx > 0 {
		name = name[:idx]
	}

	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, name)

	name = strings.ToUpper(name)
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "-", "_")

	if includeUsername && entry.Username != "" {
		username := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				return r
			}
			return '_'
		}, entry.Username)
		username = strings.ToUpper(username)
		username = strings.Trim(username, "_")
		
		if len(username) > 20 {
			username = username[:20]
		}
		
		if username != "" {
			name = fmt.Sprintf("%s_%s", name, username)
		}
	}

	if index > 0 {
		name = fmt.Sprintf("%s_%d", name, index+1)
	}

	return name
}

func DetectDuplicateSites(entries []PasswordEntry) map[string]int {
	siteCounts := make(map[string]int)
	
	for _, entry := range entries {
		baseName := FormatSecretName(entry, 0, false)
		siteCounts[baseName]++
	}
	
	return siteCounts
}

func FormatSecretValue(entry PasswordEntry) string {
	var parts []string

	if entry.URL != "" {
		parts = append(parts, fmt.Sprintf("URL: %s", entry.URL))
	}

	if entry.Username != "" {
		parts = append(parts, fmt.Sprintf("Username: %s", entry.Username))
	}

	if entry.Password != "" {
		parts = append(parts, fmt.Sprintf("Password: %s", entry.Password))
	}

	if entry.Note != "" {
		parts = append(parts, fmt.Sprintf("Note: %s", entry.Note))
	}

	return strings.Join(parts, "\n")
}

