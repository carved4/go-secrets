package envinjector

import (
	"fmt"
	"strings"
)

type SecretFilter struct {
	allowedPrefixes []string
	allowedNames    []string
	denyAll         bool
}

func NewSecretFilter() *SecretFilter {
	return &SecretFilter{
		allowedPrefixes: []string{},
		allowedNames:    []string{},
		denyAll:         false,
	}
}

func (f *SecretFilter) AllowPrefix(prefix string) *SecretFilter {
	f.allowedPrefixes = append(f.allowedPrefixes, prefix)
	return f
}

func (f *SecretFilter) AllowName(name string) *SecretFilter {
	f.allowedNames = append(f.allowedNames, name)
	return f
}

func (f *SecretFilter) AllowPrefixes(prefixes []string) *SecretFilter {
	f.allowedPrefixes = append(f.allowedPrefixes, prefixes...)
	return f
}

func (f *SecretFilter) AllowNames(names []string) *SecretFilter {
	f.allowedNames = append(f.allowedNames, names...)
	return f
}

func (f *SecretFilter) IsAllowed(secretName string) bool {
	if f.denyAll {
		return false
	}

	for _, name := range f.allowedNames {
		if secretName == name {
			return true
		}
	}

	for _, prefix := range f.allowedPrefixes {
		if strings.HasPrefix(secretName, prefix) {
			return true
		}
	}

	if len(f.allowedPrefixes) == 0 && len(f.allowedNames) == 0 {
		return true
	}

	return false
}

func (f *SecretFilter) FilterSecrets(allSecrets []string) []string {
	if len(f.allowedPrefixes) == 0 && len(f.allowedNames) == 0 {
		return allSecrets
	}

	filtered := make([]string, 0)
	for _, secret := range allSecrets {
		if f.IsAllowed(secret) {
			filtered = append(filtered, secret)
		}
	}
	return filtered
}

func (f *SecretFilter) Validate() error {
	if f.denyAll {
		return fmt.Errorf("filter denies all secrets")
	}
	return nil
}
