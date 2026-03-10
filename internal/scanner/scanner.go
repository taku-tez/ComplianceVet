package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
)

// ScanOptions configures the scanner.
type ScanOptions struct {
	Paths      []string
	Recursive  bool
	Extensions []string // default: [".yaml", ".yml", ".json"]
}

// Scan walks the given paths and parses all matching files.
func Scan(opts ScanOptions) ([]parser.K8sObject, []parser.ParseError, error) {
	if len(opts.Extensions) == 0 {
		opts.Extensions = []string{".yaml", ".yml", ".json"}
	}
	extSet := make(map[string]bool, len(opts.Extensions))
	for _, e := range opts.Extensions {
		extSet[strings.ToLower(e)] = true
	}

	var objects []parser.K8sObject
	var parseErrors []parser.ParseError

	for _, root := range opts.Paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, nil, err
		}

		if !info.IsDir() {
			res, err := parser.ParseFile(root)
			if err != nil {
				parseErrors = append(parseErrors, parser.ParseError{File: root, Message: err.Error()})
			} else {
				objects = append(objects, res.Objects...)
				parseErrors = append(parseErrors, res.Errors...)
			}
			continue
		}

		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				// Skip subdirectories if not recursive
				if !opts.Recursive && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !extSet[ext] {
				return nil
			}
			res, parseErr := parser.ParseFile(path)
			if parseErr != nil {
				parseErrors = append(parseErrors, parser.ParseError{File: path, Message: parseErr.Error()})
				return nil
			}
			objects = append(objects, res.Objects...)
			parseErrors = append(parseErrors, res.Errors...)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}

	return objects, parseErrors, nil
}
