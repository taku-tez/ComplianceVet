package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseFile parses a single file (YAML or JSON) and returns K8sObjects.
func ParseFile(path string) (ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ParseResult{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return ParseJSON(f, path)
	default:
		return ParseYAML(f, path)
	}
}

// ParseYAML parses one or more YAML documents from a reader.
func ParseYAML(r io.Reader, sourcePath string) (ParseResult, error) {
	var result ParseResult
	dec := yaml.NewDecoder(r)

	for {
		var raw map[string]interface{}
		err := dec.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Errors = append(result.Errors, ParseError{
				File:    sourcePath,
				Message: fmt.Sprintf("yaml decode: %v", err),
			})
			break
		}
		if raw == nil {
			continue
		}
		obj, ok := extractObject(raw, sourcePath)
		if !ok {
			continue
		}
		result.Objects = append(result.Objects, obj)
	}
	return result, nil
}

// ParseJSON parses a single JSON document from a reader.
func ParseJSON(r io.Reader, sourcePath string) (ParseResult, error) {
	var result ParseResult
	var raw map[string]interface{}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		result.Errors = append(result.Errors, ParseError{
			File:    sourcePath,
			Message: fmt.Sprintf("json decode: %v", err),
		})
		return result, nil
	}
	obj, ok := extractObject(raw, sourcePath)
	if ok {
		result.Objects = append(result.Objects, obj)
	}
	return result, nil
}

func extractObject(raw map[string]interface{}, sourcePath string) (K8sObject, bool) {
	kind, _ := raw["kind"].(string)
	apiVersion, _ := raw["apiVersion"].(string)
	if kind == "" {
		return K8sObject{}, false
	}

	obj := K8sObject{
		APIVersion: apiVersion,
		Kind:       kind,
		Raw:        raw,
		SourceFile: sourcePath,
	}

	if meta, ok := raw["metadata"].(map[string]interface{}); ok {
		obj.Name, _ = meta["name"].(string)
		obj.Namespace, _ = meta["namespace"].(string)
		obj.Labels = toStringMap(meta["labels"])
		obj.Annotations = toStringMap(meta["annotations"])
	}

	if spec, ok := raw["spec"].(map[string]interface{}); ok {
		obj.Spec = spec
	} else {
		obj.Spec = map[string]interface{}{}
	}

	return obj, true
}

func toStringMap(v interface{}) map[string]string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}
