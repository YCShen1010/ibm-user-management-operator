package images

import (
	"os"
	"strings"
	"sync"
)

var (
	// imageEnvVars contains all environment variable names for container images
	imageEnvVars = []string{
		"RELATED_IMAGE_MCSP_UTILS",
		"RELATED_IMAGE_ACCOUNT_IAM",
		"RELATED_IMAGE_MCSP_IM_CONFIG_JOB",
		"RELATED_IMAGE_ACCOUNT_SERVICE",
		"RELATED_IMAGE_API_SERVICE",
	}

	imageMap = make(map[string]string)

	// initOnce ensures initialization happens only once
	initOnce sync.Once
)

// Initialize loads all image references from environment variables
func Initialize() {
	initOnce.Do(func() {
		for _, envName := range imageEnvVars {
			if image, exists := os.LookupEnv(envName); exists {
				imageMap[envName] = image
			}
		}
	})
}

// // Get returns the image reference for a given environment variable name
// func Get(envName string) string {
// 	if image, exists := imageMap[envName]; exists {
// 		return image
// 	}

// 	// Fallback to direct lookup if not in cache
// 	image, _ := os.LookupEnv(envName)
// 	return image
// }

// ReplaceInYAML replaces all image placeholders in the provided YAML content
func ReplaceInYAML(yaml string) string {

	for envName, imageValue := range imageMap {
		// Only perform replacement if:
		// 1. The image value is not empty
		// 2. The environment variable name appears in the YAML
		if imageValue != "" && strings.Contains(yaml, envName) {
			yaml = strings.ReplaceAll(yaml, envName, imageValue)
			return yaml
		}
	}
	return yaml
}

// ContainsImageReferences checks if the YAML contains any image references
func ContainsImageReferences(yaml string) bool {
	for _, envName := range imageEnvVars {
		if strings.Contains(yaml, envName) {
			return true
		}
	}
	return false
}
