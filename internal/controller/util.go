package controller

import (
	"os"
	"strings"
)

var (
	ImageList = []string{"MCSP_UTILS_IMAGE", "ACCOUNT_IAM_APP_IMAGE", "MCSP_IM_CONFIG_JOB_IMAGE", "ACCOUNT_IAM_UI_INSTANCE_SERVICE_IMAGE", "ACCOUNT_IAM_UI_API_SERVICE_IMAGE"}
)

func concat(s ...string) string {
	return strings.Join(s, "")
}

func replaceImages(resource string) (result string) {
	result = resource
	for _, imageName := range ImageList {
		result = strings.ReplaceAll(result, imageName, getImage(imageName))
	}
	return result
}

func getImage(imageName string) string {
	image, _ := os.LookupEnv(imageName)
	return image
}
