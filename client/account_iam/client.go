package account_iam

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	operatorv1alpha1 "github.com/IBM/ibm-user-management-operator/api/v1alpha1"
	"github.com/IBM/ibm-user-management-operator/internal/retry"
	logger "github.com/rs/zerolog/log" // TODO: investigate if this is really necessary
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type ProductCustomRoles struct {
	Resources []Resources `json:"resources"`
}

type ActionDefinition struct {
	Resources []ActionResources `json:"resources"`
}
type ActionResources struct {
	Name string `json:"name"`
}

type Resources struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	UID         string `json:"uid"`
}

type IAMClient interface {
	Get(url string) (*http.Response, int, error)
	Post(url string, body *bytes.Reader) (*http.Response, int, error)
	Patch(url string, body *bytes.Reader) (*http.Response, int, error)
	Delete(url string) (*http.Response, int, error)
	GetToken(url string) (string, error)
	GetUID(instance *operatorv1alpha1.RoleActionConfig) (map[string]string, int, error)
	GetProductDetails(serviceID string) (map[string]any, int, error)
	PostNewProduct(serviceID string) ([]byte, int, error)
	PostCustomRoles(v2CustomRole operatorv1alpha1.V2CustomRoles, serviceID string) ([]byte, int, error)
	UpdateCustomRoles(v2CustomRole operatorv1alpha1.V2CustomRoles, serviceID string, UID string) ([]byte, int, error)
	DeleteCustomRoles(instance *operatorv1alpha1.RoleActionConfig, UID string) ([]byte, int, error)
	PostActionsProductLevel(action string, serviceID string) ([]byte, int, error)
	GetActionsProductLevel(serviceID string) ([]map[string]string, int, error)
	DeleteActionsProductLevel(serviceID string, actionName string) ([]byte, int, error)
	GetActionsRoleLevel(serviceID string, roleUID string) ([]map[string]string, int, error)
	PostActionsRoleLevel(action string, roleUID string, serviceID string) ([]byte, int, error)
	DeleteActionsRoleLevel(serviceID string, roleUID string, actionName string) ([]byte, int, error)
}

type MCSPIAMClient struct {
	BaseURL    string
	Token      string
	ApiKey     string
	HTTPClient *http.Client
	retry      *retry.Retry
}

type apiKeyBody struct {
	Apikey string `json:"apikey"`
}

type ApiToken struct {
	Token string `json:"token"`
}

const (
	tokenUrl    = "api/2.0/accounts/global_account/apikeys/token"
	pageSize    = "pageSize"
	maxPageSize = "100" //currently account IAM allows max page size as 100 for API
)

func NewMCSPIAMClient(baseUrl string, apiKey string, retryHandler *retry.Retry) (IAMClient, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // TODO: change to trust account-iam's certificate
		},
	}

	return &MCSPIAMClient{
		BaseURL:    baseUrl,
		ApiKey:     apiKey,
		HTTPClient: httpClient,
		retry:      retryHandler,
	}, nil
}

var log = logf.Log.WithName("controller_product_registration")

func (c *MCSPIAMClient) Get(url string) (*http.Response, int, error) {
	status := 0
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error(err, "failed to create GET request")
		return nil, status, err
	}

	req.Header.Set("Content-Type", "application/json")
	var bearer = "Bearer " + c.Token
	req.Header.Add("Authorization", bearer)

	//added checks for nil response to avoid runtime panics and operator crash
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		if res != nil {
			status = res.StatusCode
		}
		return nil, status, fmt.Errorf("failed to do GET request: %v", err)
	}

	return res, res.StatusCode, nil

}

func (c *MCSPIAMClient) Post(url string, body *bytes.Reader) (*http.Response, int, error) {
	status := 0
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Error(err, "failed to create POST request")
		return nil, status, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+c.Token)

	//added checks for nil response to avoid runtime panics and operator crash
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		if res != nil {
			status = res.StatusCode
		}
		return nil, status, fmt.Errorf("failed to do POST request: %v", err)
	}

	return res, res.StatusCode, nil
}

func (c *MCSPIAMClient) Patch(url string, body *bytes.Reader) (*http.Response, int, error) {
	status := 0
	req, err := http.NewRequest("PATCH", url, body)
	if err != nil {
		log.Error(err, "failed to create PATCH request")
		return nil, status, err
	}

	req.Header.Set("Content-Type", "application/json")
	bearer := "Bearer " + c.Token
	req.Header.Add("Authorization", bearer)

	//added checks for nil response to avoid runtime panics and operator crash
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		if res != nil {
			status = res.StatusCode
		}
		return nil, status, fmt.Errorf("failed to do PATCH request: %v", err)
	}

	return res, res.StatusCode, nil

}

func (c *MCSPIAMClient) Delete(url string) (*http.Response, int, error) {
	status := 0
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Error(err, "failed to create the request")
		return nil, status, err
	}

	req.Header.Set("Content-Type", "application/json")

	bearer := "Bearer " + c.Token
	req.Header.Add("Authorization", bearer)

	//added checks for nil response to avoid runtime panics and operator crash
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		if res != nil {
			status = res.StatusCode
		}
		return nil, status, fmt.Errorf("failed to do DELETE request: %v", err)
	}

	return res, res.StatusCode, nil

}

func (c *MCSPIAMClient) GetToken(url string) (string, error) {
	var finalErr error
	var tokenBody ApiToken
	//retryhandler to avoid crashing the operator when IAM is down
	retryErr := c.retry.RetryHandler(func() error {
		jsonApiKey, err := json.Marshal(apiKeyBody{Apikey: c.ApiKey})
		if err != nil {
			log.Error(err, "failed json marshalling")
			finalErr = err
			return err
		}

		resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewBuffer(jsonApiKey))
		if err != nil {
			log.Error(err, "failed IAM POST call to "+url)
			finalErr = err
			return err
		}

		if resp != nil {
			defer resp.Body.Close()

			tokenString, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Error(err, "Error reading response body")
				finalErr = err
				return err
			}

			err = json.Unmarshal(tokenString, &tokenBody)
			if err != nil {
				log.Error(err, "Error unmarshalling token response")
				finalErr = err
				return err
			}
		}
		if resp == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
			finalErr = fmt.Errorf("nil response or body")
			return finalErr
		}

		return nil
	})

	if retryErr != nil {
		log.Error(finalErr, "GET Token failed after retries")
		return "", finalErr
	}

	c.Token = tokenBody.Token
	return c.Token, nil

}

func (c *MCSPIAMClient) GetUID(instance *operatorv1alpha1.RoleActionConfig) (map[string]string, int, error) {
	serviceID := instance.Spec.ServiceID
	customRolesEndpoint := c.BaseURL + "/" + serviceID + "/roles"

	var statusCode int
	var finalErr error
	var productCustomRoles ProductCustomRoles
	var customRole = make(map[string]string)

	retryErr := c.retry.RetryHandler(func() error {
		// Add pageSize to the query
		reqURL, err := url.Parse(customRolesEndpoint)
		if err != nil {
			log.Error(err, "Failed to parse customRolesEndpoint for GetUID request", customRolesEndpoint)
			finalErr = fmt.Errorf("failed to parse customRolesEndpoint for GetUID request %v", err)
			return retry.NewPermanentError(finalErr)
		}

		query := reqURL.Query()
		query.Set(pageSize, maxPageSize)
		reqURL.RawQuery = query.Encode()

		responseCustomRoles, code, err := c.Get(reqURL.String())
		statusCode = code

		if err != nil {
			finalErr = fmt.Errorf("failed to do GET request for UIDs: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("GET returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}

		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do GET request: %d", statusCode)
			return finalErr
		}

		if responseCustomRoles != nil && responseCustomRoles.Body != nil {
			defer responseCustomRoles.Body.Close()
			if err := json.NewDecoder(responseCustomRoles.Body).Decode(&productCustomRoles); err != nil && err != io.EOF {
				log.Error(err, "failed to decode response results")
				finalErr = err
				return err
			}
		}
		if responseCustomRoles == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("GET succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("GET custom role failed: %v", retryErr)
		return nil, statusCode, retryErr
	}

	if len(productCustomRoles.Resources) > 0 {
		for _, resource := range productCustomRoles.Resources {
			customRole[resource.Name] = resource.UID
		}
	}

	return customRole, statusCode, nil
}

func (c *MCSPIAMClient) GetProductDetails(serviceID string) (map[string]interface{}, int, error) {

	productDetailsEndpoint := c.BaseURL + "/" + serviceID
	responseProductActions, statusCode, err := c.Get(productDetailsEndpoint)
	if err != nil {
		return nil, statusCode, fmt.Errorf("failed to do GET request: %v", err)
	}
	//log response body and status code
	var productDetails map[string]interface{}
	if responseProductActions != nil && responseProductActions.Body != nil {
		defer responseProductActions.Body.Close()
		if err := json.NewDecoder(responseProductActions.Body).Decode(&productDetails); err != nil && err != io.EOF {
			log.Error(err, "failed to decode response results for product details")
			return nil, statusCode, err
		}
	}

	if statusCode >= 500 {
		return nil, statusCode, fmt.Errorf("GET returned server error: %d", statusCode)
	}

	return productDetails, statusCode, nil

}

// PostNewProduct function sends a POST request to the IAM API to register a new product.
func (c *MCSPIAMClient) PostNewProduct(serviceID string) ([]byte, int, error) {

	var body []byte
	var statusCode int

	customRolesEndpoint := c.BaseURL + "/" + serviceID
	responseCustomRoles, statusCode, err := c.Post(customRolesEndpoint, bytes.NewReader(nil))
	if err != nil {
		return nil, statusCode, fmt.Errorf("failed to do POST request: %w", err)
	}

	if responseCustomRoles != nil && responseCustomRoles.Body != nil {
		defer responseCustomRoles.Body.Close()
		body, err = io.ReadAll(responseCustomRoles.Body)
		if err != nil {
			log.Error(err, "failed to read response body")
			return nil, statusCode, err
		}
	}

	if statusCode >= 500 {
		return nil, statusCode, fmt.Errorf("POST returned server error: %d", statusCode)
	}

	return body, statusCode, nil

}

func (c *MCSPIAMClient) PostCustomRoles(v2CustomRole operatorv1alpha1.V2CustomRoles, serviceID string) ([]byte, int, error) {

	var body []byte
	var statusCode int
	var finalErr error

	singleCustomRole := map[string]string{
		"name":          v2CustomRole.Name,
		"description":   v2CustomRole.Description,
		"bindableLevel": "SERVICE",
	}

	encodeBodyCustomRoles, err := json.Marshal(singleCustomRole)
	if err != nil {
		log.Error(err, "failed to marshal response")
		return nil, 0, err
	}

	customRolesEndpoint := c.BaseURL + "/" + serviceID + "/roles"
	//retryhandler to avoid crashing the operator when IAM is down
	retryErr := c.retry.RetryHandler(func() error {
		responseCustomRoles, code, err := c.Post(customRolesEndpoint, bytes.NewReader(encodeBodyCustomRoles))
		statusCode = code
		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("POST returned client error: %d", statusCode)

			//return backoff.Permanent(fmt.Errorf("do not retry"))
			return retry.NewPermanentError(finalErr)

		}
		if err != nil {
			finalErr = fmt.Errorf("failed to do POST request: %v", err)
			return finalErr
		}

		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do POST request: %d", statusCode)
			return finalErr
		}
		//nil check for responseCustomRoles to avoid nil pointer dereference which causes a panic
		if responseCustomRoles != nil && responseCustomRoles.Body != nil {
			defer responseCustomRoles.Body.Close()
			if data, err := io.ReadAll(responseCustomRoles.Body); err == nil {
				body = data
			} else {
				finalErr = err
				return err
			}
		}
		if responseCustomRoles == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("POST succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("POST custom role failed: %v", retryErr)
		return nil, statusCode, retryErr
	}

	return body, statusCode, nil

}

func (c *MCSPIAMClient) UpdateCustomRoles(v2CustomRole operatorv1alpha1.V2CustomRoles, serviceID string, UID string) ([]byte, int, error) {

	var body []byte
	var statusCode int
	var finalErr error

	singleUpdateCustomRole := map[string]string{
		"description": v2CustomRole.Description,
	}

	encodeBodyUpdateCustomRoles, err := json.Marshal(singleUpdateCustomRole)
	if err != nil {
		log.Error(err, "failed to marshal response")
		return nil, 0, err
	}

	customRolesUpdateEndpoint := c.BaseURL + "/" + serviceID + "/roles" + "/" + UID
	//retryhandler to avoid crashing the operator when IAM is down
	retryErr := c.retry.RetryHandler(func() error {
		responseUpdateCustomRoles, sc, err := c.Patch(customRolesUpdateEndpoint, bytes.NewReader(encodeBodyUpdateCustomRoles))
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("PATCH failed for %s, will retry if allowed", customRolesUpdateEndpoint)
			finalErr = fmt.Errorf("failed to do PATCH request: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("patch returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}

		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do PATCH request: %d", statusCode)
			return finalErr
		}
		//nil check for responseUpdateCustomRoles to avoid nil pointer dereference which causes a panic
		if responseUpdateCustomRoles != nil && responseUpdateCustomRoles.Body != nil {
			defer responseUpdateCustomRoles.Body.Close()

			if data, err := io.ReadAll(responseUpdateCustomRoles.Body); err == nil {
				body = data
			} else {
				logger.Info().Msg("Failed to read response body")
				finalErr = err
				return err
			}
		}
		if responseUpdateCustomRoles == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("PATCH succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("PATCH custom role failed: %v", retryErr)
		return nil, statusCode, retryErr
	}

	return body, statusCode, nil

}

func (c *MCSPIAMClient) DeleteCustomRoles(instance *operatorv1alpha1.RoleActionConfig, UID string) ([]byte, int, error) {

	serviceID := instance.Spec.ServiceID

	var body []byte
	var statusCode int
	var finalErr error

	customRolesDeleteEndpoint := c.BaseURL + "/" + serviceID + "/roles" + "/" + UID
	//retryhandler to avoid crashing the operator when IAM is down
	retryErr := c.retry.RetryHandler(func() error {
		responseDeleteCustomRoles, sc, err := c.Delete(customRolesDeleteEndpoint)
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("DELETE failed for %s, will retry if allowed", customRolesDeleteEndpoint)
			finalErr = fmt.Errorf("failed to do DELETE request: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("delete returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}

		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do DELETE request: %v", statusCode)
			return finalErr
		}
		//nil check for responseDeleteCustomRoles to avoid nil pointer dereference which causes a panic
		if responseDeleteCustomRoles != nil && responseDeleteCustomRoles.Body != nil {
			defer responseDeleteCustomRoles.Body.Close()

			if data, err := io.ReadAll(responseDeleteCustomRoles.Body); err == nil {
				body = data
			} else {
				logger.Info().Msg("Failed to read response body")
				finalErr = err
				return err
			}
		}
		if responseDeleteCustomRoles == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("DELETE succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("DELETE custom role failed: %v", retryErr)
		return nil, statusCode, retryErr
	}

	return body, statusCode, nil

}

// PostActionsProductLevel function sends a POST request to the IAM API to add a new action to a specific product. The action is specified by the action string and associated with the serviceID.
func (c *MCSPIAMClient) PostActionsProductLevel(action string, serviceID string) ([]byte, int, error) {

	productActionsEndpoint := c.BaseURL + "/" + serviceID + "/actions"

	// Format request body
	singleAction := map[string]string{
		"name": action,
	}

	encodeBodyProductActions, err := json.Marshal(singleAction)
	if err != nil {
		log.Error(err, "failed to marshal response")
		return nil, 0, err
	}

	var body []byte
	var statusCode int
	var finalErr error
	//retryhandler to avoid crashing the operator when IAM is down
	retryErr := c.retry.RetryHandler(func() error {
		responseProductActions, sc, err := c.Post(productActionsEndpoint, bytes.NewReader(encodeBodyProductActions))
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("POST failed for %s, will retry if allowed", productActionsEndpoint)
			finalErr = fmt.Errorf("failed to do POST request: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("POST returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}
		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do POST request: %v", statusCode)
			return finalErr
		}

		//nil check for responseProductActions to avoid nil pointer dereference which causes a panic
		if responseProductActions != nil && responseProductActions.Body != nil {
			defer responseProductActions.Body.Close()

			if data, err := io.ReadAll(responseProductActions.Body); err == nil {
				body = data
			} else {
				logger.Info().Msg("Failed to read response body")
				finalErr = err
				return err
			}
		}
		if responseProductActions == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("POST succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("POST product level actions failed: %v", retryErr)
		return nil, statusCode, retryErr
	}

	return body, statusCode, nil

}

func (c *MCSPIAMClient) GetActionsProductLevel(serviceID string) ([]map[string]string, int, error) {
	var statusCode int
	var finalErr error
	var actionArray []map[string]string
	var Actions ActionDefinition

	productActionsEndpoint := c.BaseURL + "/" + serviceID + "/actions"

	retryErr := c.retry.RetryHandler(func() error {
		// Parse the endpoint into a url.URL struct
		reqURL, err := url.Parse(productActionsEndpoint)
		if err != nil {
			log.Error(err, "Failed to parse productActionsEndpoint for GetActionsProductLevel request", productActionsEndpoint)
			finalErr = fmt.Errorf("failed to parse productActionsEndpoint for GetActionsProductLevel request %v", err)
			return retry.NewPermanentError(finalErr)
		}

		// Add pageSize query parameter to the request
		query := reqURL.Query()
		query.Set(pageSize, maxPageSize)
		reqURL.RawQuery = query.Encode()

		// Make GET request with updated URL
		responseProductActions, sc, err := c.Get(reqURL.String())
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("GET failed for %s, will retry if allowed", reqURL.String())
			finalErr = fmt.Errorf("failed to do GET request: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("GET returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}

		if statusCode >= 500 {
			finalErr = fmt.Errorf("GET returned server error: %d", statusCode)
			return finalErr
		}

		if responseProductActions != nil && responseProductActions.Body != nil {
			defer responseProductActions.Body.Close()
			if err := json.NewDecoder(responseProductActions.Body).Decode(&Actions); err != nil && err != io.EOF {
				log.Error(err, "failed to decode response results for actions at product level")
				finalErr = err
				return err
			}
		}
		if responseProductActions == nil {
			logger.Warn().Msg("Response or Body is nil, skipping decode")
		}

		logger.Info().Msgf("GET succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("GET product level actions failed: %v", finalErr)
		return nil, statusCode, retryErr
	}

	if len(Actions.Resources) > 0 {
		for _, resource := range Actions.Resources {
			actionArray = append(actionArray, map[string]string{
				"name": resource.Name,
			})
		}
	}

	return actionArray, statusCode, nil
}

// DeleteActionsProductLevel function sends a DELETE request to the IAM API to remove a specific action associated with a given serviceID. The action is identified by the serviceID and actionName.
func (c *MCSPIAMClient) DeleteActionsProductLevel(serviceID string, actionName string) ([]byte, int, error) {

	productActionsEndpoint := c.BaseURL + "/" + serviceID + "/actions" + "/" + actionName

	var body []byte
	var statusCode int
	var finalErr error
	//retryhandler to avoid crashing the operator when IAM is down
	retryErr := c.retry.RetryHandler(func() error {
		responseProductActions, sc, err := c.Delete(productActionsEndpoint)
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("DELETE failed for %s, will retry if allowed", productActionsEndpoint)
			finalErr = fmt.Errorf("failed to do DELETE request: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("delete returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}
		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do DELETE request: %v", statusCode)
			return finalErr
		}

		//nil check for responseProductActions to avoid nil pointer dereference which causes a panic
		if responseProductActions != nil && responseProductActions.Body != nil {
			defer responseProductActions.Body.Close()
			if data, err := io.ReadAll(responseProductActions.Body); err == nil {
				body = data
			} else {
				logger.Info().Msg("Failed to read response body")
				finalErr = err
				return err
			}
		}
		if responseProductActions == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("DELETE succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("DELETE product level action failed : %v", retryErr)
		return nil, statusCode, retryErr
	}

	return body, statusCode, nil
}

func (c *MCSPIAMClient) GetActionsRoleLevel(serviceID string, roleUID string) ([]map[string]string, int, error) {
	var statusCode int
	var finalErr error
	var Actions ActionDefinition
	var actionArray = []map[string]string{}

	productActionsEndpoint := c.BaseURL + "/" + serviceID + "/roles/" + roleUID + "/actions"

	retryErr := c.retry.RetryHandler(func() error {
		// Parse the endpoint
		reqURL, err := url.Parse(productActionsEndpoint)
		if err != nil {
			log.Error(err, "Failed to parse productActionsEndpoint for GetActionsRoleLevel request", productActionsEndpoint)
			finalErr = fmt.Errorf("failed to parse productActionsEndpoint for GetActionsRoleLevel request %v", err)
			return retry.NewPermanentError(finalErr)
		}

		// Add pageSize as query param
		query := reqURL.Query()
		query.Set(pageSize, maxPageSize)
		reqURL.RawQuery = query.Encode()

		// Perform GET
		responseProductActions, sc, err := c.Get(reqURL.String())
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("GET failed for %s, will retry if allowed", reqURL.String())
			finalErr = fmt.Errorf("failed to do GET request: %v", err)
			return finalErr
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("GET returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}

		if statusCode >= 500 {
			finalErr = fmt.Errorf("GET returned server error: %d", statusCode)
			return finalErr
		}

		if responseProductActions != nil && responseProductActions.Body != nil {
			defer responseProductActions.Body.Close()
			if err := json.NewDecoder(responseProductActions.Body).Decode(&Actions); err != nil && err != io.EOF {
				log.Error(err, "failed to decode response results for actions at role level")
				finalErr = err
				return err
			}
		}
		if responseProductActions == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body decode")
		}

		logger.Info().Msgf("GET succeeded with status %d", statusCode)
		return nil
	})

	if retryErr != nil {
		logger.Error().Msgf("GET custom role actions failed: %v", retryErr)
		return nil, statusCode, retryErr
	}

	// Format response
	if len(Actions.Resources) > 0 {
		for _, resource := range Actions.Resources {
			actionArray = append(actionArray, map[string]string{
				"name": resource.Name,
			})
		}
	}

	return actionArray, statusCode, nil
}

func (c *MCSPIAMClient) PostActionsRoleLevel(action string, roleUID string, serviceID string) ([]byte, int, error) {
	var finalErr error

	productActionsEndpoint := c.BaseURL + "/" + serviceID + "/roles/" + roleUID + "/actions"

	encodeBodyProductActions, err := json.Marshal(action)
	if err != nil {
		log.Error(err, "failed to marshal response")
		return nil, 0, err
	}

	var body []byte
	var statusCode int

	//retryhandler to avoid crashing the operator when IAM is down
	err = c.retry.RetryHandler(func() error {
		responseProductActions, sc, err := c.Post(productActionsEndpoint, bytes.NewReader(encodeBodyProductActions))
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("POST failed for %s, will retry if allowed", productActionsEndpoint)
			return fmt.Errorf("failed to do POST request: %v", err)
		}

		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("post returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}
		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do POST request: %v", statusCode)
			return finalErr
		}

		//nil check for responseProductActions to avoid nil pointer dereference which causes a panic
		if responseProductActions != nil && responseProductActions.Body != nil {
			defer responseProductActions.Body.Close()
			if data, err := io.ReadAll(responseProductActions.Body); err == nil {
				body = data
			} else {
				logger.Info().Msg("Failed to read response body") //added logs if io.ReadALL fails.
				return err
			}
		}
		if responseProductActions == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("POST succeeded with status %d", statusCode)
		return nil
	})

	if err != nil {
		logger.Error().Msgf("POST custom role action failed: %v", err)
		return nil, statusCode, err
	}

	return body, statusCode, nil
}

func (c *MCSPIAMClient) DeleteActionsRoleLevel(serviceID string, roleUID string, actionName string) ([]byte, int, error) {
	var body []byte
	var statusCode int
	var finalErr error

	customRolesActionDeleteEndpoint := c.BaseURL + "/" + serviceID + "/roles/" + roleUID + "/actions/" + actionName
	//retryhandler to avoid crashing the operator when IAM is down
	err := c.retry.RetryHandler(func() error {
		responseDeleteCustomRolesAction, sc, err := c.Delete(customRolesActionDeleteEndpoint)
		statusCode = sc

		if err != nil {
			logger.Info().Msgf("DELETE failed for %s, will retry if allowed", customRolesActionDeleteEndpoint)
			finalErr = fmt.Errorf("failed to do DELETE request: %v", err)
			return finalErr
		}
		//do not retry if the statuscode falls between this range.
		if statusCode >= 400 && statusCode < 500 {
			finalErr = fmt.Errorf("delete returned client error: %d", statusCode)
			return retry.NewPermanentError(finalErr)
		}
		if statusCode >= 500 {
			finalErr = fmt.Errorf("failed to do DELETE request: %v", statusCode)
			return finalErr
		}
		//nil check for responseDeleteCustomRolesAction to avoid nil pointer dereference which causes a panic
		if responseDeleteCustomRolesAction != nil && responseDeleteCustomRolesAction.Body != nil {
			defer responseDeleteCustomRolesAction.Body.Close()
			if data, err := io.ReadAll(responseDeleteCustomRolesAction.Body); err == nil {
				body = data
			} else {
				logger.Info().Msg("Failed to read response body") //added logs if io.ReadALL fails.
				finalErr = err
				return err
			}
		}
		if responseDeleteCustomRolesAction == nil {
			logger.Warn().Msg("Response or Body is nil, skipping body read and close")
		}

		logger.Info().Msgf("DELETE succeeded with status %d", statusCode)
		return nil
	})

	if err != nil {
		logger.Error().Msgf("DELETE custom role action failed: %v", err)
		return nil, statusCode, err
	}

	return body, statusCode, nil
}
