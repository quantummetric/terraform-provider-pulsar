// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package pulsar

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/streamnative/pulsarctl/pkg/pulsar"
	"github.com/streamnative/pulsarctl/pkg/pulsar/common"
)

// Provider returns a terraform.ResourceProvider
func Provider() terraform.ResourceProvider {
	provider := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"web_service_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: descriptions["web_service_url"],
				DefaultFunc: schema.EnvDefaultFunc("WEB_SERVICE_URL", nil),
			},
			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("PULSAR_AUTH_TOKEN", nil),
				Description: descriptions["token"],
			},
			"tls_cert_file": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("PULSAR_TLS_CERT_FILE", nil),
				Description: descriptions["tls_cert_file"],
			},
			"tls_key_file": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("PULSAR_TLS_KEY_FILE", nil),
				Description: descriptions["tls_key_file"],
			},
			"api_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "1",
				Description: descriptions["api_version"],
			},
			"tls_trust_certs_file_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["tls_trust_certs_file_path"],
				DefaultFunc: schema.EnvDefaultFunc("TLS_TRUST_CERTS_FILE_PATH", nil),
			},
			"tls_allow_insecure_connection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: descriptions["tls_allow_insecure_connection"],
				DefaultFunc: schema.EnvDefaultFunc("TLS_ALLOW_INSECURE_CONNECTION", false),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"pulsar_tenant":    resourcePulsarTenant(),
			"pulsar_cluster":   resourcePulsarCluster(),
			"pulsar_namespace": resourcePulsarNamespace(),
			"pulsar_topic":     resourcePulsarTopic(),
		},
	}

	provider.ConfigureFunc = func(d *schema.ResourceData) (interface{}, error) {
		tfVersion := provider.TerraformVersion
		if tfVersion == "" {
			// Terraform 0.12 introduced this field to the protocol, so if this field is missing,
			// we can assume Terraform version is <= 0.11
			tfVersion = "0.11+compatible"
		}

		if err := validatePulsarConfig(d); err != nil {
			return nil, err
		}

		return providerConfigure(d, tfVersion)
	}

	return provider
}

func providerConfigure(d *schema.ResourceData, tfVersion string) (interface{}, error) {

	// can be used for version locking or version specific feature sets
	_ = tfVersion
	clusterURL := d.Get("web_service_url").(string)
	token := d.Get("token").(string)
	TLSCertFile := d.Get("tls_cert_file").(string)
	TLSKeyFile := d.Get("tls_key_file").(string)
	pulsarAPIVersion := d.Get("api_version").(string)
	TLSTrustCertsFilePath := d.Get("tls_trust_certs_file_path").(string)
	TLSAllowInsecureConnection := d.Get("tls_allow_insecure_connection").(bool)

	apiVersion, err := strconv.Atoi(pulsarAPIVersion)
	if err != nil {
		apiVersion = 1
	}

	config := &common.Config{
		WebServiceURL:              clusterURL,
		Token:                      token,
		PulsarAPIVersion:           common.APIVersion(apiVersion),
		TLSTrustCertsFilePath:      TLSTrustCertsFilePath,
		TLSAllowInsecureConnection: TLSAllowInsecureConnection,
		TLSCertFile:                TLSCertFile,
		TLSKeyFile:                 TLSKeyFile,
	}

	return pulsar.New(config)
}

// Exists reports whether the named file or directory exists.
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func validatePulsarConfig(d *schema.ResourceData) error {
	webServiceURL := d.Get("web_service_url").(string)

	if _, err := url.Parse(webServiceURL); err != nil {
		return fmt.Errorf("ERROR_PULSAR_CONFIG_INVALID_WEB_SERVICE_URL: %w", err)
	}

	apiVersion, ok := d.Get("api_version").(string)
	if !ok {
		_ = d.Set("api_version", "1")
	}

	switch apiVersion {
	case "0":
		_ = d.Set("api_version", "0")
	case "1":
		// (@TODO pulsarctl) 1 is for v2, in pulsarctl, Version is set with iota, it should be iota+1
		_ = d.Set("api_version", "1")
	case "2":
		_ = d.Set("api_version", "2")
	default:
		_ = d.Set("api_version", "1")
	}

	TLSCertFile := d.Get("tls_cert_file").(string)
	if TLSCertFile != "" && !FileExists(TLSCertFile) {
		return fmt.Errorf("ERROR_PULSAR_CONFIG_CERT_FILE_NOTEXIST: %q", TLSCertFile)
	}

	TLSKeyFile := d.Get("tls_key_file").(string)
	if TLSKeyFile != "" && !FileExists(TLSKeyFile) {
		return fmt.Errorf("ERROR_PULSAR_CONFIG_KEY_FILE_NOTEXIST: %q", TLSKeyFile)
	}

	TLSTrustCertsFilePath := d.Get("tls_trust_certs_file_path").(string)
	if TLSTrustCertsFilePath != "" && !FileExists(TLSTrustCertsFilePath) {
		return fmt.Errorf("ERROR_PULSAR_CONFIG_TLS_TRUST_FILE_NOTEXIST: %q", TLSTrustCertsFilePath)
	}

	return nil
}

var descriptions map[string]string

func init() {
	descriptions = map[string]string{
		"admin_roles":      "Admin roles to be attached to tenant",
		"allowed_clusters": "Tenant will be able to interact with these clusters",
		"api_version":      "Api Version to be used for the pulsar admin interaction",
		"backlog_quota":    "",
		"dispatch_rate":    "Data transfer rate, in and out of the Pulsar Broker",
		"enable_duplication": `ensures that each message produced on Pulsar topics is persisted to disk 
only once, even if the message is produced more than once`,
		"encrypt_topics":                 "encrypt messages at the producer and decrypt at the consumer",
		"max_consumers_per_subscription": "Max number of consumers per subscription",
		"max_consumers_per_topic":        "Max number of consumers per topic",
		"max_producers_per_topic":        "Max number of producers per topic",
		"namespace_list":                 "List of namespaces for a given tenant",
		"namespace":                      "Pulsar namespaces are logical groupings of topics",
		"persistence_policy":             "Policy for the namespace for data persistence",
		"tenant": `An administrative unit for allocating capacity and enforcing an 
authentication/authorization scheme`,
		"tls_allow_insecure_connection": "Boolean flag to accept untrusted TLS certificates",
		"tls_cert_file":                 "Filepath to certificate file to use for TLS authentication",
		"tls_key_file":                  "Filepath to key file to use for TLS authentication",
		"tls_trust_certs_file_path":     "Path to a custom trusted TLS certificate file",
		"token": `Authentication Token used to grant terraform permissions
to modify Apace Pulsar Entities`,
		"web_service_url": "Web service url is used to connect to your apache pulsar cluster",
	}
}
