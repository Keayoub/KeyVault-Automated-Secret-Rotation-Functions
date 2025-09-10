terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "c7b690b3-d9ad-4ed0-9942-4e7a36d0c187"
}

variable "resource_group_name" {
  description = "Name of the resource group."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "canadacentral"
}

variable "function_app_name" {
  description = "Name of the Function App."
  type        = string
}

variable "key_vault_id" {
  description = "ID of the Key Vault to subscribe to."
  type        = string
}

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
}

# Generate a random suffix for unique storage account names
resource "random_string" "storage_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_storage_account" "main" {
  name                     = "${var.function_app_name}${random_string.storage_suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Ensure key-based authentication is enabled (required for Function Apps)
  shared_access_key_enabled = true
}

resource "azurerm_service_plan" "main" {
  name                = "${var.function_app_name}-sp"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Windows"
  sku_name            = "Y1"
}

resource "azurerm_windows_function_app" "main" {
  name                = var.function_app_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  service_plan_id     = azurerm_service_plan.main.id

  storage_account_name       = azurerm_storage_account.main.name
  storage_account_access_key = azurerm_storage_account.main.primary_access_key

  functions_extension_version = "~4"

  site_config {
    application_stack {
      powershell_core_version = "7.2"
    }
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "powershell"
    "AzureWebJobsStorage"      = azurerm_storage_account.main.primary_connection_string
  }
}

resource "azurerm_eventgrid_event_subscription" "main" {
  name                  = "${var.function_app_name}-egsub"
  scope                 = var.key_vault_id
  event_delivery_schema = "EventGridSchema"
  webhook_endpoint {
    url = "https://${azurerm_windows_function_app.main.default_hostname}/api/AkvLogAnalyticsKeyConnector"
  }
  included_event_types = [
    "Microsoft.KeyVault.SecretImportPending",
    "Microsoft.KeyVault.SecretRotationPending"
  ]
}

output "function_app_url" {
  value = azurerm_windows_function_app.main.default_hostname
}
