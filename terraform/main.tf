terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.49"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state — update with your storage account details
  # backend "azurerm" {
  #   resource_group_name  = "mailguard-tfstate-rg"
  #   storage_account_name = "mailguardtfstate"
  #   container_name       = "tfstate"
  #   key                  = "mailguard.tfstate"
  # }
}

provider "azurerm" {
  features {}
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "location" {
  description = "Azure region to deploy into"
  default     = "eastus"
}

variable "prefix" {
  description = "Prefix for all resource names"
  default     = "mailguard"
}

variable "image_tag" {
  description = "Docker image tag to deploy"
  default     = "latest"
}

variable "acr_name" {
  description = "Azure Container Registry name (must be globally unique)"
}

# ── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = { app = "mailguard", managed_by = "terraform" }
}

# ── Container Registry ────────────────────────────────────────────────────────

resource "azurerm_container_registry" "acr" {
  name                = var.acr_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true
  tags                = { app = "mailguard" }
}

# ── Log Analytics (required for Container Apps) ───────────────────────────────

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-logs"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# ── Container Apps Environment ────────────────────────────────────────────────

resource "azurerm_container_app_environment" "main" {
  name                       = "${var.prefix}-env"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}

# ── Encryption key (stored in Key Vault) ──────────────────────────────────────

resource "random_bytes" "enc_key" {
  length = 32
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                = "${var.prefix}-kv-${substr(random_bytes.enc_key.hex, 0, 6)}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = ["Get","List","Set","Delete","Purge"]
  }
}

resource "azurerm_key_vault_secret" "enc_key" {
  name         = "encryption-key"
  value        = base64encode(random_bytes.enc_key.base64)
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "secret_key" {
  name         = "secret-key"
  value        = random_bytes.enc_key.hex  # reuse entropy for app secret key
  key_vault_id = azurerm_key_vault.main.id
}

# ── Container App ─────────────────────────────────────────────────────────────

resource "azurerm_container_app" "mailguard" {
  name                         = "${var.prefix}-app"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  registry {
    server               = azurerm_container_registry.acr.login_server
    username             = azurerm_container_registry.acr.admin_username
    password_secret_name = "acr-password"
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.acr.admin_password
  }
  secret {
    name  = "encryption-key"
    value = azurerm_key_vault_secret.enc_key.value
  }
  secret {
    name  = "secret-key"
    value = azurerm_key_vault_secret.secret_key.value
  }

  template {
    min_replicas = 0   # scales to zero when idle = free!
    max_replicas = 3

    container {
      name   = "mailguard"
      image  = "${azurerm_container_registry.acr.login_server}/mailguard:${var.image_tag}"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "DEBUG"
        value = "false"
      }
      env {
        name        = "SECRET_KEY"
        secret_name = "secret-key"
      }
      env {
        name        = "ENCRYPTION_KEY"
        secret_name = "encryption-key"
      }
      env {
        name  = "DATABASE_URL"
        value = "sqlite:///./mailguard.db"
      }
      env {
        name  = "ALLOWED_ORIGINS"
        value = "https://${var.prefix}-app.${azurerm_container_app_environment.main.default_domain}"
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/api/health"
        port      = 8000
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  tags = { app = "mailguard", managed_by = "terraform" }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "app_url" {
  description = "MailGuard application URL"
  value       = "https://${azurerm_container_app.mailguard.ingress[0].fqdn}"
}

output "acr_login_server" {
  description = "Container Registry login server"
  value       = azurerm_container_registry.acr.login_server
}

output "resource_group" {
  value = azurerm_resource_group.main.name
}
