<#
This PowerShell script is designed for Azure Functions that automatically handle the rotation and import of credentials (Azure Log Analytics workspace shared keys) stored in Azure Key Vault (AKV) by responding to Azure Event Grid events.
It ensures that secrets are updated and synchronized with their associated Azure Log Analytics workspaces, helping to automate secret management using AKV's data plane APIs.
#>

# Parameters for the Azure Function triggered by an Event Grid Event.
param([object]$EventGridEvent, [object]$TriggerMetadata)

# Constants.
$MAX_RETRY_ATTEMPTS = 30  # Maximum number of retry attempts to poll for a secret update.
$MAX_JSON_DEPTH = 10  # Maximum JSON depth allowed when serializing objects.
$DATA_PLANE_API_VERSION = "7.6-preview.1"  # The API version for AKV data plane operations.
$AZURE_FUNCTION_NAME = "AkvLogAnalyticsKeyConnector"  # Name of the Azure Function.
$MODULE_NAMES = @(
    "Az.Accounts"
    "Az.OperationalInsights"
)

# Extract subscription ID, resource group name, and app name from environment variables to construct the expected Azure Function resource ID.
$EXPECTED_FUNCTION_APP_SUBSCRIPTION_ID = $env:WEBSITE_OWNER_NAME.Substring(0, 36)
$EXPECTED_FUNCTION_APP_RG_NAME = $env:WEBSITE_RESOURCE_GROUP
$EXPECTED_FUNCTION_APP_NAME = $env:WEBSITE_SITE_NAME

$EXPECTED_FUNCTION_RESOURCE_ID = "/subscriptions/$EXPECTED_FUNCTION_APP_SUBSCRIPTION_ID/resourceGroups/$EXPECTED_FUNCTION_APP_RG_NAME/providers/Microsoft.Web/sites/$EXPECTED_FUNCTION_APP_NAME/functions/$AZURE_FUNCTION_NAME"

function Invoke-MainLogic {
    $ErrorActionPreference = "Stop"
    $InformationPreference = "Continue"

    foreach ($moduleName in $MODULE_NAMES) {
        $moduleVersion = (Get-Module -Name $moduleName -ListAvailable | Select-Object -First 1).Version
        Write-Information "$moduleName Version: '$moduleVersion'"
    }

    # Extract the event type and versioned secret ID for further operations.
    $EventGridEvent | ConvertTo-Json -Depth $MAX_JSON_DEPTH -Compress | Write-Information
    $eventType = $EventGridEvent.eventType
    $versionedSecretId = $EventGridEvent.data.Id
    if (-not ($versionedSecretId -match "(https://[^/]+/[^/]+/[^/]+)/[0-9a-f]{32}")) {
        throw "The versioned secret ID '$versionedSecretId' didn't match the expected pattern."
    }
    $unversionedSecretId = $Matches[1]

    # Handle the Event Grid event based on its type.
    switch ($eventType) {
        "Microsoft.KeyVault.SecretImportPending" {
            Invoke-PendingSecretImport -VersionedSecretId $versionedSecretId -UnversionedSecretId $unversionedSecretId
        }
        "Microsoft.KeyVault.SecretRotationPending" {
            Invoke-PendingSecretRotation -VersionedSecretId $versionedSecretId -UnversionedSecretId $unversionedSecretId
        }
        default {
            throw "The Event Grid event '$eventType' is unsupported. Expected 'Microsoft.KeyVault.SecretImportPending' or 'Microsoft.KeyVault.SecretRotationPending'."
        }
    }
}

# Function to get the inactive credential ID based on what AKV considers to be the currently active one.
# Azure Log Analytics workspaces support two shared keys, and this function switches between them (either 'Primary' or 'Secondary').
function Get-InactiveCredentialId([string]$ActiveCredentialId) {
    $inactiveCredentialId = switch ($ActiveCredentialId) {
        "Primary" { "Secondary" }
        "Secondary" { "Primary" }
        default { throw "The active credential ID '$ActiveCredentialId' didn't match the expected pattern. Expected 'Primary' or 'Secondary'." }
    }
    return $inactiveCredentialId
}

# Function to retrieve the value of the active credential (shared key) from the secret provider (Azure Log Analytics workspace).
# This function validates the input and retrieves the specified shared key from the Log Analytics workspace.
function Get-CredentialValue([string]$ActiveCredentialId, [string]$ProviderAddress) {
    # Ensure that the active credential ID is provided.
    if (-not ($ActiveCredentialId)) {
        return @($null, "The active credential ID is missing.")
    }
    # Ensure that the credential ID matches the expected pattern ('Primary' or 'Secondary').
    if ($ActiveCredentialId -notin @("Primary", "Secondary")) {
        return @($null, "The active credential ID '$ActiveCredentialId' didn't match the expected pattern. Expected 'Primary' or 'Secondary'.")
    }
    # Ensure that the provider address (resource ID of the Log Analytics workspace) is provided.
    if (-not ($ProviderAddress)) {
        return @($null, "The provider address is missing.")
    }
    # Ensure that the provider address (resource ID of the Log Analytics workspace) matches the expected secret provider format.
    if (-not ($ProviderAddress -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.OperationalInsights/workspaces/([^/]+)")) {
        return @($null, "The provider address '$ProviderAddress' didn't match the expected pattern.")
    }

    # Extract details from the provider address (subscription ID, resource group name, workspace name).
    $subscriptionId = $Matches[1]
    $resourceGroupName = $Matches[2]
    $workspaceName = $Matches[3]

    # Select the subscription to operate on.
    $null = Set-AzContext -SubscriptionId $subscriptionId

    # Retrieve the specified credential (shared key) from the secret provider (Log Analytics workspace).
    try {
        $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName
        $keys = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $resourceGroupName -Name $workspaceName
        
        $credentialValue = switch ($ActiveCredentialId) {
            "Primary" { $keys.PrimarySharedKey }
            "Secondary" { $keys.SecondarySharedKey }
        }
        
        return @($credentialValue, $null)
    }
    catch {
        # Handle any exceptions by logging detailed information and re-throwing the exception.
        Write-Information "Exception during Get-CredentialValue: $($_.Exception.Message)"
        throw "Encountered unexpected exception during Get-CredentialValue. Throwing."
    }
}

# Function to regenerate a credential (shared key) via the secret provider (Log Analytics workspace).
# This function generates a new inactive credential, which can later be made active.
function Invoke-CredentialRegeneration([string]$InactiveCredentialId, [string]$ProviderAddress) {
    if (-not ($ProviderAddress)) {
        return @($null, "The provider address is missing.")
    }
    if (-not ($ProviderAddress -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.OperationalInsights/workspaces/([^/]+)")) {
        return @($null, "The provider address '$ProviderAddress' didn't match the expected pattern.")
    }
    $subscriptionId = $Matches[1]
    $resourceGroupName = $Matches[2]
    $workspaceName = $Matches[3]

    $null = Set-AzContext -SubscriptionId $subscriptionId

    # Attempt to regenerate the inactive credential (Log Analytics workspace shared key) and return it.
    try {
        # Note: Log Analytics doesn't have individual key regeneration like Cosmos DB
        # We need to regenerate all keys and then return the requested one
        $null = New-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $resourceGroupName -Name $workspaceName
        
        # Get the new keys after regeneration
        $keys = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $resourceGroupName -Name $workspaceName
        
        $credentialValue = switch ($InactiveCredentialId) {
            "Primary" { $keys.PrimarySharedKey }
            "Secondary" { $keys.SecondarySharedKey }
        }
        
        return @($credentialValue, $null)
    }
    catch {
        Write-Information "Exception during Invoke-CredentialRegeneration: $($_.Exception.Message)"
        throw "Encountered unexpected exception during Invoke-CredentialRegeneration. Throwing."
    }
}

# Function to get the current secret from AKV for validation purposes.
# This function ensures that the secret is in the expected state before proceeding with further actions.
function Get-CurrentSecret(
    [string]$UnversionedSecretId,
    [string]$ExpectedSecretId,
    [string]$ExpectedLifecycleState,
    [string]$CallerName) {
    $secret = $null
    $actualSecretId = $null
    $actualLifecycleState = $null
    $actualFunctionResourceId = $null

    # Get the access token for authenticating requests to AKV.
    $token = (Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString).Token

    # In rare cases, this handler might receive the published event before AKV has finished committing to its own internal storage.
    # To mitigate this, poll the current secret for up to 30s until its current lifecycle state matches that of the published event.
    foreach ($i in 1..$MAX_RETRY_ATTEMPTS) {
        $clientRequestId = [Guid]::NewGuid().ToString()
        Write-Information "  Attempt #$i with x-ms-client-request-id: '$clientRequestId'"

        # Define HTTP headers for the request.
        $headers = @{
            "User-Agent"             = "$AZURE_FUNCTION_NAME/1.0 ($CallerName; Step 1; Attempt $i)"
            "x-ms-client-request-id" = $clientRequestId
        }

        # Perform a GET request to fetch the current secret from AKV.
        $response = Invoke-WebRequest -Uri "${UnversionedSecretId}?api-version=$DATA_PLANE_API_VERSION" `
            -Method "GET" `
            -Authentication OAuth `
            -Token $token `
            -ContentType "application/json" `
            -Headers $headers
        $secret = $response.Content | ConvertFrom-Json
        $actualSecretId = $secret.id
        $actualLifecycleState = $secret.attributes.lifecycleState
        $actualFunctionResourceId = $secret.providerConfig.functionResourceId

        # Stop polling if the actual state matches the expected state.
        if (
            ($actualSecretId -eq $ExpectedSecretId) -and
            ($actualLifecycleState -eq $ExpectedLifecycleState) -and
            ($actualFunctionResourceId -eq $EXPECTED_FUNCTION_RESOURCE_ID)
        ) {
            break
        }
        Start-Sleep -Seconds 1
    }

    # Return an error message if the secret's actual state did not reach the expected state after polling.
    if (-not ($actualSecretId -eq $ExpectedSecretId)) {
        return @($null, "The secret '$actualSecretId' did not transition to '$ExpectedSecretId' after approximately $MAX_RETRY_ATTEMPTS seconds. Exiting.")
    }
    if (-not ($actualLifecycleState -eq $ExpectedLifecycleState)) {
        return @($null, "The secret '$actualSecretId' still has a lifecycle state of '$actualLifecycleState' and did not transition to '$ExpectedLifecycleState' after approximately $MAX_RETRY_ATTEMPTS seconds. Exiting.")
    }
    if (-not ($actualFunctionResourceId -eq $EXPECTED_FUNCTION_RESOURCE_ID)) {
        return @($null, "Expected function resource ID to be '$EXPECTED_FUNCTION_RESOURCE_ID', but found '$actualFunctionResourceId'. Exiting.")
    }

    # Log part of the secret's metadata for telemetry purposes.
    $lifecycleDescription = $secret.attributes.lifecycleDescription
    $validityPeriod = $secret.rotationPolicy.validityPeriod
    $activeCredentialId = $secret.providerConfig.activeCredentialId
    $providerAddress = $secret.providerConfig.providerAddress
    $functionResourceId = $secret.providerConfig.functionResourceId
    Write-Information "  lifecycleDescription: '$lifecycleDescription'"
    Write-Information "  validityPeriod: '$validityPeriod'"
    Write-Information "  activeCredentialId: '$activeCredentialId'"
    Write-Information "  providerAddress: '$providerAddress'"
    Write-Information "  functionResourceId: '$functionResourceId'"

    return @($secret, $null)
}

# Function to update a secret in AKV whose lifecycle state is currently either 'ImportPending' or 'RotationPending'.
# This function updates the secret's attributes based on the provided request body.
function Update-PendingSecret(
    [string]$UnversionedSecretId,
    [object]$PendingSecret,
    [string]$CallerName) {
    $clientRequestId = [Guid]::NewGuid().ToString()
    Write-Information "  x-ms-client-request-id: '$clientRequestId'"
    $token = (Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString).Token
    $headers = @{
        "User-Agent"             = "$AZURE_FUNCTION_NAME/1.0 ($CallerName; Step 3)"
        "x-ms-client-request-id" = $clientRequestId
    }
    $updatePendingSecretRequestBody = ConvertTo-Json $PendingSecret -Depth $MAX_JSON_DEPTH -Compress

    # Perform an HTTP PUT request to update the pending secret via the UpdatePendingSecret API.
    try {
        $response = Invoke-WebRequest -Uri "${UnversionedSecretId}/pending?api-version=$DATA_PLANE_API_VERSION" `
            -Method "PUT" `
            -Authentication OAuth `
            -Token $token `
            -ContentType "application/json" `
            -Headers $headers `
            -Body $updatePendingSecretRequestBody
        $updatedSecret = $response.Content | ConvertFrom-Json
        $lifecycleState = $updatedSecret.attributes.lifecycleState
        $lifecycleDescription = $updatedSecret.attributes.lifecycleDescription
        $activeCredentialId = $updatedSecret.providerConfig.activeCredentialId
        Write-Information "  lifecycleState: '$lifecycleState'"
        Write-Information "  lifecycleDescription: '$lifecycleDescription'"
        Write-Information "  activeCredentialId: '$activeCredentialId'"
        return @($updatedSecret, $null)
    }
    catch {
        $httpStatusCode = $_.Exception.Response.StatusCode
        $httpStatusCodeDescription = "$([int]$httpStatusCode) ($httpStatusCode)"
        $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json
        $requestUri = $_.Exception.Response.RequestMessage.RequestUri
        $requestId = $_.Exception.Response.Headers.GetValues("x-ms-request-id") -join ","
        $errorCode = $errorBody.error.code
        $errorMessage = $errorBody.error.message
        Write-Information "  httpStatusCode: '$httpStatusCodeDescription'"
        Write-Information "  requestUri: '$requestUri'"
        Write-Information "  x-ms-request-id: '$requestId'"
        Write-Information "  errorCode: '$errorCode'"
        Write-Information "  errorMessage: '$errorMessage'"

        # If the error is in the 400 range, classify it as non-retriable and return.
        if (($httpStatusCode -ge 400) -and ($httpStatusCode -lt 500)) {
            return @($null, "Classifying $httpStatusCodeDescription as non-retriable. Exiting.")
        }

        # If the error is outside the 400 range, throw a retriable error.
        throw "Classifying $httpStatusCodeDescription as retriable. Throwing."
    }
}

# Function to handle a pending secret import event from AKV.
# This function imports the active credential from the secret provider and updates the secret in AKV.
function Invoke-PendingSecretImport([string]$VersionedSecretId, [string]$UnversionedSecretId) {
    Write-Information "Handling secret import for '$VersionedSecretId'"

    # Step 1: Get the current secret to understand its configuration.
    $callerName = "Invoke-PendingSecretImport"
    ($currentSecret, $errorMessage) = Get-CurrentSecret -UnversionedSecretId $UnversionedSecretId -ExpectedSecretId $VersionedSecretId -ExpectedLifecycleState "ImportPending" -CallerName $callerName
    if ($errorMessage) {
        throw $errorMessage
    }

    # Step 2: Retrieve the active credential from the secret provider.
    $activeCredentialId = $currentSecret.providerConfig.activeCredentialId
    $providerAddress = $currentSecret.providerConfig.providerAddress
    ($credentialValue, $errorMessage) = Get-CredentialValue -ActiveCredentialId $activeCredentialId -ProviderAddress $providerAddress
    if ($errorMessage) {
        throw $errorMessage
    }

    # Step 3: Update the pending secret with the retrieved credential.
    $pendingSecret = @{
        value = $credentialValue
    }
    ($updatedSecret, $errorMessage) = Update-PendingSecret -UnversionedSecretId $UnversionedSecretId -PendingSecret $pendingSecret -CallerName $callerName
    if ($errorMessage) {
        throw $errorMessage
    }

    Write-Information "Successfully imported secret for Log Analytics workspace."
}

# Function to handle a pending secret rotation event from AKV.
# This function regenerates the inactive credential, updates it in AKV, and then makes it active.
function Invoke-PendingSecretRotation([string]$VersionedSecretId, [string]$UnversionedSecretId) {
    Write-Information "Handling secret rotation for '$VersionedSecretId'"

    # Step 1: Get the current secret to understand its configuration.
    $callerName = "Invoke-PendingSecretRotation"
    ($currentSecret, $errorMessage) = Get-CurrentSecret -UnversionedSecretId $UnversionedSecretId -ExpectedSecretId $VersionedSecretId -ExpectedLifecycleState "RotationPending" -CallerName $callerName
    if ($errorMessage) {
        throw $errorMessage
    }

    # Step 2: Regenerate the inactive credential.
    $activeCredentialId = $currentSecret.providerConfig.activeCredentialId
    $inactiveCredentialId = Get-InactiveCredentialId -ActiveCredentialId $activeCredentialId
    $providerAddress = $currentSecret.providerConfig.providerAddress
    ($credentialValue, $errorMessage) = Invoke-CredentialRegeneration -InactiveCredentialId $inactiveCredentialId -ProviderAddress $providerAddress
    if ($errorMessage) {
        throw $errorMessage
    }

    # Step 3: Update the pending secret with the new credential and make it active.
    $pendingSecret = @{
        value = $credentialValue
        providerConfig = @{
            activeCredentialId = $inactiveCredentialId
            providerAddress = $providerAddress
            functionResourceId = $EXPECTED_FUNCTION_RESOURCE_ID
        }
    }
    ($updatedSecret, $errorMessage) = Update-PendingSecret -UnversionedSecretId $UnversionedSecretId -PendingSecret $pendingSecret -CallerName $callerName
    if ($errorMessage) {
        throw $errorMessage
    }

    Write-Information "Successfully rotated secret for Log Analytics workspace."
}

Invoke-MainLogic
