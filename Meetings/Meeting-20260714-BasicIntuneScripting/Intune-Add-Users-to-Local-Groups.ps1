<#
.SYNOPSIS
    Creates or Updates an Intune Custom OMA-URI Policy for Local Group Management.
.DESCRIPTION
    Resolves Entra ID Group names to SIDs and User Principal Names (UPNs). 
    It recursively flattens nested groups, deduplicates users, and constructs 
    the 'LocalUsersAndGroups' XML payload. 
    
    Includes UPNs as XML comments next to SIDs for human-readable auditing 
    within the Intune console.
.NOTES
    Requires Microsoft.Graph modules and 'DeviceManagementConfiguration.ReadWrite.All' permissions.
#>

# ==============================================================================
# 1. VARIABLES - ADMINS: JUST UPDATE THESE NAMES
# ==============================================================================

# Policy Information
$PolicyName             = "DEPT: Set User Groups via Script (Smith Lab)"
$PolicyDescription      = "Manages Administrators, Users, and RDP Groups via Entra ID Groups."

# The name of your built-in local administrator (e.g., "Administrator" or "itadmin01")
$BuiltInAdminUser       = "itadmin01" 

# Source Entra ID Group Names for each local category
$SourceUserGroupNamesAdmin = @("Admin Group 1", "Admin Group 2")
$SourceUserGroupNamesUsers = @("User Group 1", "User Group 2")
$SourceUserGroupNamesRDP   = @("RDP User Group 1", "RDP User Group 2")

# Deployment Targets
$TargetDeviceGroupNames    = @("Device Group 1", "Device Group 2")

# The abbreviation/name of your Scope Tag
$ScopeTagName              = "Default"

# ==============================================================================
# 2. TRANSCRIPT LOGGING (For Auditing)
# ==============================================================================
$LogDir = "C:\Temp\IntuneScripts"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$LogFile = "$LogDir\LocalGroup_Policy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -NoClobber

# ==============================================================================
# 3. MODULE CHECK & FUNCTIONS
# ==============================================================================
Write-Host "Checking for required Microsoft Graph modules..." -ForegroundColor Cyan

$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.DeviceManagement"
)

foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $Module)) {
        Write-Host "Installing $Module..." -ForegroundColor Yellow
        Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $Module
}

function Convert-AzureAdGuidToSid {
    param([Parameter(Mandatory)][string]$Guid)
    $guidBytes = ([guid]$Guid).ToByteArray()
    $parts = for ($i = 0; $i -lt $guidBytes.Length; $i += 4) { [BitConverter]::ToUInt32($guidBytes, $i) }
    return "S-1-12-1-$(($parts -join '-'))"
}

# Gets the SIDs and Display Names of the Groups themselves (No Expansion)
function Get-GroupObjectsFromGroupName {
    param([string[]]$GroupNames)
    $Results = @()
    foreach ($Name in $GroupNames) {
        $Grp = Get-MgGroup -Filter "displayName eq '$Name'" -Property "id,displayName"
        if ($Grp) {
            Write-Host "Resolving Entra group details: $Name" -ForegroundColor Gray
            $Results += [PSCustomObject]@{
                SID  = (Convert-AzureAdGuidToSid -Guid $Grp.Id)
                Name = $Grp.DisplayName
            }
        }
    }
    return $Results
}

# Flattens and expands users (Used exclusively for RDP)
function Get-MemberObjectsFromGroupName {
    param([string[]]$GroupNames)
    $Results = @()
    foreach ($Name in $GroupNames) {
        $Grp = Get-MgGroup -Filter "displayName eq '$Name'"
        if ($Grp) {
            Write-Host "Fetching members for Entra group: $Name" -ForegroundColor Gray
            
            $Members = Get-MgGroupTransitiveMember -GroupId $Grp.Id -All -Property "id,userPrincipalName,additionalProperties"
            
            foreach ($m in $Members) { 
                if ($m.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                    
                    $ResolvedUpn = $m.AdditionalProperties["userPrincipalName"]
                    if (-not $ResolvedUpn) { $ResolvedUpn = "Unknown" }
                    
                    $Results += [PSCustomObject]@{
                        SID = (Convert-AzureAdGuidToSid -Guid $m.Id)
                        UPN = $ResolvedUpn
                    }
                }
            }
        }
    }
    # Deduplicate by SID and return the full object
    return $Results | Group-Object SID | ForEach-Object { $_.Group[0] }
}

# ==============================================================================
# 4. CONNECT & RESOLVE
# ==============================================================================
$requiredScopes = @(
    "GroupMember.Read.All",
    "User.Read.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementRBAC.Read.All"
)

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $requiredScopes

try {
    Write-Host "Resolving Entra IDs to SIDs..." -ForegroundColor Cyan

    # Process Admin and User groups
    $AdminGroups = Get-GroupObjectsFromGroupName -GroupNames $SourceUserGroupNamesAdmin
    $UserGroups  = Get-GroupObjectsFromGroupName -GroupNames $SourceUserGroupNamesUsers

    # Process RDP Groups
    $RdpUsers   = Get-MemberObjectsFromGroupName -GroupNames $SourceUserGroupNamesRDP

    # Resolve Device Groups for Assignment
    $ResolvedDeviceGroups = @()
    foreach ($GroupName in $TargetDeviceGroupNames) {
        $Grp = Get-MgGroup -Filter "displayName eq '$GroupName'"
        if (-not $Grp) { throw "Could not find a device group named '$GroupName'." }
        $ResolvedDeviceGroups += $Grp
    }

    # Resolve Scope Tag
    $ScopeTagsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
    $ScopeTagId = ($ScopeTagsResponse.value | Where-Object { $_.displayName -eq $ScopeTagName }).id
    if (-not $ScopeTagId) { throw "Could not find a Scope Tag named '$ScopeTagName'." }

    # ==============================================================================
    # 5. BUILD THE XML PAYLOAD
    # ==============================================================================
    Write-Host "Constructing XML payload..." -ForegroundColor Cyan
    
    # ADMINISTRATORS (Replace Action)
    $XmlString = @"
<GroupConfiguration>
    <accessgroup desc="Administrators">
        <group action="R"/>
        <add member="$BuiltInAdminUser"/>
"@
    foreach ($GroupObj in $AdminGroups) { $XmlString += "`n        <add member=`"$($GroupObj.SID)`"/><!-- $($GroupObj.Name) -->" }
    $XmlString += "`n    </accessgroup>`n"

    # USERS (Replace Action)
    $XmlString += @"
    <accessgroup desc="Users">
        <group action="R"/>
        <add member="$BuiltInAdminUser"/>
"@
    foreach ($GroupObj in $UserGroups) { $XmlString += "`n        <add member=`"$($GroupObj.SID)`"/><!-- $($GroupObj.Name) -->" }
    $XmlString += "`n    </accessgroup>`n"

    # REMOTE DESKTOP USERS (Replace Action)
    $XmlString += @"
    <accessgroup desc="Remote Desktop Users">
        <group action="R"/>
"@
    foreach ($UserObj in $RdpUsers) { $XmlString += "`n        <add member=`"$($UserObj.SID)`"/><!-- $($UserObj.UPN) -->" }
    $XmlString += "`n    </accessgroup>`n"

    $XmlString += "</GroupConfiguration>"

    # ==============================================================================
    # 6. CREATE / UPDATE INTUNE POLICY
    # ==============================================================================
    $XmlByteArray = [System.Text.Encoding]::UTF8.GetBytes($XmlString)
    $Base64Xml = [Convert]::ToBase64String($XmlByteArray)

    $ExistingPolicy = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq '$PolicyName'" -ErrorAction SilentlyContinue

    $OmaSettingsJson = @(
        @{
            "@odata.type" = "#microsoft.graph.omaSettingStringXml"
            displayName   = "LocalGroupsConfig"
            description   = "Managed via PowerShell Graph API"
            omaUri        = "./Device/Vendor/MSFT/Policy/Config/LocalUsersAndGroups/Configure"
            fileName      = "localgroups.xml"
            value         = $Base64Xml
        }
    )

    if ($ExistingPolicy) {
        Write-Host "Updating existing policy: $($ExistingPolicy.Id)" -ForegroundColor Yellow
        $UpdateBody = @{
            "@odata.type"     = "#microsoft.graph.windows10CustomConfiguration"
            description       = $PolicyDescription
            omaSettings       = $OmaSettingsJson
            roleScopeTagIds   = @($ScopeTagId)
        }
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($ExistingPolicy.Id)" -Body ($UpdateBody | ConvertTo-Json -Depth 10)
        $PolicyId = $ExistingPolicy.Id
    } else {
        Write-Host "Creating new policy..." -ForegroundColor Yellow
        $CreateBody = @{
            "@odata.type"     = "#microsoft.graph.windows10CustomConfiguration"
            displayName       = $PolicyName
            description       = $PolicyDescription
            omaSettings       = $OmaSettingsJson
            roleScopeTagIds   = @($ScopeTagId)
        }
        $NewPolicy = New-MgDeviceManagementDeviceConfiguration -BodyParameter $CreateBody
        $PolicyId = $NewPolicy.Id
    }

    # ==============================================================================
    # 7. ASSIGNMENTS
    # ==============================================================================
    foreach ($DevGrp in $ResolvedDeviceGroups) {
        Write-Host "Assigning to $($DevGrp.DisplayName)..." -ForegroundColor Cyan
        $AssignmentTarget = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId = $DevGrp.Id
        }
        New-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $PolicyId -Target $AssignmentTarget -ErrorAction SilentlyContinue
    }

    Write-Host "Process Complete!" -ForegroundColor Green
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Disconnect-MgGraph
    Stop-Transcript
}