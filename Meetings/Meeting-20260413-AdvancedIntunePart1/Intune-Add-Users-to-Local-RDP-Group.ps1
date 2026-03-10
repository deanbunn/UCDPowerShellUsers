<#
.SYNOPSIS
    Creates or Updates an Intune Custom OMA-URI Policy for RDP Access via Security Groups.
.DESCRIPTION
    Allows admins to input multiple standard Group Names and Scope Tag names. The script 
    resolves these to Entra Object IDs, recursively retrieves nested users, deduplicates 
    them, builds the LocalUsersAndGroups XML using Entra SIDs, and assigns the policy.
#>

# ==============================================================================
# 1. VARIABLES - ADMINS: JUST UPDATE THESE NAMES
# ==============================================================================

# Name of the Intune policy to create/update
$PolicyName            = "Policy Name"

# Description for the policy
$PolicyDescription     = "Policy Description"

# Array of group names that contain the users to be added to the RDP Users list
$SourceUserGroupNames  = @("User Group 1", "User Group 2")

# Array of Device group names that will be added to the policy assignment
$TargetDeviceGroupNames= @("Device Group 1", "Device Group 2")

# The abbreviation/name of your Scope Tag
$ScopeTagName          = "Scope Tag"


# ==============================================================================
# 2. TRANSCRIPT LOGGING (For Auditing)
# ==============================================================================
$LogDir = "C:\Temp\IntuneScripts"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$LogFile = "$LogDir\RDP_Policy_Update_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -NoClobber

# ==============================================================================
# 3. MODULE CHECK & IMPORT
# ==============================================================================
Write-Host "Checking for required Microsoft Graph modules..." -ForegroundColor Cyan

$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Groups", "Microsoft.Graph.Users", "Microsoft.Graph.DeviceManagement")
foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $Module)) {
        Write-Host "Installing $Module..." -ForegroundColor Yellow
        Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $Module
}

# ==============================================================================
# 4. CONNECT TO GRAPH 
# ==============================================================================
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "GroupMember.Read.All", "User.Read.All", "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementRBAC.Read.All"

try {
    # ==============================================================================
    # 5. RESOLVE NAMES TO IDs 
    # ==============================================================================
    Write-Host "Resolving names to Entra IDs..." -ForegroundColor Cyan
    
    # Resolve all User Groups
    $ResolvedUserGroups = @()
    foreach ($GroupName in $SourceUserGroupNames) {
        $Grp = Get-MgGroup -Filter "displayName eq '$GroupName'"
        if (-not $Grp) { throw "Could not find a user group named '$GroupName'." }
        $ResolvedUserGroups += $Grp
    }
    
    # Resolve all Device Groups
    $ResolvedDeviceGroups = @()
    foreach ($GroupName in $TargetDeviceGroupNames) {
        $Grp = Get-MgGroup -Filter "displayName eq '$GroupName'"
        if (-not $Grp) { throw "Could not find a device group named '$GroupName'." }
        $ResolvedDeviceGroups += $Grp
    }
    
    Write-Host "Querying Graph API for Scope Tags..." -ForegroundColor Cyan
    $ScopeTagsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
    $ScopeTagId = ($ScopeTagsResponse.value | Where-Object { $_.displayName -eq $ScopeTagName }).id

    if (-not $ScopeTagId) { throw "Could not find a Scope Tag named '$ScopeTagName'." }

    Write-Host "Successfully resolved all names to IDs!" -ForegroundColor Green

    # ==============================================================================
    # 6. FETCH GROUP MEMBERS RECURSIVELY & CALCULATE SIDs
    # ==============================================================================
    
    # HELPER FUNCTION: Must be declared before it is called below
    function Convert-AzureAdGuidToSid {
        param(
            [Parameter(Mandatory)]
            [string]$Guid
        )
        $guidBytes = ([guid]$Guid).ToByteArray()
        $parts = for ($i = 0; $i -lt $guidBytes.Length; $i += 4) {
            [BitConverter]::ToUInt32($guidBytes, $i)
        }
        return "S-1-12-1-$(($parts -join '-'))"
    }

    $AllMemberIds = @()
    
    foreach ($Grp in $ResolvedUserGroups) {
        Write-Host "Fetching recursive members from User Group: $($Grp.DisplayName)..." -ForegroundColor Cyan
        # Using TransitiveMember to automatically crawl down through nested groups
        $Members = Get-MgGroupTransitiveMember -GroupId $Grp.Id -All
        if ($Members) {
            $AllMemberIds += $Members.Id
        }
    }

    # Deduplicate Object IDs to save API calls if a user is in multiple groups
    $UniqueMemberIds = $AllMemberIds | Select-Object -Unique
    Write-Host "Found $($UniqueMemberIds.Count) unique directory objects across all groups. Querying user details..." -ForegroundColor Cyan

    $MemberInfo = @()
    foreach ($UserId in $UniqueMemberIds) {
        # Silently continue filters out devices/service principals that might be in the groups
        $User = Get-MgUser -UserId $UserId -ErrorAction SilentlyContinue -Property userPrincipalName
        if (-not $User.UserPrincipalName) { continue }

        # FORCE the Entra Cloud SID generation using the $UserId from the loop
        $sid = Convert-AzureAdGuidToSid -Guid $UserId

        $MemberInfo += [pscustomobject]@{
            UPN = $User.UserPrincipalName
            SID = $sid
        }
    }

    Write-Host "Successfully translated $($MemberInfo.Count) valid users for the XML payload." -ForegroundColor Green

    # ==============================================================================
    # 7. BUILD THE XML PAYLOAD
    # ==============================================================================
    Write-Host "Constructing XML payload..." -ForegroundColor Cyan
    
    $XmlString = @"
<GroupConfiguration>
    <accessgroup desc="Remote Desktop Users">
        <group action="U"/>
"@

    foreach ($m in $MemberInfo) {
        $XmlString += "`n        <add member=`"$($m.SID)`"/>"
    }

    $XmlString += @"
    
    </accessgroup>
</GroupConfiguration>
"@

    $XmlByteArray = [System.Text.Encoding]::UTF8.GetBytes($XmlString)

    # ==============================================================================
    # 8. CHECK FOR EXISTING POLICY & CREATE/UPDATE
    # ==============================================================================
    Write-Host "Checking for existing Intune Policy: '$PolicyName'..." -ForegroundColor Cyan
    
    $ExistingPolicy = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq '$PolicyName'" -ErrorAction SilentlyContinue

    $OmaSettings = @(
        @{
            "@odata.type" = "#microsoft.graph.omaSettingStringXml"
            displayName = "RDP Users Config"
            description = "Automated via Graph API Script"
            omaUri = "./Device/Vendor/MSFT/Policy/Config/LocalUsersAndGroups/Configure"
            fileName = "rdp_config.xml"
            value = $XmlByteArray
        }
    )

    $OmaSettingsJson = @(
        @{
            "@odata.type" = "#microsoft.graph.omaSettingStringXml"
            displayName   = "RDP Users Config"
            description   = "Automated via Graph API Script"
            omaUri        = "./Device/Vendor/MSFT/Policy/Config/LocalUsersAndGroups/Configure"
            fileName      = "rdp_config.xml"
            value         = [Convert]::ToBase64String($XmlByteArray)
        }
    )

    $PolicyId = $null

    if ($ExistingPolicy) {
        Write-Host "Policy found! Updating the existing user list, description, and scope tags..." -ForegroundColor Yellow
        $PolicyId = $ExistingPolicy.Id
        
        $UpdateBody = @{
            "@odata.type"     = "#microsoft.graph.windows10CustomConfiguration"
            description       = $PolicyDescription
            omaSettings       = $OmaSettingsJson
            roleScopeTagIds   = @($ScopeTagId)
        }
        $UpdateJson = $UpdateBody | ConvertTo-Json -Depth 10
        $PatchUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId"
        Invoke-MgGraphRequest -Method PATCH -Uri $PatchUri -Body $UpdateJson -ContentType "application/json"

        Write-Host "Policy successfully updated!" -ForegroundColor Green
    } else {
        Write-Host "Policy not found. Creating a new policy..." -ForegroundColor Yellow
        
        $CreateBody = @{
            "@odata.type"     = "#microsoft.graph.windows10CustomConfiguration"
            displayName       = $PolicyName
            description       = $PolicyDescription
            omaSettings       = $OmaSettings
            roleScopeTagIds   = @($ScopeTagId)
        }
        
        $NewPolicy = New-MgDeviceManagementDeviceConfiguration -BodyParameter $CreateBody
        $PolicyId = $NewPolicy.Id
        Write-Host "Policy created successfully!" -ForegroundColor Green

        Start-Sleep -Seconds 5
        $UpdateBody = @{
            "@odata.type"     = "#microsoft.graph.windows10CustomConfiguration"
            description       = $PolicyDescription
            omaSettings       = $OmaSettingsJson
            roleScopeTagIds   = @($ScopeTagId)
        }
        $UpdateJson = $UpdateBody | ConvertTo-Json -Depth 10
        $PatchUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId"
        Invoke-MgGraphRequest -Method PATCH -Uri $PatchUri -Body $UpdateJson -ContentType "application/json"
    }

    # ==============================================================================
    # 9. ASSIGN POLICY TO ALL TARGETED DEVICE GROUPS
    # ==============================================================================
    Write-Host "Checking policy assignments for Target Device Groups..." -ForegroundColor Cyan
    
    $ExistingAssignments = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $PolicyId -ErrorAction SilentlyContinue
    
    foreach ($DevGrp in $ResolvedDeviceGroups) {
        $AlreadyAssigned = $false
        
        if ($ExistingAssignments) {
            foreach ($Assignment in $ExistingAssignments) {
                $TargetId = if ($Assignment.Target.GroupId) { $Assignment.Target.GroupId } else { $Assignment.Target.AdditionalProperties["groupId"] }
                if ($TargetId -eq $DevGrp.Id) {
                    $AlreadyAssigned = $true
                    break
                }
            }
        }

        if (-not $AlreadyAssigned) {
            Write-Host "Assigning policy to Device Group: $($DevGrp.DisplayName)..." -ForegroundColor Yellow
            
            $AssignmentTarget = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId = $DevGrp.Id
            }
            
            New-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $PolicyId -Target $AssignmentTarget -ErrorAction Stop
            Write-Host "Policy assignment complete for $($DevGrp.DisplayName)!" -ForegroundColor Green
        } else {
            Write-Host "Policy is already assigned to $($DevGrp.DisplayName)." -ForegroundColor Green
        }
    }

}
catch {
    Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # ==============================================================================
    # 10. DISCONNECT & STOP TRANSCRIPT
    # ==============================================================================
    Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Cyan
    Disconnect-MgGraph
    Stop-Transcript
}