# 1. Define your Group IDs
$SourceUserGroupId  = "Source User Group ID Here"  # Replace with your source user group ID
$TargetDeviceGroupId = "Target Device Group ID Here"  # Replace with your target device group ID

# 2. Connect to Graph (Stripped down to only required scopes)
$Scopes = @(
    "GroupMember.ReadWrite.All", 
    "User.Read.All", 
    "Device.Read.All", 
    "DeviceManagementManagedDevices.Read.All"
)
Connect-MgGraph -Scopes $Scopes

Write-Host "Fetching members from the source user group..." -ForegroundColor Cyan
$GroupMembers = Get-MgGroupMember -GroupId $SourceUserGroupId -All | Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user" }

if ($null -eq $GroupMembers) {
    Write-Warning "No users found in the specified source group."
    return
}

# Collection for unique Entra ID Device Object IDs
$DeviceIdsToAssign = [System.Collections.Generic.List[string]]::new()

Write-Host "Scanning users for Intune Primary User devices..." -ForegroundColor Cyan
foreach ($User in $GroupMembers) {
    # We must use UPN or Email to query Intune Primary User
    $UserUPN = $User.AdditionalProperties["userPrincipalName"] 
    
    if ($UserUPN) {
        # Query Intune for devices where this user is the Primary User
        $IntuneDevices = Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$UserUPN'" -All
        
        foreach ($IntuneDevice in $IntuneDevices) {
            $EntraDeviceId = $IntuneDevice.AzureADDeviceId
            
            if ($EntraDeviceId) {
                # Map the Intune 'AzureADDeviceId' to the Entra 'ObjectId' required for group membership
                $EntraDeviceObject = Get-MgDevice -Filter "deviceId eq '$EntraDeviceId'"
                
                if ($EntraDeviceObject -and -not $DeviceIdsToAssign.Contains($EntraDeviceObject.Id)) {
                    $DeviceIdsToAssign.Add($EntraDeviceObject.Id)
                    Write-Host "Found corporate device ($($IntuneDevice.DeviceName)) for user $UserUPN" -ForegroundColor Gray
                }
            }
        }
    }
}

Write-Host "Found $($DeviceIdsToAssign.Count) unique corporate managed devices." -ForegroundColor Green

# 3. Fetch existing members of the target group to avoid duplicate errors
$ExistingMembers = Get-MgGroupMember -GroupId $TargetDeviceGroupId -All | Select-Object -ExpandProperty Id

# 4. Assign devices to the target group
Write-Host "Assigning devices to the target group..." -ForegroundColor Cyan
foreach ($DeviceId in $DeviceIdsToAssign) {
    if ($DeviceId -in $ExistingMembers) {
        Write-Host "Device $DeviceId is already a member of the target group. Skipping..." -ForegroundColor Yellow
    } else {
        try {
            New-MgGroupMemberByRef -GroupId $TargetDeviceGroupId -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceId"
            Write-Host "Successfully added device $DeviceId to the group." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to add device $DeviceId. Error: $_"
        }
    }
}

Write-Host "Process complete!" -ForegroundColor Magenta