[CmdletBinding()]
param (
    [string]$UsersFile = (Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath 'users.txt')
)

# make sure the ActiveDirectory module is available
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -Path $UsersFile)) {
    Write-Error "User file '$UsersFile' does not exist."
    return
}

$lines = Get-Content -Path $UsersFile
$users = @()
$admins = @()
$inAdminSection = $false

foreach ($line in $lines) {
    $trim = $line.Trim()
    if ($trim -eq '') {
        continue
    }
    if (-not $inAdminSection -and $trim -ieq 'Admin List') {
        $inAdminSection = $true
        continue
    }

    if ($inAdminSection) {
        # each remaining non-blank line is a logon name for an admin
        $admins += $trim
    }
    else {
        $parts = $trim -split ',\s*'
        if ($parts.Count -lt 3) {
            Write-Warning "Skipping malformed line: '$trim'"
            continue
        }
        $users += [pscustomobject]@{
            DisplayName   = $parts[0].Trim()
            SamAccountName = $parts[1].Trim()
            Description   = $parts[2].Trim()
        }
    }
}

# derive UPN suffix from domain
$domain = (Get-ADDomain).DnsRoot
$password  = ConvertTo-SecureString 'Secure!23' -AsPlainText -Force

foreach ($u in $users) {
    Write-Verbose "Processing user $($u.SamAccountName)"

    # create the account if it doesn't already exist
    if (-not (Get-ADUser -Filter { SamAccountName -eq $u.SamAccountName } -ErrorAction SilentlyContinue)) {
        New-ADUser -Name           $u.DisplayName `
                   -SamAccountName  $u.SamAccountName `
                   -UserPrincipalName "$($u.SamAccountName)@$domain" `
                   -DisplayName     $u.DisplayName `
                   -Description     $u.Description `
                   -AccountPassword $password `
                   -Enabled         $true `
                   -PasswordNeverExpires $true `
                   -CannotChangePassword $true `
                   -PassThru | Out-Null
        Write-Verbose "Created user $($u.SamAccountName)"
    }
    else {
        Write-Verbose "User $($u.SamAccountName) already exists" 
    }

    Add-ADGroupMember -Identity 'Domain Users' -Members $u.SamAccountName -ErrorAction SilentlyContinue
}

foreach ($a in $admins) {
    # ensure the account exists before attempting to add to group
    $acct = Get-ADUser -Identity $a -ErrorAction SilentlyContinue
    if (-not $acct) {
        Write-Warning "Admin account '$a' not found in domain; skipping group assignment."
        continue
    }
    Add-ADGroupMember -Identity 'Domain Admins' -Members $a -ErrorAction SilentlyContinue
}

Write-Host 'Processing complete.'
