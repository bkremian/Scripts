#Requires -Version 5.1
#Requires -Modules @{ModuleName="PSFalcon";ModuleVersion='2.0.0'}
#Requires -Modules @{ModuleName="PSRiskIQ";ModuleVersion='1.0.2'}
<#
.SYNOPSIS
    Retrieve artifacts associated with a RiskIQ project and adds domains/hashes/IPs
    into CrowdStrike Falcon as custom IOCs
.PARAMETER PROJECTID
    The project identifier to scan for artifacts
.PARAMETER CSV
    A CSV file exported from a RiskIQ Threat Intel article
.PARAMETER PLATFORMS
    The operating system platforms to assign the IOCs (default: 'windows', 'mac', 'linux')
.PARAMETER EXPIRATION
    The number of days before the IOC expires (default: 1)
#>
[CmdletBinding(DefaultParameterSetName = 'API')]
[OutputType()]
param(
    [Parameter(
        ParameterSetName = 'API',
        Position = 1,
        Mandatory=$true)]
    [ValidatePattern('\w{8}-\w{4}-\w{4}-\w{4}-\w{12}')]
    [string] $ProjectId,

    [Parameter(
        ParameterSetName = 'CSV',
        Position = 1,
        Mandatory=$true)]
    [ValidateScript({ Test-Path $_ })]
    [string] $CSV,

    [Parameter(
        ParameterSetName = 'API',
        Position = 2)]
    [Parameter(
        ParameterSetName = 'CSV',
        Position = 2)]
    [ValidateSet('windows', 'mac', 'linux')]
    [array] $Platforms,

    [Parameter(
        ParameterSetName = 'API',
        Position = 3)]
    [Parameter(
        ParameterSetName = 'CSV',
        Position = 3)]
    [int] $Expiration
)
begin {
    # Maximum number of IOCs per add request
    $MaxCount = 200

    if (-not $Platforms) {
        # Set default platforms
        $Platforms = @('windows', 'mac', 'linux')
    }
    if (-not $Expiration) {
        # Set expiration days
        $Expiration = 1
    }
    # Convert expiration date format
    $ExpirationDate = (Get-Date).AddDays($Expiration)

    $Import = if ($ProjectId) {
        # Retrieve artifacts from ProjectId
        $Request = Get-RiskArtifact -ProjectId $ProjectId

        if ($Request.artifacts) {
            # Collect artifacts from API response
            $Request.artifacts | Where-Object { $_.type -match '(domain|hash_md5|hash_sha256|ip)' } |
                Select-Object type, query
        }
    } else {
        # Retrieve artifacts from CSV
        Import-Csv $CSV | Where-Object { $_.type -match '(domain|hash_md5|hash_sha256|ip)' } |
            Select-Object type, value
    }
    if ($CSV) {
        # Collect ArticleId
        [regex] $Regex = '(?:passivetotal_article_)(\w+)(?:.csv)'
        $ArticleId = $Regex.matches(($CSV | Split-Path -Leaf)).value -replace '(passivetotal_article_)|(.csv)',''
    }
    # Output filename
    $OutputPath = if ($ProjectId) {
        "$pwd\$(Get-Date -Format yyyy-MM-dd)_$($ProjectId).csv"
    } else {
        "$pwd\$(Get-Date -Format yyyy-MM-dd)_$($ArticleId).csv"
    }
}
process {
    if ($Import) {
        # Notify user of artifacts found
        if ($ProjectId) {
            Write-Host "`nRiskIQ ProjectId " -ForegroundColor Blue -NoNewline
            Write-Host "$ProjectId" -ForegroundColor Cyan -NoNewline
        } else {
            Write-Host "`nRiskIQ Article " -ForegroundColor Blue -NoNewline
            Write-Host "$ArticleId" -ForegroundColor Cyan -NoNewline
        }
        Write-Host " artifacts:`n" -ForegroundColor Blue

        foreach ($Type in @('domain', 'ip', 'hash_md5', 'hash_sha256')) {
            if (($Import | Where-Object { $_.type -eq $Type }).count -gt 0) {
                Write-Host "  $(($Import | Where-Object { $_.type -eq $Type }).count)" -ForegroundColor Cyan -NoNewline
                Write-Host " $Type result(s)" -ForegroundColor Blue
            }
        }
        [array] $Array = $Import.foreach{
            # Set description
            $Description = if ($ProjectId) {
                "RiskIQ ProjectId $ProjectId"
            } else {
                "RiskIQ Article $ArticleId"
            }
            # Convert type
            $Type = switch ($_.type) {
                'ip'          { 'ipv4' }
                'hash_md5'    { 'md5' }
                'hash_sha256' { 'sha256' }
                default       { $_ }
            }
            # Convert value from API/CSV
            $Value = if ($_.query) {
                $_.query
            } else {
                $_.value
            }
            # Output IOC
            @{
                description = $Description
                action = "detect"
                type = $Type
                value = $Value
                platforms = $Platforms
                expiration = $ExpirationDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                applied_globally = $true
            }
        }
        Write-Host "`nImporting into CrowdStrike Falcon..." -ForegroundColor DarkRed -NoNewLine

        try {
            $AddIOCs = for ($i = 0; $i -le $Array.count; $i += $MaxCount) {
                # Add IOCs in groups, to avoid maximum limits
                New-FalconIOC -Array $Array[$i..($i + ($MaxCount - 1))]
            }
            if ($AddIOCs) {
                Write-Host "complete." -ForegroundColor Red

                # Export to CSV
                $Output = $Array.foreach{
                    [PSCustomObject] @{
                        type = $_.type
                        value = $_.value
                        action = $_.action
                        platforms = $_.platforms -join ','
                        expiration = $_.expiration
                        description = $_.description
                        applied_globally = $_.applied_globally
                    }
                }
                # Output result file
                $Output | Export-Csv $OutputPath -NoTypeInformation
            }
        } catch {
            # Output error
            throw $_
        }
    } else {
        # Output error
        throw "No results available for import"
    }
}
end {
    if (Test-Path $OutputPath) {
        # Display output file to user
        Get-ChildItem $OutputPath
    }
}
