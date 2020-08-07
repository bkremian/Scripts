#Requires -Version 5.1
#Requires -Modules @{ModuleName="PSFalcon";ModuleVersion='1.4.1'}
#Requires -Modules @{ModuleName="PSRiskIQ";ModuleVersion='1.0'}
<#
.SYNOPSIS
    Retrieve artifacts associated with a RiskIQ project and adds domains/hashes/IPs
    into CrowdStrike Falcon as custom IOCs
.PARAMETER PROJECTID
    The project identifier to scan for artifacts
.PARAMETER CSV
    A CSV file exported from a RiskIQ Threat Intel article
#>
[CmdletBinding()]
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
    [string] $CSV
)
begin {
    # Days before new Falcon IOCs expire
    $Expiration = 7

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
        [array] $Array = $Import | ForEach-Object {
            # Set description
            $Description = if ($ProjectId) {
                "RiskIQ ProjectId $ProjectId"
            } else {
                "RiskIQ Article $ArticleId"
            }
            # Convert type
            $Type = switch ($_.type) {
                'ip' {
                    'ipv4'
                }
                'hash_md5' {
                    'md5'
                }
                'hash_sha256' {
                    'sha256'
                }
                default {
                    $_
                }
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
                expiration_days = $Expiration
                policy = "detect"
                type = $Type
                value = $Value
            }
        }
        Write-Host "`nImporting into CrowdStrike Falcon..." -ForegroundColor DarkRed -NoNewLine

        # Add IOCs
        $AddIOCs = New-CsIoc -Body $Array

        if (-not($AddIOCs.errors)) {
            Write-Host "complete." -ForegroundColor Red

            # Export to CSV
            $Output = $Array | ForEach-Object {
                [PSCustomObject] @{
                    type = $_.type
                    value = $_.value
                    policy = $_.policy
                    expiration_days = $_.expiration_days
                    description = $_.description
                    source = $_.source
                }
            }
            # Output result file
            $Output | Export-Csv $OutputPath -NoTypeInformation
        } else {
            # Output error
            throw ($AddIOCs | ConvertTo-Json)
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