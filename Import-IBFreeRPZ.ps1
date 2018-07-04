Function Get-IBRpzExportObjectFromFile {
    <#
    .SYNOPSIS
    Generate an object with the properties of the CSV export for RPZs
    
    .PARAMETER File
    Input file
    
    .PARAMETER Domains
    Switch variable to describe the format of the file
    
    .PARAMETER Hosts
    Switch variable to describe the format of the file
    
    .PARAMETER IPs
    Switch variable to describe the format of the file
    
    .PARAMETER ParentZone
    Name of the RPZ Zone to which we'll target for import. 
    
    .PARAMETER Source
    Name of the source of the hosts for blacklisting
    
    .PARAMETER View
    The RPZ view in which we'll be commiting these.  
    #>
    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter()][switch]$Domains,
        [Parameter()][switch]$Hosts,
        [Parameter()][switch]$IPs,
        [Parameter(Mandatory = $true)][string]$ParentZone,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$View
    )

    #define a regex to return first NON-whitespace character
    [regex]$r = "\S"

    if (-Not (Get-Item $File -ea "SilentlyContinue").Exists) { 
        Write-Error "$File does not exist"
        return 
    }

    # Strip out any lines beginning with # and blank lines
    $hostsData = Get-Content $File | where { (($r.Match($_)).value -ne "#") -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0) }
  
    if ( -Not $hostsData ) { 
        Write-Warning "$File has no entries in its domain file." 
        return
    }

    $Results = @()
    
    #only process if something was found in HOSTS file
    $hostsData | foreach {

        #created named values
        if ( $Domains ) { 
            # I'm expecting the format
            #       badguy.com  comment comment ...
            $_ -match "\s+(?<FQDN>\S+)" | Out-Null
            $fqdn = $Matches.FQDN.ToLower()
        }
        if ( $Hosts ) { 
            # I'm expecting the format
            #       127.0.0.1   badguy.com # comment
            $_ -match "(?<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?<FQDN>\S+)" | Out-Null 
            $fqdn = $Matches.FQDN.ToLower()
        }
        if ( $IPs ) { 
            # I'm expecting the format
            #       123.123.123.123 # comment
            $_ -match "(?<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" | Out-Null
            $fqdn = $Matches.IP
        }
        
        if ( $Domains -or $Hosts ) { 
            $Results += [PSCustomObject]@{
                'header-responsepolicycnamerecord' = "responsepolicycnamerecord"
                'fqdn*'                            = "$fqdn.$ParentZone"
                '_new_fqdn'                        = ""
                'canonical_name'                   = ""
                'comment'                          = "Source: $Source"
                'disabled'                         = ""
                'parent_zone'                      = $ParentZone
                'ttl'                              = ""
                'view'                             = $View
            }
        } 
        if ( $IPs ) {
            $Results += [PSCustomObject]@{
                'header-responsepolicycnamerecord' = "responsepolicycnamerecord"
                'fqdn*'                            = "$fqdn.$ParentZone"
                '_new_fqdn'                        = ""
                'canonical_name'                   = ""
                'comment'                          = "Source: $Source"
                'disabled'                         = ""
                'parent_zone'                      = $ParentZone
                'ttl'                              = ""
                'view'                             = $View
            }
        }
    } #end ForEach

    Write-Verbose "Found $($Results.Count) entries in $File"
    return $Results
} 

Function Download-Files {
    <#
    .SYNOPSIS
    Helper function to either download or copy files
    
    .DESCRIPTION
    Helper function to either download or copy files
    
    .PARAMETER Path
    Paths to files.  Can be either local paths, or remote.  If remote, be sure
    to prefix with 'http://' or 'https://'
    
    .PARAMETER DownloadsLocation
    Location where the downloaded and referenced files will reside for import.
    Defaults to $env:TEMP
    
    .PARAMETER DomainList
    Switch Parameter to let the function know to add the '-Domain.txt' suffix 
    to the file.
    
    .PARAMETER HostList
    Switch Parameter to let the function know to add the '-Hosts.txt' suffix
    to the file.
    
    .PARAMETER IPList
    Switch Parameter to let the function know to add the '-IPs.txt' suffix
    to the file.

    #>
    [CmdLetBinding()]
    Param (
        [string[]]$Path,
        [string]$DownloadsLocation = "RPZFiles",
        [switch]$DomainList,
        [switch]$HostList,
        [switch]$IPList
    )

    begin { 
        # Powershell defaults to TLS 1.0
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    }

    process {
        if ($false -eq (Test-Path $DownloadsLocation)) {
            Write-Verbose "Download File Location $DownloadsLocation Does Not Exist - Creating Directory"
            New-Item -ItemType directory -Path $DownloadsLocation -ErrorAction Stop
        }

        $FileList = @()

        foreach ( $Destination in $Path ) {
            # For urls as paths. 
            if ( ($Destination -match "http://") -or ($Destination -match "https://")) { 
                $DestHost = ([system.uri]$Destination).Host
                if ( $DomainList ) { $DestFile = Join-Path $DownloadsLocation -ChildPath "$DestHost-Domains.txt" }
                elseif ( $HostList ) { $DestFile = Join-Path $DownloadsLocation -ChildPath "$DestHost-Hosts.txt" }
                elseif ( $IPList ) { $DestFile = Join-Path $DownloadsLocation -ChildPath "$DestHost-IPs.txt" }
                else { Write-Error "Download type not specified for $Destination" }

                if (Test-Path $DestFile) { 
                    Write-Verbose "Previous version of $Destfile already exists.  Deleting."
                    remove-item $DestFile 
                }
                Write-Verbose "Downloading from $Destination"
                Invoke-WebRequest -Uri $Destination -OutFile $DestFile
                $FileList += $DestFile
            }
            # For local files.
            else {
                $DestHost = (Get-Item $file).BaseName
                if ( $DomainList ) { $DestFile = Join-Path $DownloadsLocation -ChildPath "$DestHost-Domains.txt" }
                elseif ( $HostList ) { $DestFile = Join-Path $DownloadsLocation -ChildPath "$DestHost-Hosts.txt" }
                elseif ( $IPList ) { $DestFile = Join-Path $DownloadsLocation -ChildPath "$DestHost-IPs.txt" }
                else { Write-Error "Download type not specified for $Destination" }

                if (Test-Path $DestFile) { 
                    Write-Verbose "Previous version of $Destfile already exists.  Deleting."
                    remove-item $DestFile 
                }
                Write-Verbose "Copying $Destination to $DownloadsLocation"
                Copy-Item $Destination $DestFile
                $FileList += $DestFile
            }
        }
        return $FileList
    } 
    
    end { }
}

Function Process-RPZObjects {
    Param (
        $ParentZone,
        [pscustomobject[]]$RecordResults,
        [switch]$Names,
        [switch]$IPs
    )

    if ( $Names ) { $Type = "Name" }
    if ( $IPs ) { $Type = "IP" }

    $UniqueRecordResults = ($RecordResults | Sort 'fqdn*' -Unique).Count
    $TotalRecordResults = $RecordResults.count
    Write-Verbose "$TotalRecordResults total $Type records, $UniqueRecordResults unique."
    $DuplicateRecords = 0
    $PurgedRecords = 0
    $StartTime = (get-date)
    
    $Activity = "Processing $Type Records" 
    # Populate all the name records using our results.
    if ($Names) {
        $oldRecordParams = @{
            ObjectType      = 'record:rpz:cname'
            MaxResults      = 9999999
            ReturnAllFields = $true
            Filters         = "zone=$ParentZone"
        }
    } 
    elseif ($IPS) { 
        $oldRecordParams = @{
            ObjectType      = 'record:rpz:cname:ipaddress'
            MaxResults      = 9999999
            ReturnAllFields = $true
            Filters         = "zone=$ParentZone"
        }
    }
    $Task = "Retrieving old RPZ $Type Records"
    Write-Progress -Activity $Activity -Status $Task
    $oldRecords = Get-IBObject @oldRecordParams
        
    $Task = "Comparing RPZ $Type Records"
    Write-Progress -Activity $Activity -Status $Task

    # Old Record Hash
    $oldRecordHash = @{}

    foreach ($oldRecord in $oldRecords) {
        $oldRecordHash.Add( $oldRecord.Name, "old")
    }

    # Populate a second hash with the list of duplicates
    # This is due to limitation of powershell with hashes in foreach loops.
    $dupRecordHash = @{}
        
    # and a third for new results. 
    $newRecordHash = @{}
    foreach ($result in ($RecordResults | Sort 'fqdn*' -Unique)) {
        if ($oldRecordHash.ContainsKey($result.'fqdn*')) {
            $dupRecordHash.Add($result.'fqdn*', "old")
        }
        else {
            $newRecordHash.Add($result.'fqdn*', "new")  
        }
    }
   
    foreach ($key in $dupRecordHash.Keys) {
        $oldRecordHash.Remove($key)
    }
        
    # Purging the old
    $StartTime = (Get-Date)
    $count = 1
    foreach ($oldRecord in $oldRecords) {
        if ($oldRecordHash.ContainsKey($oldRecord.Name)) {
            Remove-IBObject -ObjectRef $oldRecord._ref | Out-Null
            $Task = "Removing old $Type records from RPZ $ParentZone`: $count / $($oldRecordHash.count)"
            Write-Progress -Activity $Activity -Status $Task -PercentComplete (($count / $oldRecordHash.count) * 100)
            $count++
        }
    }
    Write-Verbose "Succesfully purged $($oldRecordHash.count) $type records."
    $EndTime = (Get-Date)
    $Duration = $EndTime - $StartTime
    Write-Verbose "Elapsed Time: $($Duration.Minutes) Minutes, $($Duration.Seconds) Seconds"
        
    # Adding the new
    $StartTime = (Get-Date)
    $count = 1
    foreach ($result in ($RecordResults | Sort 'fqdn*' -Unique)) {
        if ($newRecordHash.ContainsKey($result.'fqdn*')) {
            $NewRecord = @{
                name      = $result | select -ExpandProperty 'fqdn*'
                canonical = ''
                rp_zone   = $ParentZone
                comment   = $result.comment
                view      = $result.view
            }
            if ($Names) { New-IBObject -ObjectType 'record:rpz:cname' -IBObject $NewRecord | Out-Null }
            elseif ($IPS) { new-IBObject -ObjectType 'record:rpz:cname:ipaddress' -IBObject $NewRecord | Out-Null }
            $Task = "Adding new $type records to RPZ $ParentZone`: $count / $($newRecordHash.count)"
            Write-Progress -Activity $Activity -Status $Task -PercentComplete (($count / $newRecordHash.count) * 100)
            $count++
        }
    }
    $EndTime = (Get-Date)
    $Duration = $EndTime - $StartTime
    Write-Verbose "Successfully added $($newRecordHash.count) records"
    Write-Verbose "Elapsed Time: $($Duration.Minutes) Minutes, $($Duration.Seconds) Seconds"
    
    Write-Output "---  Stats ---"
    Write-Output "$TotalRecordResults total $type records processed, $UniqueRecordResults unique."
    Write-Output "$($dupRecordHash.count) existing $type records found already in $Parentzone."
    Write-Output "$($oldRecordHash.count) $type records were retired."
    Write-Output "$($newRecordHash.count) $type records created"        
}

Function Import-IBFreeRPZ {
    <#
    .SYNOPSIS
    Imports hosts to an Infoblox RPZ as specified by collected list files.
    
    .DESCRIPTION
    Imports hosts to an Infoblox RPZ as specified by collected list files.
    
    .PARAMETER View
    RPZ View in Infoblow
    
    .PARAMETER ParentZone
    Target RPZ Zone.
    
    .PARAMETER DownloadsLocation
    Location for the downloaded and copied files for processing.  Defaults to
    $env:TEMP
    
    .PARAMETER DomainListFiles
    Parameter description
    
    .PARAMETER HostListFiles
    Parameter description
    
    .PARAMETER IPListFiles
    Parameter description
    
    .PARAMETER OutputToFile
    Parameter description
    
    .EXAMPLE
    An example
    
 
    #>
    [CmdLetBinding(SupportsShouldProcess)]
    Param (
        [Parameter(Mandatory = $true)][string]$View,
        [Parameter(Mandatory = $true)][string]$ParentZone,
        [string]$DownloadsLocation = "$($env:TEMP)\FreeRPZ",
        [string[]]$DomainListFiles,
        [string[]]$HostListFiles,
        [string[]]$IPListFiles,
        [switch]$OutputToFile,
        [switch]$AutoUpload
    )

    begin { 
        # Confirm Posh-IBWAPI loaded and Set-IBWapiConfig 
    }

    process {
        <# Download Section #>
        $Starttime = (get-date)
        # Download files, or copy them to destination. 
        $Activity = "Downloading List Files for $ParentZone"
        $TotalFiles = $DomainListFiles.Count + $HostListFiles.Count + $IPListFiles.Count
        $Downloaded = 0

        if ( $DomainListFiles ) { 
            $Task = "Downloading Domain List Files"
            Write-Progress -Activity $Activity -Status $Task -PercentComplete ($Downloaded / $TotalFiles * 100)
            $DomainListFile = Download-Files -Path $DomainListFiles -DownloadsLocation $DownloadsLocation -DomainList
            Write-Progress -Activity $Activity -Status $Task -PercentComplete ($Downloaded / $TotalFiles * 100)  
        }
        if ( $HostListFiles ) { 
            $Task = "Downloading Hosts List Files"
            Write-Progress -Activity $Activity -Status $Task -PercentComplete ($Downloaded / $TotalFiles * 100)
            $HostListFile = Download-Files -Path $HostListFiles -DownloadsLocation $DownloadsLocation -HostList
            $Downloaded += $HostListFiles.Count
            Write-Progress -Activity $Activity -Status $Task -PercentComplete ($Downloaded / $TotalFiles * 100)          
        }
        if ( $IPListFiles ) {
            $Task = "Downloading IP List Files"
            Write-Progress -Activity $Activity -Status $Task -PercentComplete ($Downloaded / $TotalFiles * 100)
            $IPListFile = Download-Files -Path $IPListFiles -DownloadsLocation $DownloadsLocation -IPList
            $Downloaded += $IPListFiles.Count
            Write-Progress -Activity $Activity -Status $Task -PercentComplete ($Downloaded / $TotalFiles * 100)
        }
        $EndTime = (get-date)
        $Duration = $EndTime - $StartTime
        Write-Verbose "Elapsed Time: $($Duration.Minutes) Minutes, $($Duration.Seconds) Seconds"

        $Activity = "Processing Input Files for $ParentZone"
        $nameResults = @()
        <# Parse the new files and gather results. #>
        if ( $DomainListFile ) {
            $curCount = 1
            foreach ($file in $DomainListFile) {
                $Task = "Processing $curCount of $($DomainListFile.Count) domain files"
                Write-Progress -Activity $Activity -Status $Task -PercentComplete ($curCount / $DomainListFile.Count * 100)
                $Source = (Get-Item $file).BaseName 
                $nameResults += Get-IBRpzExportObjectFromFile $file $ParentZone $Source $View -Domains
                $curCount++
            }
        }
        if ( $HostListFile ) {
            $curCount = 1
            foreach ($file in $HostListFile) {
                $Task = "Processing $curCount of $($HostListFile.Count) domain files"
                Write-Progress -Activity $Activity -Status $Task -PercentComplete ($curCount / $HostListFile.Count * 100)
                $Source = (Get-Item $file).BaseName 
                $nameResults += Get-IBRpzExportObjectFromFile $file $ParentZone $Source $View -Hosts
                $curCount++
            }
        }
        if ( $OutputToFile ) {
            $OutputFile = "RPZ-$ParentZone-Names-$(get-date -Format yyyyMMdd).csv"
            $nameResults | Sort-Object -Property 'fqdn*' -Unique| Export-CSV  -Path $OutputFile -NoTypeInformation
        }
        
        if ( $AutoUpload ) {
            Process-RPZObjects -ParentZone $ParentZone -RecordResults $nameResults -Names
        }    
         
        $ipResults = @()
        if ( $IPListFile ) {   
            $curCount = 1
            foreach ($file in $IPListFile) {
                $Task = "Processing $curCount of $($IPListFile.Count) domain files"
                Write-Progress -Activity $Activity -Status $Task -PercentComplete ($curCount / $IPListFile.Count * 100)
                $Source = (Get-Item $file).BaseName 
                $ipResults += Get-IBRpzExportObjectFromFile $file $ParentZone $Source $View -IPs
                $curCount++
            }
        }
    
        if ($OutputToFile) {
            $OutputFile = "RPZ-$ParentZone-IPs-$(get-date -Format yyyyMMdd).csv"
            $ipResults | Sort-Object -Property 'fqdn*' -Unique| Export-CSV  -Path $OutputFile -NoTypeInformation
        } 

        if ( $AutoUpload ) {
            Process-RPZObjects -ParentZone $ParentZone -RecordResults $IPResults -IPs
        }
     
        Write-Verbose "Completed."
    }

    end { }
}
