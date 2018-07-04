Import-Module Posh-IBWAPI

. .\Import-IBFreeRPZ.ps1

$IBConfigParams = @{
    WAPIHost                    = "gridmaster.mydomain.com"
    WAPIVersion                 = "latest"
    Credential                  = (Get-Credential)
    IgnoreCertificateValidation = $true
}
Set-IBWAPIConfig @IBConfigParams

$MalwareBlacklistParams = @{
    # These parameters must be updated. 
    View            = 'default'
    ParentZone      = 'my-malware-blacklist'
    # These ListFiles can be local or remote. Just be sure to use http or https
    # prefix if remote, and point directly at the file in question.  Sorted by Format  
    DomainListFiles = @("http://mirror1.malwaredomains.com/files/domains.txt")
    HostListFiles   = @("http://www.malwaredomainlist.com/hostslist/hosts.txt", `
            "https://zeustracker.abuse.ch/blocklist.php?download=hostfile")
    IPListFiles     = @("http://www.malwaredomainlist.com/hostslist/ip.txt", `
            "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist")
    # These are optional
    AutoUpload      = $true
    OutputToFile    = $false   
    Verbose         = $true
}
Import-IBFreeRPZ @MalwareBlacklistParams

