# Infoblox

Currently for these scripts, I use Ryan Bolger's [Posh-IBWAPI](https://github.com/rmbolger/Posh-IBWAPI). It's 
really flexible, and I'm probably not using it to its fullest.

 **In order to use these scripts, Posh-IBWAPI is a prerequisite.** 

## Infoblox-FreeRPZ

This is a script I use to update my own Local RPZs.   There are some caveats with this, though, as it will 
both increase your local object count, and decrease your effective capacity.  The benefits include being able
to extend your local protection to threats past 2013. (I was on a call with my rep and we couldn't find a 
recent threat in the base, antimalware, ransomware, dhs-ais-ip, dhs-ais.domain feeds.  Which is sad, since I'm
paying for it.) There are probably better ways of doing this, and you might need to manuall review/purge your 
Recycle Bin for records that phase out.  I'll look into automating that part soon.

The point of this is to allow me to create a few local RPZs and update them by pointing to freely available 
resources online.  I can usually find the resources in the forms of 
1) Domain Lists
2) Hosts Files
3) IP Lists

To set up, 
1) go to your grid master's web interface Data Management -> DNS -> Name Server Groups.  I like to have a 
Separate local group for overrides.  You can set this up here.   
2) Go to Response Policy Zones tab
3) Make note of the view that you want to add this RPZ to, such as `default` or `internal`. Go into that view.
4) Click Add -> Local Response Policy Zone.  Click Next.
5) Name it something like `my-malware-blacklist`, set a policy override if you like (this currently sets all 
incoming records as NXDOMAIN), change the severity if you like, depending on your reporting. Click Next.
6) Change the value of Use This Nameserver Group to your Local RPZ Group. Click Save and Close.
7) I like to change the order of this so that it is the lowest ranking RPZ.  That will let you know what fell
through the cracks of your Active Trust subscription, if you have one. There's a option on the right hand side
to "Order Response Policy Zones". 
8) Invoke the Import-IBFreeRPZ function.

Here's an example in how to invoke for our newly created malware blocking RPZ using external lists.  
 **In order to use these scripts, Make sure Posh-IBWAPI is installed from PSGallery.**

~~~ Powershell
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
~~~

And if you want an internal adblock, like [Pi-Hole](https://pi-hole.net), you could probably create 
one using their adlists, but it would mean a lot of RPZ Events, and any useful canned reports would be shot.

