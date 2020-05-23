# crowdstrike-falcon-queries

<img src="https://img.shields.io/github/last-commit/pe3zx/crowdstrike-falcon-queries.svg"/> </p>

A collection of Splunk's Search Processing Language (SPL) for Threat Hunting with CrowdStrike Falcon

Developed and maintained by [Intelligent Response](https://www.i-secure.co.th/author/intelligentresponse/) team, i-secure co., Ltd.

- [crowdstrike-falcon-queries](#crowdstrike-falcon-queries)
  - [Execution of Renamed Executables](#execution-of-renamed-executables)
  - [List of Living Off The Land Binaries with Network Connections](#list-of-living-off-the-land-binaries-with-network-connections)
  - [Suspicious Network Connections from Processes](#suspicious-network-connections-from-processes)
  - [Suspicious PowerShell Process, Spawned from Explorer, with Network Connections](#suspicious-powershell-process-spawned-from-explorer-with-network-connections)
  - [Threat Hunting #1 - RDP Hijacking traces - Part 1](#threat-hunting-1---rdp-hijacking-traces---part-1)
  - [Threat Hunting #2 - Detecting PsLoggedOn exec using EID 5145](#threat-hunting-2---detecting-psloggedon-exec-using-eid-5145)

## Execution of Renamed Executables

This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

Idea:

- Identify if there are any events with file renaming activity � found that CrowdStrike Falcon already had a specific field name for executables, `NewExecutableRenamed`.
- Correlate `TargetFileName` field on `NewExecutableRenamed` event with a filename available on `ImageFileName` field on `ProcessRollup2` event.
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, and `CommandLine` as columns.

```
event_simpleName="NewExecutableRenamed"
| rename TargetFileName as ImageFileName
| join ImageFileName 
    [ search event_simpleName="ProcessRollup2" ]
| table ComputerName SourceFileName ImageFileName CommandLine
```

## List of Living Off The Land Binaries with Network Connections

This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

Idea:

- Identify if there are any events relating to network activity � found that CrowdStrike Falcon has `DnsRequest` and `NetworkConnectIP4` events. We�re going to use the `DnsRequest` event in this query.
- Correlate `ContextProcessId` field from `DnsRequest` event with `TargetProcessId` on `ProcessRollup2` event.
- Create a sub-search to filter only known LOLBas files.
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, and `CommandLine` as columns. 

Because our hunting query required a list of known LOL binaries/files for filtering, we need to enumerate a list of files available on [LOLBAS-Project/LOLBas](https://github.com/LOLBAS-Project/LOLBAS), which can simple by done by a `grep` expression: `grep -Poh "(?<=Name:\s)[A-Za-z0-9_-]+.exe$" OSBinaries/`

```
event_simpleName="DnsRequest"
| rename ContextProcessId as TargetProcessId
| join TargetProcessId 
    [ search event_simpleName="ProcessRollup2" (FileName=Atbroker.exe OR FileName=Bash.exe OR FileName=Bitsadmin.exe OR FileName=Certutil.exe OR FileName=Cmd.exe OR FileName=Cmstp.exe OR FileName=Control.exe OR FileName=Cscript.exe OR FileName=Csc.exe OR FileName=Dfsvc.exe OR FileName=Diskshadow.exe OR FileName=Dnscmd.exe OR FileName=Esentutl.exe OR FileName=Eventvwr.exe OR FileName=Expand.exe OR FileName=Extexport.exe OR FileName=Extrac32.exe OR FileName=Findstr.exe OR FileName=Forfiles.exe OR FileName=Ftp.exe OR FileName=Gpscript.exe OR FileName=Hh.exe OR FileName=Ie4uinit.exe OR FileName=Ieexec.exe OR FileName=Infdefaultinstall.exe OR FileName=Installutil.exe OR FileName=Jsc.exe OR FileName=Makecab.exe OR FileName=Mavinject.exe OR FileName=Mmc.exe OR FileName=Msconfig.exe OR FileName=Msdt.exe OR FileName=Mshta.exe OR FileName=Msiexec.exe OR FileName=Odbcconf.exe OR FileName=Pcalua.exe OR FileName=Pcwrun.exe OR FileName=Presentationhost.exe OR FileName=Print.exe OR FileName=Regasm.exe OR FileName=Regedit.exe OR FileName=Register-cimprovider.exe OR FileName=Regsvcs.exe OR FileName=Regsvr32.exe OR FileName=Reg.exe OR FileName=Replace.exe OR FileName=Rpcping.exe OR FileName=Rundll32.exe OR FileName=Runonce.exe OR FileName=Runscripthelper.exe OR FileName=Schtasks.exe OR FileName=Scriptrunner.exe OR FileName=Sc.exe OR FileName=SyncAppvPublishingServer.exe OR FileName=Verclsid.exe OR FileName=Wab.exe OR FileName=Wmic.exe OR FileName=Wscript.exe OR FileName=Wsreset.exe OR FileName=Xwizard.exe) ] 
| table ComputerName timestamp ImageFileName DomainName CommandLine 
```

## Suspicious Network Connections from Processes

This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

Idea:

- Identify network activities recorded by CrowdStrike falcon with the `DNSRequest` or `NetworkConnectIP4` event, in this query we will use `NetworkConnectIP4`.
- Correlate `ContextProcessId_decimal` with `TargetProcessId_decimal` on `ProcessRollup2` events
- Create a result table with `RemoteIP`, `RemotePort_decimal`, `ImageFileName`, `UserName` and `UserSid_readable`.

```
event_simpleName="NetworkConnectIP4"
| rename ContextProcessId_decimal as TargetProcessId_decimal
| join TargetProcessId_decimal 
    [ search event_simpleName=ProcessRollup2 ]
| table RemoteIP RemotePort_decimal ImageFileName UserName UserSid_readabl
```

## Suspicious PowerShell Process, Spawned from Explorer, with Network Connections

This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

Idea:

- Identify network activities recorded by CrowdStrike falcon with the `DNSRequest` event
- Correlate `ContextProcessId` field on `DNSRequest` with `TargetProcessId` on `ProcessRollup2` and `SyntheticProcessRollup2` events
- With a combination of *rename-join-subsearch*, the outer nested sub-search will be created and responsible for identifying a `TargetProcessId_decimal` of `Explorer.exe` from `ProcessRollup2` event, and then join with the inner nested sub-search that responsible to find `PowerShell.exe` which has the same `ParentProcessId_decimal` as `TargetProcessId_decimal` of `Explorer.exe`
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, `DomainName`, and `CommandLine`

Be aware that whenever `ParentProcessId_decimal` is used, you may need to extend a search scope longer than usual. Because some processes, especially system processes, usually have high uptime but been abused recently.

```
event_simpleName="DnsRequest"
| rename ContextProcessId as TargetProcessId
| join TargetProcessId 
    [ search (event_simpleName="ProcessRollup2" OR event_simpleName="SyntheticProcessRollup2") AND FileName="explorer.exe" 
    | rename TargetProcessId_decimal as ParentProcessId_decimal 
    | join ParentProcessId_decimal 
        [ search event_simpleName="ProcessRollup2" FileName="powershell.exe" ]] 
| table ComputerName timestamp ImageFileName DomainName CommandLine
```

## Threat Hunting #1 - RDP Hijacking traces - Part 1

This query is inspired by [MENASEC's research](https://blog.menasec.net/2019/02/of-rdp-hijacking-part1-remote-desktop.html).

CrowdStrike has an event category named `RegSystemConfigValueUpdate` for this kind of behavior. However, `LastLoggedOnUser` and `LastLoggedOnSAMUser` aren't considered a system config. So, we can find an attempt to edit `RDP-Tcp\PortNumber` only.

```
event_simpleName="RegSystemConfigValueUpdate" AND RegObjectName="*\RDP-Tcp" AND RegValueName="PortNumber" 
| rename RegNumericValue_decimal as "NewRDPPort"
| table timestamp, ComputerName, NewRDPPort
```

## Threat Hunting #2 - Detecting PsLoggedOn exec using EID 5145

This query is inspired by [MENASEC's research](https://blog.menasec.net/2019/02/threat-hunting-detecting-psloggedon.html)

*No events related to this activity*