# crowdstrike-falcon-queries

<img src="https://img.shields.io/github/last-commit/pe3zx/crowdstrike-falcon-queries.svg"/> </p>

A collection of Splunk's Search Processing Language (SPL) for Threat Hunting with CrowdStrike Falcon

Developed and maintained by [Intelligent Response](https://www.i-secure.co.th/author/intelligentresponse/) team, i-secure co., Ltd.

- Execution of Renamed Executables

This query is inspired by [Red Canary's research]([Black Hat: Detecting the unknown and disclosing a new attack technique at Black Hat 2019](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/).

For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

Idea:

- Identify if there are any events with file renaming activity — found that CrowdStrike Falcon already had a specific field name for executables, `NewExecutableRenamed`.
- Correlate `TargetFileName` field on `NewExecutableRenamed` event with a filename available on `ImageFileName` field on `ProcessRollup2` event.
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, and `CommandLine` as columns.

```
event_simpleName="NewExecutableRenamed"
| rename TargetFileName as ImageFileName
| join ImageFileName [ search event_simpleName="ProcessRollup2" ]
| table ComputerName SourceFileName ImageFileName CommandLine
```
