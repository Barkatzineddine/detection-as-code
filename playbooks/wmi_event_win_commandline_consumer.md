# WMI Event Consumer Running a Command or Script

| | |
|---|---|
| Rule | [`rules/windows/wmi_event/wmi_event_win_commandline_consumer.yml`](../rules/windows/wmi_event/wmi_event_win_commandline_consumer.yml) |
| Severity | high |
| ATT&CK | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) |
| Test samples | [`tests/data/wmi_event_win_commandline_consumer/`](../tests/data/wmi_event_win_commandline_consumer/) |

## What it means

A WMI CommandLineEventConsumer (or ActiveScriptEventConsumer) was created. Bound to an event
filter, WMI runs its command as SYSTEM every time the filter fires. The recorded Empire
persistence created a filter `Updater` firing a few minutes after boot and a consumer running
`powershell.exe -NonI -W hidden -enc ...`.

## Investigate

1. Read the consumer's destination (command) and decode it.
2. Find the matching filter (Sysmon 19) and binding (Sysmon 21) to learn the trigger.
3. List all subscriptions: `Get-CimInstance -Namespace root/subscription -ClassName __EventFilter`,
   `CommandLineEventConsumer`, `__FilterToConsumerBinding`.
4. Identify the process that created it; children of `WmiPrvSE.exe` later show it ran.

## False positives

- Some management agents (SCCM, older OEM tools) register consumers. Inventory them once
  and filter by consumer name and command.

## Respond

- Remove the binding, consumer and filter (in that order) after exporting them.
- The creator had administrator rights: investigate how, and look for other persistence.
