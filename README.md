# Good2Go Mobile Plan Monitor
This is a simple script intended to run as a cronjob to alert when bad conditions are present on the user's Good2Go mobile service plan. As of now, it checks for the following:
* Low data (upper limit being user-defined)
* Plan being past due
* Account status being anything other than `INSTALLED` (the normal active state)

## Usage
`python3 good2go_plan_monitor.py`

## Arguments
|Name|Type|Description|
|-|-|-|
|`--config`|`str`|The path to a configuration file. If absent, `./config.json` is used|
|`--ignore-408`|flag|If set, do not alert when an `HTTPError` with response status 408 is raised|

## Configuration
See config.json.example for an example configuration.

The `auth` section contains login credentials for the Good2Go Mobile website.
Set `phone_number` to the MDN (10-digit phone number) you want monitored.
Set `low_data_warning_bytes` to the upper limit that the script should alert on (defaults to 50MiB).
