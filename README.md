# Good2Go Mobile Plan Monitor
This is a simple script intended to run as a cronjob to alert when bad conditions are present on the user's Good2Go mobile service plan. As of now, it checks for the following:
* Low data (upper limit being user-defined)
* Plan being past due

## Usage
`python3 good2go_plan_monitor.py`

## Arguments
|Name|Type|Description|
|-|-|-|
|`--config`|`str`|The path to a configuration file. If absent, `./config.json` is used|

## Configuration
See config.json.example for an example configuration.

The `auth` section contains login credentials for the Good2Go Mobile website.
Set `low_data_warning_bytes` to the upper limit that the script should alert on (defaults to 50MiB).

Last, and here's the fun part - you need to find your "account ID". At this time, I do not know how this value is generated, so you'll need to rip it out of your browser when authenticated to the site. After logging in, open your browser's network console and look for an XHR GET request to the following URL `https://www.good2gomobile.com/api/plan/ACCOUNT_ID/account/PHONE_NUMBER/sync`. Simply copy the `ACCOUNT_ID` value from that URL into your config file.
