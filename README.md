# zap-cicd-integration

A python script designed to be integrated into CI/CD pipelines as part of the vulnerability assessment stage along with the use of OWASP Zed Attack Proxy (ZAP). 

The current capabilities of the script include:

- Ability to suppress false positives from alert summaries and reports
- Output Team Foundation Server (TFS) logging commands
- Fail Team Foundation Server (TFS) builds and releases according to alerts
- Attach HTML reports to Team Foundation Server (TFS) logs

## Requirements
- Python 3.6 or later
- python-owasp-zap-v2.4 package
- Running instance of OWASP ZAP

## Usage
```
usage: zap.py [-h] -t T [-c C] [-s S] [-r R] [-host HOST] [-port PORT]
              [-api API] [-tfs]

A Python script to perform operations in OWASP Zed Attack Proxy, designed for use in vulnerability assessment stages in CI/CD pipelines.

optional arguments:
  -h, --help  show this help message and exit
  -t T        Target of vulnerability assessment
  -c C        ONLY FOR TFS SUMMARY - Ruleset JSON configuration file
              (default=all rules enabled)
  -s S        JSON file containing list of false positives
  -r R        Name of report to be generated (default=zap-
              report.html)
  -host HOST  Set host of ZAP instance, (default=127.0.0.1)
  -port PORT  Set port which ZAP instance is listening on, (default=8082)
  -api API    Specify API key of ZAP instance, if any, (default=none)
  -tfs        TFS mode, output summary of results compliant to TFS
```

## Configurations

This python script uses JSON files to store configurations for:

- List of alerts to suppress
	```
	{"instances": [
	        {"URL":"http://10.0.0.99/scripts/app.js", "AlertID":"2"},
	        {"URL":"http://10.0.0.99/scripts/app.js", "AlertID":"3"},
	    ]
	}
	```
	NOTE: It is advised to refer to previous reports for list of URLs and corresponding alert IDs

- Alert severity levels (TFS only)
	```
	{"alerts": [
			{"id": 50001, "level":"WARN", "message": "Script Passive Scan Rules"},
			{"id": 50003, "level":"WARN", "message": "Stats Passive Scan Rule"},
			{"id": 90022, "level":"WARN", "message": "Application Error Disclosure"},
			{"id": 10015, "level":"WARN", "message": "Incomplete or No Cache-control and Pragma HTTP Header Set"},
			{"id": 10019, "level":"WARN", "message": "Content-Type Header Missing"},
			{"id": 10010, "level":"WARN", "message": "Cookie No HttpOnly Flag"},
			{"id": 10011, "level":"WARN", "message": "Cookie Without Secure Flag"},
			{"id": 10017, "level":"WARN", "message": "Cross-Domain JavaScript Source File Inclusion"},
			{"id": 10016, "level":"WARN", "message": "Web Browser XSS Protection Not Enabled"},
			{"id": 10040, "level":"WARN", "message": "Secure Pages Include Mixed Content"},
			{"id": 2, "level":"WARN", "message": "Private IP Disclosure"},
			{"id": 3, "level":"WARN", "message": "Session ID in URL Rewrite"},
			{"id": 10021, "level":"WARN", "message": "X-Content-Type-Options Header Missing"},
			{"id": 10020, "level":"WARN", "message": "X-Frame-Options Header Scanner"}
		]
	}
	```
	NOTE: A full list of updated alerts that ZAP scans for can be found at pscan > scanners from the ZAP local API

## Examples

1. Perform a spider scan against http://example.com 
	
	`python zap.py -t http://example.com`
	
2. Perform a spider scan against http://example.com, with an instance of ZAP that has an API key specified, generate a report named zap-results.html

	`python zap.py -api 9l67llmogm1cr6trcu683fqddq -t http://example.com -r zap-results.html `

3. Perform a spider scan against http://example.com, suppress a list of alerts contained in false-positive.json

	`python zap.py -t http://example.com -s false-positive.json`

4. Perform a spider scan against http://example.com in TFS

	`python zap.py -tfs -t http://example.com `

5. Perform a spider scan against http://example.com in TFS, fail build if rule ID 2 is detected, suppress a list of alerts contained in false-positive.json, generate a report named zap-tfsbuild.html
	
	`python zap.py -tfs -t http://example.com -c rules.json -s false-positive.json -r zap-tfsbuild.html`

