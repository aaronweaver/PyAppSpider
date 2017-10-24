# PyAppSpider

A python client for Rapid7 AppSpider Enterprise. This can be used on the command line to interact with AppSpider or the module can be included to query AppSpider using your own Python script.

### Command Line Options

```
usage: AppSpider.py [-h] [--url URL] [--username USERNAME]
                    [--password PASSWORD] [--admin-username ADMIN_USERNAME]
                    [--admin-password ADMIN_PASSWORD] [--client CLIENT]
                    [--engine-group ENGINE_GROUP] [--proxy PROXY] [--scans]
                    [--configs] [--vulns] [--vulns-summary]
                    [--scan-id SCAN_ID] [--output-file OUTPUT_FILE]
                    [--report-zip] [--crawled-links] [--run-scan RUN_SCAN]
                    [--create-config] [--create-run]
                    [--create-engine-group CREATE_ENGINE_GROUP]
                    [--create-name CREATE_NAME] [--create-xml CREATE_XML]
                    [--create-seed-url CREATE_SEED_URL]
                    [--create-constraint-url CREATE_CONSTRAINT_URL]
                    [--create-custom-header CREATE_CUSTOM_HEADER] [--engines]
                    [--engine-groups]

AppSpider API Client.

optional arguments:
  -h, --help            show this help message and exit
  --scans               Retrieve the scans status.
  --configs             Retrieves all the scan configurations.
  --vulns               Retrieves all the vulnerabilites for the specified
                        client.
  --vulns-summary       Gets VulnerabilitiesSummary.xml for the scan. Requires
                        a scan id and output file.
  --scan-id SCAN_ID     Scan id for the specified client.
  --output-file OUTPUT_FILE
                        Name of the output file.
  --report-zip          Retrieves the zip report file. Requires a scan id and
                        output file.
  --crawled-links       Retrieves the crawled links. Requires a scan id and
                        output file.
  --run-scan RUN_SCAN   Runs the scan with the specified scan name.
  --create-config       Creates a scan configuration
  --create-run          Creates a scan configuration and runs it
  --create-engine-group CREATE_ENGINE_GROUP
                        Engine group for a scan configuration
  --create-name CREATE_NAME
                        Config name
  --create-xml CREATE_XML
                        XML configuration for scan
  --create-seed-url CREATE_SEED_URL
                        Starting URL for scan
  --create-constraint-url CREATE_CONSTRAINT_URL
                        Include url constraint, example:
                        http://www.yoursite.com/*
  --create-custom-header CREATE_CUSTOM_HEADER
                        Custom Header (API Token in header for example)
  --engines             Lists the engines configured in AppSpider Enterprise
  --engine-groups       Lists the engine groups configured in AppSpider
                        Enterprise
```

### Authentication
Two options for authenticating:


#### Authenticate Using Environment Variables

```
export APPSPIDER_USERNAME=<AppSpider Client User>
export APPSPIDER_PASSWORD=<AppSpider Client Password>
export APPSPIDER_ADMIN_USERNAME=<AppSpider Admin>
export APPSPIDER_ADMIN_PASSWORD=<AppSpider Password>
```

#### Environment Specific

```
export APPSPIDER_URL=<URL for AppSpider Enterprise>
export APPSPIDER_CLIENT=<AppSpider Client Name(optional)>
export APPSPIDER_ENGINE_GROUP=<AppSpider Engine Group Name(optional)>
export APPSPIDER_PROXY=<AppSpider Proxy (optional)>
```

#### Authenticate Using Command Line Variables

```
--url URL             AppSpider URL.
--username USERNAME   AppSpider username.
--password PASSWORD   AppSpider password.
--admin-username ADMIN_USERNAME
                      AppSpider admin username. (Used for global admin
                      features)
--admin-password ADMIN_PASSWORD
                      AppSpider admin password. (Used for global admin
                      features)
```

#### Environment Specific Command Line Variables

```
--client CLIENT       Client name.
--engine-group ENGINE_GROUP
                      Engine group for scanning.
--proxy PROXY         Proxy for client to use for requests.
```

### Example Command Line Usage

Display help.

`./AppSpider.py -h`

List vulnerabilities for a client.

`./AppSpider.py --client "<client name>" --vulns`

Saves vulnerabilities for a client to an XML file.

`./AppSpider.py --client "<client name>" --vulns-summary --output-file output/vulnssummer.xml`

Return scans for a client.

`./AppSpider.py --client "<client name>" --scans`

Generate a zip report file.

`./AppSpider.py --report-zip --client "<client name>" --scan-id <Scan ID Returned from --scans> --output-file output/report.zip`

Create a scan configuration based off a prior scan config xml file.

`./AppSpider.py --client "<client name>" --create-config --create-engine-group "<Engine GroupName>" --create-name "<Scan Name>" --create-seed-url "<URL to scan>" --create-custom-header "<optional API key or session token>" --create-xml scan_configs/scan_config.xml --create-constraint-url "<Constraint URL"`

Creates and runs scan configuration based off a prior scan config xml file.

`./AppSpider.py --client "<client name>" --create-config --create-run --create-engine-group "<Engine GroupName>" --create-name "<Scan Name>" --create-seed-url "<URL to scan>" --create-custom-header "<optional API key or session token>" --create-xml scan_configs/scan_config.xml --create-constraint-url "<Constraint URL>"`

Run a scan.

`./AppSpider.py -run-scan <Scan Name>`
