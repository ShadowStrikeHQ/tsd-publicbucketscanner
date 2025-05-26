# tsd-PublicBucketScanner
Scans a specified domain's DNS records and common bucket naming conventions (e.g., <domain>-bucket, bucket-<domain>) for publicly accessible cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob Storage), reporting those with list/read permissions. - Focused on Automated enumeration of publicly exposed assets and technologies to identify potential attack vectors. Focus on gathering information about domains, subdomains, exposed services, and technology stacks to understand the overall threat landscape from an attacker's perspective.

## Install
`git clone https://github.com/ShadowStrikeHQ/tsd-publicbucketscanner`

## Usage
`./tsd-publicbucketscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
