# Red Team Automation Scripts
Scripts to help automate tedious red teaming enumeration and tasks.

external_enumeration.sh
---
__Usage: `./external_enumeration.sh <DOMAIN.com> <SHODAN_API_TOKEN> <RISKIQ_EMAIL> <RISKIQ_API_KEY>`__

This script will automate passive reconnaissance information such as:

1. Whois
2. Pulling all public DNS records (as much as possible without a zone transfer)
3. Shodan (you'll need an API token)
