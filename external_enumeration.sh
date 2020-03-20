#!/bin/bash

# Script to automate some initial enumeration for external assessments
# Author: Connor McGarr (@33y0re)

# Domain name variable
domain=$1

# Extracting just domain for organizational SSL search in Shodan
domain_no_com=$(echo $domain | awk -F '.' '{print $1}')

# Shodan API token variable
shodan_api=$2

# RiskIQ email
risk_iq_email=$3

# RiskIQ API secret variable
risk_iq_api=$4

# Error handling for lack of command line arguments
if [ -z "$domain" ]
	then
		echo -e "\e[31m[-] No domain specified! Please specify a domain, Shodan API token, RiskIQ email, and RiskIQ API secret.\e[0m"
		echo "Usage: ./external_enumeration.sh <DOMAIN.com> <SHODAN_API_TOKEN> <RISK_IQ_EMAIL> <RISKIQ_API_SECRET>"
	exit 1
fi

# Error handling for no Shodan API key
if [ -z "$shodan_api" ]
	then
		echo -e "\e[31m[-] You seemed to have entered a domain- but no Shodan API token, RiskIQ email, or RiskIQ API secret!\e[0m"
		echo "Usage: ./external_enumeration.sh <DOMAIN.com> <SHODAN_API_TOKEN> <RISK_IQ_EMAIL> <RISKIQ_API_SECRET>"
	exit 1
fi

# Error handling for no RiskIQ email
if [ -z "$risk_iq_email" ]
	then
		echo -e "\e[31m[-] You seemed to have entered a domain and Shodan API token- but no RiskIQ email or RiskIQ API secret!\e[0m"
		echo "Usage: ./external_enumeration.sh <DOMAIN.com> <SHODAN_API_TOKEN> <RISK_IQ_EMAIL> <RISK_IQ_EMAIL> <RISKIQ_API_SECRET>"
	exit 1
fi

# Error handline for no RiskIQ API secret
if [ -z "$risk_iq_api" ]
	then
		echo -e "\e[31m[-] You seemed to have entered a domain, Shodan API token, and RiskIQ email- but no RiskIQ API secret!\e[0m"
		echo "Usage: ./external_enumeration.sh <DOMAIN.com> <SHODAN_API_TOKEN> <RISKIQ_EMAIL> <RISKIQ_API_SECRET>"
	exit 1
fi

# Error handling for missing python-pip
if pip --version >/dev/null 2>&1
then
	echo "[+] Python-pip is installed! Continuing on..."
else
	echo -e "\e[31m[-] It seems as though you are missing python-pip. Please install it with sudo apt-get install python-pip.\e[0m"
	exit 1
fi

# Error handling for missing shodan
if shodan -h >/dev/null 2>&1
then
	echo "[+] Shodan is installed! Continuing on..."
else
	echo -e "\e[31m[-] It seems as though you are missing shodan. Please install it with sudo pip install shodan.\e[0m"
	exit 1
fi

# Error handling for missing jq
if jq --version >/dev/null 2>&1
then
	echo "[+] jq is installed! Continuing on..."
else
	echo -e "\e[31m[-] It seems as though you are missing jq. Please install it with sudo apt install jq. Your future self will thank you!\e[0m"
	exit 1
fi

# Make direcotry for all output
echo "[+] Creating directory INITIAL_EXTERNAL_ENUMERATION in the current directory..."
mkdir $PWD/INITIAL_EXTERNAL_ENUMERATION

echo -e "\e[93m[+] All ouput files will be written to $PWD/INITIAL_EXTERNAL_ENUMERATION!\e[0m"

# Sleeping for 2 seconds to inform user where files will be written to
sleep 2

# WHOIS function
function who_is
{
	whois $domain >> $PWD/INITIAL_EXTERNAL_ENUMERATION/WHO_IS_$domain.txt
}

who_is

# Print update for whois function
echo "[+] WHOIS enumeration for $domain is done!"

# DNS records function
function get_all_dns_records
{
	dig $domain TXT >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain A >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain NS >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain AAAA >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain ALIAS >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain CNAME >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain MX >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain PTR >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain SOA >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	dig $domain SRV >> $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt
	grep -v "DiG" $PWD/INITIAL_EXTERNAL_ENUMERATION/DNS_Records_$domain.txt >> $PWD/INITIAL_EXTERNAL_ENUMERATION/TEST.txt
	grep "$domain." $PWD/INITIAL_EXTERNAL_ENUMERATION/TEST.txt >> $PWD/INITIAL_EXTERNAL_ENUMERATION/TEST2.txt
	grep -v ";$domain" $PWD/INITIAL_EXTERNAL_ENUMERATION/TEST2.txt >> $PWD/INITIAL_EXTERNAL_ENUMERATION/Cleaned_Up_DNS_Records_$domain.txt

	rm $PWD/INITIAL_EXTERNAL_ENUMERATION/TEST.txt
	rm $PWD/INITIAL_EXTERNAL_ENUMERATION/TEST2.txt
}

get_all_dns_records

#Print update
echo "[+] All DNS records (via dig) for $domain have been saved in DNS_Records_$domain.txt!"
echo "[+] A cleaner version of dig DNS records for $domain is located in Cleaned_Up_DNS_Records_$domain.txt"

# Shodan function
function run_shodan
{

	shodan init $shodan_api >/dev/null

	# Create shodan directory to store Shodan results
	mkdir $PWD/INITIAL_EXTERNAL_ENUMERATION/Shodan_Output

	# Any easy wins?
	echo "[+] Downloading Shodan information for any easy wins. Please wait- this may take some time..."
	shodan download search "port:21,23,139,445,3389,5900" $domain >/dev/null
	shodan parse --fields ip_str,port,org --separator , search.json.gz >> $PWD/INITIAL_EXTERNAL_ENUMERATION/Shodan_Output/21_23_139_445_3389_5900_SHODAN_OUTPUT.csv

	# Web servers?
	echo "[+] Downloading Shodan information for any potential web servers. Please wait- this may take some time..."
	shodan download search "port:80,443,8080,8443" $domain >/dev/null
	shodan parse --fields ip_str,port,org --separator , search.json.gz >> $PWD/INITIAL_EXTERNAL_ENUMERATION/Shodan_Output/WEB_SERVERS_SHODAN_OUTPUT.csv

	# SSL certificates notice
	echo -e "\e[93m[+] Please note- if the name of the organization is different than $domain_no_com- please perform a manual search for SSL certificates referencing the organization...\e[0m"

	# Sleep to allow user to read information above
	sleep 5

	# SSL certificates?
	echo "[+] Downloading Shodan information for any SSL certificates referencing $domain_no_com. Please wait- this may take some time..."
	shodan download search "ssl:*$domain_no_com" >/dev/null
	shodan parse --fields ip_str,port,org --separator , search.json.gz >> $PWD/INITIAL_EXTERNAL_ENUMERATION/Shodan_Output/SSL_CERTS_SHODAN_OUTPUT.csv

	# Clean up
	echo "[+] Cleaning up!"
	rm $PWD/search.json.gz
}

run_shodan

function risk_iq
{

	# Create directory for RiskIQ API queries
	mkdir $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output

	# API Query for passive DNS records
	echo "[+] Downloading RiskIQ passive DNS records and resolutions..."

	# Let cURL breathe
	sleep 2

	# Starting RiskIQ API queries

	# Grabbing RiskIQ DNS information
	echo "[+] Pulling RiskIQ DNS information..."
	curl -u "$risk_iq_email:$risk_iq_api" "https://api.passivetotal.org/v2/dns/passive?query=$domain" >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data.json
	jq -r '.results[] | [.resolve, .recordType, .firstSeen, .lastSeen | tostring] | @csv' < $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data.json >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/RISKIQ_DNS_RECORDS_$domain.csv

	# Again, let cURL breath
	sleep 1

	# Grabbing RiskIQ subdomain information
	echo "[+] Pulling RiskIQ subdomain information..."
	curl -u "$risk_iq_email:$risk_iq_api" "https://api.passivetotal.org/v2/enrichment/subdomains?query=$domain" >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data_1.json 2>&1
	jq -r '.subdomains | @csv' < $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data_1.json >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/RISKIQ_SUBDOMAINS_$domain.csv

	# Again again, let cURL breath
	sleep 1

	# Grabbing OSINT information
	echo "[+] Pulling RiskIQ OSINT information..."
	curl -u "$risk_iq_email:$risk_iq_api" "https://api.passivetotal.org/v2/enrichment/osint?query=$domain" >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data_2.json 2>&1
	jq -r '.results[] | [.source, .sourceUrl] | @csv' < $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data_2.json >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/RISKIQ_OSINT_$domain.csv

	# Grabbing SSL certificate information
	echo "[+] Pulling RiskIQ SSL Certificate information via the Common Name..."
	curl -u "$risk_iq_email:$risk_iq_api" "https://api.passivetotal.org/v2/ssl-certificate/search" -XGET -H "Content-Type: application/json" --data '{"field": "subjectCommonName", "query": "$domain"}' >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data_3.json 2>&1
	jq -r '.results[] | [.subjectCountry, .issuerCommonName, .issuerProvince, .subjectStateOrProvinceName, .subjectStreetAddress, .issuerStateOrProvinceName, .subjectSurname, .issuerCountry, .subjectLocalityName, .issuerOrganizationUnitName, .firstSeen, .lastSeen, .expirationDate, .issueDate, .issuerOrganizationName, .subjectEmailAddress, .subjectOrganizationName, .sha1, .issuerLocalityName, .serialNumber, .subjectCommonName, .subjectProvince, .issuerGivenName, .subjectOrganizationUnitName, .subjectOrganizationUnitName, .subjectGivenName, .subjectSerialNumber, .sslVersion, .issuerStreetAddress, .fingerprint, .issuerSerialNumber, .issuerSurname] | @csv' < $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/data_3.json >> $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/RISKIQ_SSL_CERTS_$domain.csv

	# Clean up
	echo "[+] Cleaning up!"
	rm $PWD/INITIAL_EXTERNAL_ENUMERATION/RiskIQ_Output/*.json

}

risk_iq
