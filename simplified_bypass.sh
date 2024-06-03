#!/usr/bin/env bash

# Constants and Variables
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
GREEN='\033[1;32m'
NC='\033[0m'
RED='\033[1;31m'
YELLOW='\033[0;33m'

# Input Variables
checkall=0
POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    -d|--domain)
    domain="$2"
    shift
    shift
    ;;
    -o|--outputfile)
    outfile="$2"
    shift
    shift
    ;;
    -l|--listsubdomains)
    listsubdomains="$2"
    shift
    shift
    ;;
    -a|--checkall)
    checkall=1
    shift
    ;;
    *)
    POSITIONAL+=("$1")
    shift
    ;;
esac
done
set -- "${POSITIONAL[@]}"

# Show Script Information
if [ -z "$domain" ]; then
    echo 'usage: ./bypass-firewalls-by-DNS-history.sh -d example.com'
    echo '-d --domain: domain to bypass'
    echo "-o --outputfile: output file with IP's only"
    echo '-l --listsubdomains: list with subdomains for extra coverage'
    echo '-a --checkall: Check all subdomains for a WAF bypass'
    exit 0
fi

# Check if jq is installed
jq --help >/dev/null 2>&1 || { echo >&2 "'jq' is needed for extra subdomain lookups, but it's not installed. Consider installing it for better results (e.g., 'apt install jq'). Aborting."; exit 1; }

# Cleanup temp files
rm /tmp/waf-bypass-*$domain* &> /dev/null

# Add extra Subdomains
if [ -n "$listsubdomains" ]; then
    cat $listsubdomains > /tmp/waf-bypass-alldomains-$domain.txt
fi

# Show Logo
cat << "EOF"
-------------------------------------------------------------
WWWWWMWWWWWWWWWWWNWWWWWWWWWWWWWWWWWWWWWNWMMMWNKOxddxOKNWMMMWWWNWWWWWWWWWWWWWWWWWWWWWNWWWWWWWWWWWWWWW
WWWWNNNWWWWWWWWWWWWWWWWWWWNNNWWWWWWWNNXK0Okdlc;,''''';:ldxO0KXNNWWWWWWWWNNWWWWWWWWWWWWWWWWWWWWNNWWWW
MMMWWNWMMMMMMMMMMMMMMMMMMWWNWWNOxddolc:;,,''''''''''''''''',;:cloddxOXMWNWWMMMMMMMMMMMMMMMMMMWNWWMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWWx,'''''''''''''''''''''''''''''''''''',dWWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWWd''''''''''''''';lddol:,'''''''''''''''oNWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWWd''''''''''''''';oKMMWXx;''''''''''''''oNWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWWd'''''''''''''''':0MMMMWx,'''''''''''''oNWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
WWWWWNWWWWWWWWWWWWWWWWWWWWWNWNd'''''''''''''',cOWMMMMMk,'''''''''''''lXWNWWWWWWWWWWWWWWWWWWWWWNNWWWW
WWWWWWWWWWWWWWWWNNWWWWWWWWWWWNd''''''''''''';xXMMMMMMW0xdc,''''''''''lXWWWWWWWWWWWWWNWWWWWWWWWWWWWWW
MMMMMMMMMMMMMMMWWNWMMMMMMMMMMWd''''''''''',l0WMMMMMMMMMWOc,''''''''''oNMMMMMMMMMMMMWNWMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWNWMMMMMMMMMMWd'''''''''',dNMMMMXO0XMMMWx,'''''''''''oNMMMMMMMMMMMMWNWMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWNWMMMMMMMMMMWd''''''''''oXMMMMXl:lOWMMMNx;''''''''''oNMMMMMMMMMMMMWNWMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWNWMMMMMMMMMMWd''''''''',kMMMMMO;'':xXMMMWx,'''''''''oNMMMMMMMMMMMMWNWMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMWWNWMMMMMMMMMMWx,'''''''',kWMXkO0o,'',c0WMMO;'''''''''dNMMMMMMMMMMMMWNWMMMMMMMMMMMMMM
WWWWWWWWWWWWWWWWNNWWWWWWWWWWWW0:'''''''''cKM0:,:;,''''cKMWx,'''''''';OWWWWWWWWWWWWWNNNWWWWWWWWWWWWWW
WWWWWNWWWWWWWWWWWWWWWWWWWWWNWWWk;'''''''''cOKo,'''''''oXXx;'''''''',dNWWNWWWWWWWWWWWWWWWWWWWWWNWWWWW
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMNk;''''''''',loc,'''',:dd:,'''''''',dNMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMWOc,'''''''''',,''''',,'''''''''':kNMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMMMXx:'''''''''''''''''''''''''';dKWMMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
MMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMMMMWXxc,'''''''''''''''''''',:dKWMMMMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMM
WWWWWNWWWWWWWWWWWWWWWWWWWWWNWWWWWWWWWWNOdc;'''''''''''''',cdOXWWWWWWWWWWNWWWWWWWWWWWWWWWWWWWWWNWWWWW
WWWWWWWWWWWWWWWWNNWWWWWWWWWWWWWWWWWWWWNNWNKkxoc:;;;;:codk0XWWNNWWWWWWWWWWWWWWWWWWWWNNNWWWWWWWWWWWWWW
MMMMMMMMMMMMMMMWWNWMMMMMMMMMMMMMMMMMMWWNWMMMMMWNXKKKXWMMMMMMMWNWMMMMMMMMMMMMMMMMMMMWNWMMMMMMMMMMMMMM
( @alby-shinoj)
-------------------------------------------------------------
EOF

# Matchmaking Function
function matchmaking {
    file1=$1
    file2=$2
    ip=$3
    domain=$4
    protocol=$5

    curl --silent -o "/tmp/waf-bypass-https-$domain" "https://$domain"
    curl --silent -o "/tmp/waf-bypass-http-$domain" "http://$domain"

    touch $file1
    touch $file2

    sizefile1=$(wc -l < $file1)
    sizefile2=$(wc -l < $file2)
    biggestsize=$(( sizefile1 > sizefile2 ? sizefile1 : sizefile2 ))

    if [[ $biggestsize -ne 0 ]]; then
        difference=$(sdiff -B -b -s $file1 $file2 | wc -l)
        confidence_percentage=$(( 100 * (( biggestsize - difference )) / biggestsize ))

        if [[ $confidence_percentage -gt 0 ]]; then
            echo "$ip" >> "$outfile"
            if [[ $checkall -le 0 ]]; then
                echo -e "$protocol://$ip | $confidence_percentage % | $(curl --silent https://ipinfo.io/$ip/org )" >>  /tmp/waf-bypass-output-$domain.txt
            else
                echo -e "$protocol://$domain | $ip | $confidence_percentage % | $(curl --silent https://ipinfo.io/$ip/org )" >>  /tmp/waf-bypass-output-$domain.txt
            fi
        fi
    fi
}

# IP Validation Function
function in_subnet {
    local ip mask netmask sub_ip ip_a start end
    local readonly BITMASK=0xFFFFFFFF

    IFS=/ read -r sub mask <<< "${1}"
    IFS=. read -ra sub_ip <<< "${sub}"
    IFS=. read -ra ip_a <<< "${2}"

    netmask=$((BITMASK<<$((32-mask)) & BITMASK))

    start=0
    for o in "${sub_ip[@]}"
    do
        start=$((start<<8 | o))
    done

    start=$((start & netmask))
    end=$((start | ~$netmask & BITMASK))

    ip=0
    for o in "${ip_a[@]}"
    do
        ip=$((ip<<8 | o))
    done

    (( ip >= start && ip <= end )) && echo 1 || echo 0
}

function ip_is_waf {
    IP=$1
    for subnet in $PUBLICWAFS
    do
        if [[ $(in_subnet $subnet $IP) -eq 1 ]]; then
            echo 1
            return
        fi
    done
    echo 0
}

function get_top_domain {
    domain=$1
    top_domain=$(curl -s "http://tldextract.appspot.com/api/extract?url=$domain" | jq -r '.domain, .tld' | tr -d '\n' | rev | cut -c2- | rev)
    if [ "$domain" != "$top_domain" ]; then
        echo $top_domain
    fi
}

# Subdomain Gathering Function
function dnsdumpster_subdomains {
    domain=$1
    curl https://dnsdumpster.com -o /dev/null -c /tmp/dnsdumpster-$domain-cookies.txt -s
    CSRF=$(grep csrftoken /tmp/dnsdumpster-$domain-cookies.txt | cut -f 7)
    curl -s -X 'POST' -H 'Content-Type: application/x-www-form-urlencoded' -H "Cookie: csrftoken=$CSRF" --data-binary "csrfmiddlewaretoken=$CSRF&targetip=$domain" -o /tmp/dnsdumpster-$domain-output.txt 'https://dnsdumpster.com/'
    grep -oP '\w*\.'$domain /tmp/dnsdumpster-$domain-output.txt | sort -u
    rm /tmp/dnsdumpster-$domain-output.txt /tmp/dnsdumpster-$domain-cookies.txt
}

function virustotal_subdomains {
    domain=$1
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API_KEY&domain=$domain" | jq -r '.subdomains[]?' | sort -u
}

function certspotter_subdomains {
    domain=$1
    curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | grep "\.$domain$" | sort -u
}

# Collect Subdomains
dnsdumpster_subdomains $domain >> /tmp/waf-bypass-alldomains-$domain.txt
virustotal_subdomains $domain >> /tmp/waf-bypass-alldomains-$domain.txt
certspotter_subdomains $domain >> /tmp/waf-bypass-alldomains-$domain.txt
sort -u /tmp/waf-bypass-alldomains-$domain.txt -o /tmp/waf-bypass-alldomains-$domain.txt
cat /tmp/waf-bypass-alldomains-$domain.txt | grep -v "www\." > /tmp/waf-bypass-alldomains-filtered-$domain.txt

# Start Scanning Each Subdomain
while IFS= read -r subdomain
do
    for protocol in "http" "https"
    do
        curl --silent -o /tmp/waf-bypass-original-$subdomain "$protocol://$subdomain"
        curl -s "https://securitytrails.com/api/v1/domain/$subdomain/dns" | jq -r '.records_dns[] | select(.type == "A") | .ip' | while IFS= read -r ip
        do
            if [[ $(ip_is_waf $ip) -eq 0 ]]; then
                curl --silent -o "/tmp/waf-bypass-$protocol-$ip-$subdomain" "$protocol://$ip"
                matchmaking "/tmp/waf-bypass-original-$subdomain" "/tmp/waf-bypass-$protocol-$ip-$subdomain" "$ip" "$subdomain" "$protocol"
            fi
        done
    done
done < /tmp/waf-bypass-alldomains-filtered-$domain.txt

# Cleanup
rm /tmp/waf-bypass-*$domain*
echo -e "${GREEN}[+][DONE] Output saved in '/tmp/waf-bypass-output-$domain.txt'${NC}"
