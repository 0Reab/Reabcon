#!/bin/bash
#set -x

# add more ouptut from curl
# and grep for api keys or signin/login froms,
# json/json data basic stuff...
# and sort the final list
# add more subdomain finders
# gowitness screenshots or make your own
# ad wapalyzer cli equivalent tool
# inline js endpoint parser or sumt

# cleanup code at the end
# debug / verbose on off fucntion

# GLOBAL VARIABLES
# --------------------------------------------------------------------------------

sublister="$HOME/scripts/Sublist3r/venv/bin/python3 $HOME/scripts/Sublist3r/sublist3r.py"
LINE="----------------------------------------------"
USAGE="reabcon.sh usage: ./con.sh -o test1.txt -f scopes.csv -c\n\n -o output file\n -f scope file\n -c set if source = h1 csv"

GREEN='\033[0;32m'
RED='\033[0;31m'
OFF='\033[0m'

is_csv=false
TMP="$PWD/tmp.txt"
ENGINES="Baidu,Yahoo,Bing,Ask,Netcraft,DNSdumpster,ThreatCrowd,SSL Certificates,PassiveDNS,Google,Virus Total" # virus total and google

SUBDOMAINS="$PWD/found.txt"

# UTILS AND ARG OPTIONS
# --------------------------------------------------------------------------------

function line() { echo "$LINE"; }
function usage() { echo -e "$USAGE" && exit 1; }


while getopts "hco:f:" opt; do
	case $opt in
		f) DOMAINS=${OPTARG} ;;
		o) RESULT=${OPTARG} ;;
		c) is_csv=true ;;
		h) usage ;;
		*) usage ;;
	esac
done

# VALIDATION AND PARSING
# --------------------------------------------------------------------------------

function prepare_input() {

	line
	echo "Running with arguments..."
	echo "DOMAINS = $DOMAINS"
	echo "SUBDOMAINS = $SUBDOMAINS"
	echo "RESULT = $RESULT"
	echo "is_csv = $is_csv"
	line

	if [ ! -f "$DOMAINS" ]; then
		echo -e "${RED}${DOMAINS} is not a valid file"
		exit 1
	else
		echo -e "${GREEN}${DOMAINS} is a valid file"
	fi

	if [ ! -f "$TMP" ]; then
		touch "$TMP"
	fi

	if [ "$is_csv" = true ]; then
		echo "processing CSV..."
		cut -f 1 -d ',' "$DOMAINS" | grep '\*' | cut -c 3- > "$PWD/csv_to_list.txt"
		cut -f 1 -d ',' "$DOMAINS" | grep -v '\*' >> "$SUBDOMAINS"
		PROCESSED_DOMAINS="$PWD/csv_to_list.txt"
		echo "CSV converted to a list -> $PWD/csv_to_list.txt"
	else
		echo -e "${OFF}Not a csv skipping preprocessing."
		PROCESSED_DOMAINS="$DOMAINS"
	fi
	echo "PROCESSED_DOMAINS = $PROCESSED_DOMAINS"
	cat "$PROCESSED_DOMAINS"
	line
}
	
# RUN SUBLISTER ON DOMAINS
# --------------------------------------------------------------------------------

function sublist() {
	truncate --size 0 "$SUBDOMAINS"

	while read -r line; do
		truncate --size 0 "$TMP"
		echo -e "${GREEN}running sublister on -> $line ${OFF}"
		$sublister -d "$line" -o "$TMP" &>/dev/null # -e "$ENGINES" 2>/dev/null
		wait
		cat "$TMP" >> "$SUBDOMAINS"
		echo "SUBLISTER TMP loop iter = $TMP" && cat "$TMP"
		# echo "SUBLISTER SUBDOAMINS iter = $SUBDOMAINS" && cat "$SUBDOMAINS"
		echo "SUBLISTER line loop iter = $line"
	done < "$PROCESSED_DOMAINS"

	line
	truncate --size 0 "$RESULT" && echo "cleared $RESULT file"
	line
	
	echo "DEBUG 3 -> TMP = $TMP ; SUBDOMAINS = $SUBDOMAINS ; PROCESSED_DOMAINS=$PROCESSED_DOMAINS"
}

# GET REQUEST ON FOUND SUBDOMAINS
# --------------------------------------------------------------------------------

function parse() { echo "$1" | grep -i "$2" | head -n 1; }

function output() {
	local url="$1"
	local exit_code="$2"
	local resp_code="$3"
	local server="$4"
	local title="$5"
	local length="$6"

	echo -e "DEBUGING 2 -> $1 ^ $2 ^ $3 ^ $4 ^ $5 ^ $6"

	if [ "$exit_code" -eq 0 ]; then
		echo -e "${GREEN} ${url} - LIVE ${OFF}"
		echo "https://${url} ^ ${resp_code} ^ ${server} ^ ${title} ^ $length" >> "$RESULT"
	else
		echo -e "${RED} ${url} - DEAD ${OFF}"
	fi
}


function request() {
	mkdir -p "$PWD/recon_requests"
	sort -u "$SUBDOMAINS" -o "$SUBDOMAINS"

	while read -r i; do
		cmd=$(curl -L -i -s --connect-timeout 5 -m 10 "https://${i}" 2>/dev/null)
		exit_code=$?
		response=$( echo "$cmd" | tr -d '\r')


		echo "$response" > "$PWD/recon_requests/$i"
		if [ $? -ne 0 ]; then
			echo -e "${RED} Failed to create file $i ${OFF}"
		fi

		resp_code=$(echo "$response" | grep -i 'HTTP/' | tail -n1 )
		length=$(echo "$response" | grep -i 'content-length:' | tail -n1 )
		title=$(parse "$response" "<title>" | cut -f 2 -d ">" | sed "s:</title::g")	
		server=$(echo "$response" | grep -i '^server:' | cut -d' ' -f2- | tr -d '\r')

		match=$(echo "$response" | grep -iE 'apikey|bearer|token|login|signin|firebase')
		if [ -n "$match" ]; then
    		{
        		echo "[$i]"
		        echo "$match"
		        echo
		    } >> findings.txt
		fi

		echo -e "DEBUG OUTPUT FUNC WITH - $i ^ $exit_code ^ $resp_code ^ $server ^ $title ^ $length"
		output "$i" "$exit_code" "$resp_code" "$server" "$title" "$length"

		sleep 0.3

	done < "$SUBDOMAINS"
}

function enumerate() {

	function keyword() { grep "$1" "$RESULT" | awk '{print $1}'; } 
	# keyword 'HTTP/.* 404'
	
	keyword 'HTTP/.* 403' | while read -r url; do
		line
		echo "$url"	
		line
		echo "$url" | getallurls
		line
	done
}

# MAIN
# --------------------------------------------------------------------------------

function main() {
	
	prepare_input
	sublist
	request

	echo -e "${OFF}" && line
	echo "domain total list" && wc -l "$DOMAINS" && cat "$DOMAINS" && line
	echo "live domains" && wc -l "$RESULT" && cat "$RESULT" && line
	
	rm "$TMP"
}

main
