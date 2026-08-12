#!/usr/bin/env bash

# Check if your system has tools required for reabcon.sh
# 
# To make the python tools available in scripts:
# For example, create /usr/local/bin/secretfinder (will need sudo).
#
# With following contents (absolute paths to venv and script):
# #!/bin/bash
# exec /secretfinder/.venv/bin/python3 /secretfinder/SecretFinder.py "$@"
# 
# Then just chmod +x the files.

green=$'\e[32m'
red=$'\e[31m'
orange=$'\e[38;5;208m'
col_off=$'\e[0m'

function tool_check() {
	local cmd="$1"
	local cmd_link="$2"

	$cmd -h &> /dev/null

	if [[ $? -eq 0 ]]; then
		echo "${green}[OK] ${cmd}${col_off}"
	else
		if [[ "$cmd" == "ungate" || "$cmd" == "ffuf" || "$cmd" == "secretfinder" || "$cmd" == "linkfinder" ]]; then
			echo "${orange}[FAIL] $cmd -> missing OPTIONAL tool -> ${cmd_link}${col_off}"
		else
			echo "${red}[FAIL] $cmd -> missing tool -> ${cmd_link}${col_off}"
		fi
	fi
}


echo "Checking for dependencies..."; echo 

#tool_check "amass"
tool_check "subfinder" "https://github.com/projectdiscovery/subfinder"
tool_check "sublist3r" "https://github.com/aboul3la/sublist3r"
tool_check "httpx" "https://github.com/projectdiscovery/httpx"
tool_check "getallurls" "https://github.com/lc/gau"
tool_check "waybackurls" "https://github.com/tomnomnom/waybackurls"
tool_check "katana" "https://github.com/projectdiscovery/katana"
tool_check "gowitness" "https://github.com/sensepost/gowitness"
tool_check "ungate" "https://github.com/aptspyder/ungate"
tool_check "ffuf" "https://github.com/ffuf/ffuf"
tool_check "secretfinder" "https://github.com/m4ll0k/SecretFinder"
tool_check "linkfinder" "https://github.com/GerbenJavado/LinkFinder"

echo; echo "Finished (exit $?)"
