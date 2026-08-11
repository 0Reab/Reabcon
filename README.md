# Reabcon

My recon bash script for bug hunting automation.<br>
Currently work in progress, baseline is set just have to iron it out to be robust.<br>

## Features

Comprehensive reconnaissance for bug bounty and penetration testing.<br>
Includes the following:<br>
- subdomain enumeration (amass, subfinder, sublist3r)<br>
- fingerprinting and crawling (httpx, katana)<br>
- URL parameter collecting (GAU, waybackurls)<br>
- Screenshot live URLs (gowitness)<br>
- Fuzzing live URLs and API endpoints (ffuf)<br>
- Attempt 403 forbidden bypasses (ungate)<br>
- Parsing HTML and JS for Info (secretfinder, linkfinder, custom parsers)<br>

## Requirements

* amass, subfinder, sublist3r, httpx, gau, waybackurls, katana, gowitness, ungate, ffuf, secretfinder, linkfinder

## Installation & Usage

`git clone <url>` clone this repository.<br>
`cd reabcon && chmod +x reabcon.sh` add execution rights to the script.<br>

Ensure you have command names `aliased` the same as outlined in requirements section.<br>
Update the scripts custom `User-Agent` and `arbitrary HTTP header` to your specs (global variables at the start).<br>
This tool logs and outputs a lot, recommended an `empty working directory`.<br> 

```reabcon -s scope.txt -r 5 -v```<br><br>
`-s scope.txt` scope list, entries can be *.domain.com or https://domain.com or domain.com. <br>
`-r 5` rate limit 5 requests/second - default value. <br> 
`-v` verbose mode.<br>
`-b` run 403 bypass script ungate, only on logged 403s. <br>

Following option args are still in development:<br>
`-w wordlist.txt` supply a wordlist for FFUF, work in progress atm.<br>
`-H 'Header: val'` specify arbitrary http header.<br>
