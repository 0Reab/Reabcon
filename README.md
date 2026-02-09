# Reabcon

My recon bash script for bug hunting automation.

## Features

Subdomain discovery via:
* Sublist3r
* Waybackurls

Host live checking, parsing by http response code.
Logging and saving the output.

Parsing saved http responses for other scripts with HTML parsing for URLs/endpoints and informational finds.

## Installation & Usage

`git clone <url>` clone this repository.
Make sure you have sublist3r installed, configure it's absolute path in the script.

```reabcon.sh -o test1.txt -f scopes.csv -c -o output file```
-f <basic_scope_list> (add -c if it's hacker1 CSV scope).
-o <output_file>
