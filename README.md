# Reabcon

My recon bash script for bug hunting automation.

## Features

Subdomain discovery via:
* Sublist3r
* Waybackurls

Host live checking, parsing by http response code.<br>
Logging and saving the output.<br>

Parsing saved http responses for other scripts with HTML parsing for URLs/endpoints and informational finds.

## Installation & Usage

`git clone <url>` clone this repository.<br>
Make sure you have sublist3r installed, configure it's absolute path in the script.

```reabcon.sh -o <output_file.txt> -f scope.csv -c```<br><br>
-f <basic_scope_list> (add -c if it's hacker1 CSV scope).<br>
-o <output_file>
