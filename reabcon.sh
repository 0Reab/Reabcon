#!/usr/bin/env bash
set -Eeuo pipefail

trap 'echo "${red}[-] ERROR -> Failed at line $LINENO: ${b_red}$BASH_COMMAND${red} -> (exit $?)${color_off}" >&2' ERR

# reabcon - Bug bounty reconnaissance helper
# Requirements:
#   amass, subfinder, sublist3r, httpx, gau, waybackurls, katana, gowitness, ungate, ffuf
# Optional:
#   SecretFinder.py, linkfinder.py

RATE_LIMIT=5
HTTP_HEADER="X-Intigriti-Bugbounty: Reab"
MAX_WORKERS=5
USER_AGENT="reab@intigriti.me Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

ROOT_DIR="$PWD"
SCAN_DIR="$ROOT_DIR/scans"
SS_DIR="$ROOT_DIR/ss"
RESPONSE_DIR="$SCAN_DIR/responses"

color_off=$'\e[0;0m'
cyan=$'\e[0;96m'
green=$'\e[0;92m'
red=$'\e[0;31m'

b_green=$'\e[1;92m'
b_red=$'\e[1;31m'
b_cyan=$'\e[1;96m'

star="${b_green}[*]${green}"
draw_line="${red}----------------------------------------------------------------------------------${color_off}"

# ── Patterns ────────────────────────────────────────────────────────────────

PARAM_PATTERN='redirect=|url=|next=|return=|returnTo=|callback=|continue=|dest=|destination=|target=|view=|file=|path=|folder=|template=|page=|lang=|locale=|token=|access_token=|refresh_token=|jwt=|auth=|session=|api_key=|apikey=|key=|secret=|signature='
LEAK_PATTERN='password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|aws_|BEGIN (RSA|EC|OPENSSH|PGP)|Authorization:|Basic [A-Za-z0-9+/=]{8,}|Bearer [A-Za-z0-9._\-]{8,}|-----BEGIN|mysql://|postgres://|mongodb://|redis://|smtp://|\.env|\.git/config|internal error|stack trace|traceback|exception in|at [A-Za-z]+\.[A-Za-z]+\(.*:[0-9]+\)'
SINK_PATTERN='innerHTML|outerHTML|document\.write|eval\(|new Function\(|location\.hash|location\.search|postMessage|addEventListener\([\"'\'']message|onmessage\s*='
VERSION_PATTERN='[Vv]ersion["'\''\s:=]+[0-9]+\.[0-9]+|[Vv][0-9]+\.[0-9]+\.[0-9]+|/[0-9]+\.[0-9]+\.[0-9]+["'\''\s/]|"version"\s*:\s*"[0-9]+\.[0-9]+'
TECH_PATTERN='X-Powered-By:|X-Generator:|X-AspNet-Version:|X-AspNetMvc-Version:|X-Drupal|X-Joomla|Server:\s*(Apache|nginx|IIS|LiteSpeed|Caddy|Tomcat|JBoss|WebLogic|WebSphere|Jetty|Gunicorn|uWSGI|Kestrel|OpenResty)|wp-content|wp-includes|Drupal\.settings|Joomla!|generator.*WordPress|generator.*Drupal|generator.*Joomla|laravel_session|XSRF-TOKEN|__rails|csrfmiddlewaretoken|ASP\.NET_SessionId|JSESSIONID|struts|backbone\.js|angular\.js|react\.development|vue\.runtime|ember\.js|jquery[.-][0-9]|bootstrap[.-][0-9]|moment\.js|lodash\.js|GraphQL|ApolloClient|grpc-status|x-amz-|x-goog-|x-ms-|CF-Ray:|x-cache:|x-varnish:|x-envoy|x-kong-|x-forwarded-by'
# Matches interesting *paths/resources* discovered during crawling (report only)
INTERESTING_PATH_PATTERN='admin|administrator|manage|dashboard|console|internal|private|debug|test|staging|dev|qa|uat|beta|preview|backup|old|temp|upload|import|export|config|settings|graphql|swagger|openapi|api-docs|prometheus|metrics|actuator|health|env|\.git|\.svn|phpinfo|jenkins|kibana|grafana|sonar|nexus|artifactory|pgadmin|phpmyadmin|adminer|wp-admin|setup|install|reset|token|oauth|callback|redirect|login|logout|register|signup|forgot|password|reset|profile|account|user|users|roles|permissions|audit|log|logs|report|reports'

# Matches interesting *hostnames* — used to select fuzz targets from live_urls.txt.
# Checks every dot-separated label in the hostname so "api-v2.prod.example.com"
# matches on "api" and "prod.example.com" still won't be missed.
# Intentionally broad: a false positive just means one extra fuzz run.
INTERESTING_HOST_PATTERN='admin|administrator|manage|portal|dashboard|console|panel|control|internal|intranet|private|corp|corporate|staff|employee|helpdesk|support|ops|operations|sre|infra|infrastructure|monitoring|metrics|prometheus|grafana|kibana|elastic|logstash|splunk|sentry|datadog|jenkins|ci|cd|build|deploy|devops|gitlab|github|bitbucket|sonar|nexus|artifactory|registry|repo|repository|packages|api|apis|api-v[0-9]|v[0-9]|rest|graphql|gql|grpc|gateway|gw|service|services|svc|backend|server|app|apps|application|web|site|secure|security|vpn|remote|mx|mail|smtp|imap|pop|ftp|sftp|ssh|git|svn|dev|developer|develop|devel|development|test|testing|qa|uat|staging|stg|stage|beta|preview|demo|sandbox|canary|lab|labs|experimental|backup|bak|old|legacy|archive|temp|tmp|pre|preprod|nightly|rc|int|acceptance|auth|sso|login|id|identity|account|accounts|profile|user|users|member|members|pay|payment|payments|billing|invoice|checkout|store|shop|order|orders|cdn|assets|static|media|images|upload|uploads|download|downloads|files|docs|documentation|wiki|kb|knowledge|help|status|health|ping|monitor|alert|alerts|report|reports|data|database|db|mysql|postgres|redis|mongo|elastic|search|crm|erp|hr|finance|legal|partner|partners|vendor|vendors|supplier|customer|customers|client|clients|extranet|b2b|b2c|public|open'

API_BASE_PATHS=(
  "/api"
  "/api/v1"
  "/api/v2"
  "/api/v3"
  "/v1"
  "/v2"
  "/rest"
  "/graphql"
  "/gql"
)

# ── Banner / Usage ───────────────────────────────────────────────────────────

banner() {
  cat << EOF
${b_green}                                                            :                    
                     ,;                              .,    t#,     L.            
  j.               f#i               .              ,Wt   ;##W.    EW:        ,ft
  EW,            .E#t             .. Ef.           i#D.  :#L:WE    E##;       t#E
  E##j          i#W,             ;W, E#Wi         f#f   .KG  ,#D   E###t      t#E
  E###D.       L#D.             j##, E#K#D:     .D#i    EE    ;#f  E#fE#f     t#E
  E#jG#W;    :K#Wfff;          G###, E#t,E#f.  :KW,    f#.     t#i E#t D#G    t#E
  E#t t##f   i##WLLLLt       :E####, E#WEE##Wt t#f     :#G     GK  E#t  f#E.  t#E
  E#t  :K#E:  .E#L          ;W#DG##, E##Ei;;;;. ;#G     ;#L   LW.  E#t   t#K: t#E
  E#KDDDD###i   f#E:       j###DW##, E#DWWt      :KE.    t#f f#:   E#t    ;#W,t#E
  E#f,t#Wi,,,    ,WW;     G##i,,G##, E#t f#K;     .DW:    f#D#;    E#t     :K#D#E
  E#t  ;#W:       .D#;  :K#K:   L##, E#Dfff##E,     L#,    G#t     E#t      .E##E
  DWi   ,KK:        tt ;##D.    L##, jLLLLLLLLL;     jt     t      ..         G#E
                       ,,,      .,,                                            fE
                                                                                ,${color_off}
EOF
}

usage() {
  cat <<EOF
${cyan}Usage: reabcon -s scope.txt [-r RATE] [-w wordlist.txt] [-H "Header: value"] [-b] [-v]

  -s   Scope file (required)
  -r   Rate limit in requests/sec (default: 5)
  -w   Wordlist for content discovery and API fuzzing (enables those phases)
  -H   HTTP header in "Name: value" form (repeatable; use for Cookie:, Authorization:, etc.)
  -b   Enable 403 bypass with ungate (opt-in; can be noisy)
  -v   Verbose: print each tool invocation and its arguments before running

Examples:
  reabcon -s scope.txt
  reabcon -s scope.txt -r 10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
  reabcon -s scope.txt -w wordlist.txt -H "Cookie: PHPSESSID=deadbeef" -H "Authorization: Bearer TOKEN"${color_off}
EOF
}

# ── CLI argument parsing ─────────────────────────────────────────────────────

# HEADERS holds all "Name: value" strings. Everything — User-Agent, the
# bug-bounty marker, cookies, auth tokens — lives here after build_headers.
# Call site helpers (h_curl, h_httpx, h_ffuf) expand it into tool-specific flags.
HEADERS=()
WORDLIST=""
VERBOSE=0
BYPASS=0

while getopts ":s:r:w:H:bv" opt; do
  case "$opt" in
    s) SCOPE_FILE="$OPTARG" ;;
    r) RATE_LIMIT="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    H) HEADERS+=("$OPTARG") ;;
    b) BYPASS=1 ;;
    v) VERBOSE=1 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "${SCOPE_FILE:-}" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$SCOPE_FILE" ]]; then
  echo "[-] Scope file not found: $SCOPE_FILE" >&2
  exit 1
fi

if [[ -n "$WORDLIST" && ! -f "$WORDLIST" ]]; then
  echo "[-] Wordlist not found: $WORDLIST" >&2
  exit 1
fi

# Prepend the fixed headers so user-supplied ones can override them if needed.
build_headers() {
  HEADERS=(
    "User-Agent: $USER_AGENT"
    "$HTTP_HEADER"
    "${HEADERS[@]}"
  )
}

# h_curl  → repeated: -H "Name: value"           (curl, katana, ungate, ffuf)
# h_httpx → repeated: -header "Name: value"       (httpx)
h_curl()  { local h; for h in "${HEADERS[@]}"; do printf '%s' "-H"; printf '%s' "$h"; done; }
h_httpx() { local h; for h in "${HEADERS[@]}"; do printf '%s' "-header"; printf '%s' "$h"; done; }

# These emit into arrays the caller captures with:
#   curl_h=(); readarray -d '' curl_h < <(h_curl_args)
# But it's cleaner to just inline the expansion at each call site; see below.
h_curl_args()  { local h; for h in "${HEADERS[@]}"; do printf -- '-H\0%s\0' "$h"; done; }
h_httpx_args() { local h; for h in "${HEADERS[@]}"; do printf -- '-header\0%s\0' "$h"; done; }

# ── run_cmd / show_usage ─────────────────────────────────────────────────────

run_cmd() {
  if (( VERBOSE )); then
    printf "${b_cyan}[CMD]${cyan}" >&2
    printf ' %q' "$@" >&2
    printf '%s\n' "${color_off}" >&2
  fi
  "$@"
}

show_usage() {
  if (( VERBOSE )); then
    echo -n "${b_cyan}[CMD]${cyan} "
    echo "$1"
    echo -n "${color_off}"
  fi
}

# ── Directory / file setup ───────────────────────────────────────────────────

mkdir -p "$SCAN_DIR" "$SS_DIR" "$RESPONSE_DIR"

touch \
  "$SCAN_DIR/amass.txt" \
  "$SCAN_DIR/subfinder.txt" \
  "$SCAN_DIR/sublister.txt" \
  "$SCAN_DIR/gau.txt" \
  "$SCAN_DIR/waybackurls.txt"

WILDCARD_ROOTS="$SCAN_DIR/wildcard_roots.txt"
SCOPE_URLS="$SCAN_DIR/scope_urls.txt"
KNOWN_HOSTS="$SCAN_DIR/known_hosts.txt"

: > "$WILDCARD_ROOTS"
: > "$SCOPE_URLS"
: > "$KNOWN_HOSTS"

# ── Scope normalisation ──────────────────────────────────────────────────────

normalize_scope() {
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    line="$(echo "$raw" | tr -d '\r' | xargs)"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    if [[ "$line" =~ ^\*\.(.+)$ ]]; then
      echo "${BASH_REMATCH[1]}" >> "$WILDCARD_ROOTS"
      continue
    fi

    if [[ "$line" =~ ^https?:// ]]; then
      url="$line"
    else
      url="https://$line"
    fi

    echo "$url" >> "$SCOPE_URLS"
    host="$(echo "$url" | sed -E 's#https?://##' | cut -d/ -f1 | cut -d: -f1)"
    echo "$host" >> "$KNOWN_HOSTS"
  done < "$SCOPE_FILE"

  sort -u "$WILDCARD_ROOTS" -o "$WILDCARD_ROOTS" 2>/dev/null || true
  sort -u "$SCOPE_URLS"     -o "$SCOPE_URLS"
  sort -u "$KNOWN_HOSTS"    -o "$KNOWN_HOSTS"
}

# ── Worker pool ──────────────────────────────────────────────────────────────

run_pool() {
  local worker_func="$1"
  local input_file="$2"

  while IFS= read -r item || [[ -n "$item" ]]; do
    while (( $(jobs -pr | wc -l) >= MAX_WORKERS )); do
      wait -n
    done
    "$worker_func" "$item" &
  done < "$input_file"

  wait
}

in_scope() {
  local host="${1%%:*}"

  if grep -qxF "$host" "$KNOWN_HOSTS" 2>/dev/null; then
    return 0
  fi

  while IFS= read -r root || [[ -n "$root" ]]; do
    [[ "$host" == "$root" || "$host" == *."$root" ]] && return 0
  done < "$WILDCARD_ROOTS"

  return 1
}

filter_in_scope() {
  while IFS= read -r url || [[ -n "$url" ]]; do
    local host
    host="$(echo "$url" | sed -E 's#https?://##' | cut -d/ -f1 | cut -d: -f1)"
    in_scope "$host" && echo "$url" || true
  done
}

# ── Subdomain enumeration ────────────────────────────────────────────────────

amass_worker() {
  local domain="$1"
  local tmp="$SCAN_DIR/amass_${domain}.txt"

  run_cmd amass enum -passive -d "$domain" >/dev/null 2>&1 || true
  run_cmd amass subs -names -d "$domain" > "$tmp" 2>/dev/null || true

  [[ -s "$tmp" ]] && cat "$tmp" >> "$SCAN_DIR/amass.txt" || true
}

subfinder_worker() {
  local domain="$1"
  local tmp="$SCAN_DIR/subfinder_${domain}.txt"

  run_cmd subfinder -silent -d "$domain" -o "$tmp" 2>/dev/null || true

  [[ -s "$tmp" ]] && cat "$tmp" >> "$SCAN_DIR/subfinder.txt" || true
}

sublist3r_worker() {
  local domain="$1"
  local tmp="$SCAN_DIR/sublister_${domain}.txt"

  run_cmd sublist3r -d "$domain" -t 3 -o "$tmp" >/dev/null 2>&1 || true

  [[ -s "$tmp" ]] && cat "$tmp" >> "$SCAN_DIR/sublister.txt" || true
}

build_domains() {
  cat "$KNOWN_HOSTS" \
      "$SCAN_DIR/amass.txt" \
      "$SCAN_DIR/subfinder.txt" \
      "$SCAN_DIR/sublister.txt" \
      2>/dev/null | sed '/^$/d' | sort -u > "$ROOT_DIR/domains.txt"
}

# ── httpx probing ────────────────────────────────────────────────────────────

run_httpx() {
  local httpx_h=()
  readarray -d '' httpx_h < <(h_httpx_args)

  run_cmd httpx \
    -l "$ROOT_DIR/domains.txt" \
    "${httpx_h[@]}" \
    -silent \
    -json \
    -no-color \
    -timeout 5 \
    -retries 2 \
    -rate-limit "$RATE_LIMIT" \
    -ports 80,443,7547,8089,8085,8443,8080,4567,7170,8008,2083,8000,2082,8081,2087,2086,8888,8880,60000,40000,9080,5985,9100,2096,3000,1024,30005,81,21,5000,2095 \
    -mc 100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511 \
    -status-code \
    -title \
    -tech-detect \
    -server \
    -content-length \
    -store-response \
    -store-response-dir "$RESPONSE_DIR" \
    -o "$SCAN_DIR/httpx.json" \
    $VERBOSE>/dev/null

  jq -r '
    [.url, (.status_code|tostring), (.webserver // "-"), ((.tech // []) | join(",")), (.title // "-")] | @tsv
  ' "$SCAN_DIR/httpx.json" 2>/dev/null \
  | awk -F'\t' '{printf "%-40s %-4s %-18s %-30s %s\n", $1,$2,$3,$4,$5}' \
  > "$SCAN_DIR/httpx_summary.txt"

  jq -r '.url'                              "$SCAN_DIR/httpx.json" 2>/dev/null | filter_in_scope | sort -u > "$ROOT_DIR/live_urls.txt"
  jq -r 'select(.status_code==403) | .url' "$SCAN_DIR/httpx.json" 2>/dev/null | filter_in_scope | sort -u > "$ROOT_DIR/forbidden_urls.txt"
}

# ── Response body analysis ───────────────────────────────────────────────────

# clip_match PATTERN LINE
# If LINE is short enough to be useful as-is, echo it unchanged.
# If it is a long single-line blob (minified JSON, HTML, etc.), extract a
# window of characters centred on the first occurrence of PATTERN instead.
# The window is:  ...{60 chars before match}{MATCH}{60 chars after}...
# Falls back to a plain truncation if grep -P is unavailable.
CLIP_THRESHOLD=200
CLIP_CONTEXT=60

clip_match() {
  local pattern="$1"
  local line="$2"
  local len="${#line}"

  if (( len <= CLIP_THRESHOLD )); then
    echo "$line"
    return
  fi

  # Try PCRE lookahead/lookbehind window first (GNU grep -P)
  local window
  window="$(echo "$line" | grep -oiP ".{0,${CLIP_CONTEXT}}(?:${pattern}).{0,${CLIP_CONTEXT}}" 2>/dev/null | { head -n1; cat > /dev/null; } )"

  if [[ -n "$window" ]]; then
    echo "...$window..."
  else
    # Fallback: plain truncation at threshold with ellipsis
    echo "${line:0:${CLIP_THRESHOLD}}..."
  fi
}

run_response_analysis() {
  : > "$ROOT_DIR/response_findings.txt"

  local find_dirs=()
  [[ -d "$RESPONSE_DIR" ]]              && find_dirs+=("$RESPONSE_DIR")
  [[ -d "$SCAN_DIR/katana_responses" ]] && find_dirs+=("$SCAN_DIR/katana_responses")

  [[ ${#find_dirs[@]} -eq 0 ]] && { echo "  [!] No stored responses found; skipping body analysis." >&2; return; }

  while IFS= read -r -d '' resp_file; do
    [[ "$resp_file" == *.js ]] && continue || true
    grep -qiE '^Content-Type:.*javascript' "$resp_file" 2>/dev/null && continue || true

    local label
    label="$(basename "$(dirname "$resp_file")")/$(basename "$resp_file")"

    # RESPONSE_LEAK — most likely to be on a fat minified line; clip around match
    while IFS= read -r match_line; do
      local clipped
      clipped="$(clip_match "$LEAK_PATTERN" "$match_line")"
      { echo "[FINDING]"; echo "TYPE: RESPONSE_LEAK"; echo "FILE: $label"; echo "LINE: $clipped"; echo; } \
        >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inE "$LEAK_PATTERN" "$resp_file" 2>/dev/null | head -n 20 || true)

    # DEBUG_STRING — same risk of long lines
    while IFS= read -r match_line; do
      local clipped
      clipped="$(clip_match 'debug' "$match_line")"
      { echo "[FINDING]"; echo "TYPE: DEBUG_STRING"; echo "FILE: $label"; echo "LINE: $clipped"; echo; } \
        >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inF 'debug' "$resp_file" 2>/dev/null | head -n 10 || true)

    # VERSION and TECH tend to be short header values; store as-is but still
    # guard with a plain truncation so a pathological line can't blow the file
    while IFS= read -r match_line; do
      { echo "[FINDING]"; echo "TYPE: RESPONSE_VERSION"; echo "FILE: $label"
        echo "LINE: ${match_line:0:${CLIP_THRESHOLD}}"; echo; } \
        >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inE "$VERSION_PATTERN" "$resp_file" 2>/dev/null | grep -ivE '<\?xml|<svg|encoding=' | head -n 20 || true)

    while IFS= read -r match_line; do
      { echo "[FINDING]"; echo "TYPE: RESPONSE_TECH"; echo "FILE: $label"
        echo "LINE: ${match_line:0:${CLIP_THRESHOLD}}"; echo; } \
        >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inE "$TECH_PATTERN" "$resp_file" 2>/dev/null | head -n 20 || true)

  done < <(find "${find_dirs[@]}" -type f -print0 2>/dev/null)
}

# ── Archive collectors ────────────────────────────────────────────────────────

run_archives() {
  run_cmd waybackurls < "$ROOT_DIR/domains.txt" >> "$SCAN_DIR/waybackurls.txt" 2>/dev/null || true
  run_cmd getallurls -random-agent < "$ROOT_DIR/domains.txt" >> "$SCAN_DIR/gau.txt" 2>/dev/null || true

  sort -u "$SCAN_DIR/waybackurls.txt" -o "$SCAN_DIR/waybackurls.txt" 2>/dev/null || true
  sort -u "$SCAN_DIR/gau.txt"         -o "$SCAN_DIR/gau.txt"         2>/dev/null || true
}

# ── Katana crawler ───────────────────────────────────────────────────────────

run_katana() {
  mkdir -p "$SCAN_DIR/katana_responses"

  local curl_h=()
  readarray -d '' curl_h < <(h_curl_args)

  run_cmd katana \
    -list "$ROOT_DIR/live_urls.txt" \
    -silent \
    -d 3 \
    -jc \
    -kf all \
    -c 5 \
    -rl "$RATE_LIMIT" \
    "${curl_h[@]}" \
    -store-response \
    -store-response-dir "$SCAN_DIR/katana_responses" \
    -o "$ROOT_DIR/crawling.txt" \
    $VERBOSE>/dev/null || true

  [[ -s "$ROOT_DIR/crawling.txt" ]] && sort -u "$ROOT_DIR/crawling.txt" -o "$ROOT_DIR/crawling.txt" || true

  if [[ -s "$ROOT_DIR/crawling.txt" ]]; then
    filter_in_scope < "$ROOT_DIR/crawling.txt" | sort -u > "$ROOT_DIR/crawling_scoped.txt" || true
    mv "$ROOT_DIR/crawling_scoped.txt" "$ROOT_DIR/crawling.txt"
  fi
}

# ── URL parameter mining ─────────────────────────────────────────────────────

extract_params_from_urls() {
  local src_file="$1"
  local out_params="$2"
  local out_keys="$3"
  local out_values="$4"

  grep -F '?' "$src_file" 2>/dev/null >> "$out_params" || true

  while IFS= read -r url || [[ -n "$url" ]]; do
    local query="${url#*\?}"
    IFS='&' read -ra pairs <<< "$query"
    for pair in "${pairs[@]}"; do
      echo "${pair%%=*}" >> "$out_keys"
      [[ "$pair" == *=* ]] && echo "${pair#*=}" >> "$out_values"
    done
  done < <(grep -F '?' "$src_file" 2>/dev/null || true)
}

extract_params_from_js_body() {
  local js_file="$1"
  local out_keys="$2"
  local out_values="$3"

  grep -oE '[?&][A-Za-z0-9_%-]{1,64}=[^&"\047 \t>]+' "$js_file" 2>/dev/null \
  | while IFS='=' read -r kpart vpart; do
      echo "${kpart#[?&]}" >> "$out_keys"
      [[ -n "$vpart" ]] && echo "$vpart" >> "$out_values"
    done || true
}

parse_params() {
  local raw_params="$SCAN_DIR/url_params_raw.txt"
  local raw_keys="$SCAN_DIR/url_param_keys_raw.txt"
  local raw_values="$SCAN_DIR/url_param_values_raw.txt"

  : > "$raw_params"; : > "$raw_keys"; : > "$raw_values"

  for src in "$SCAN_DIR/waybackurls.txt" "$SCAN_DIR/gau.txt"; do
    [[ -s "$src" ]] && extract_params_from_urls "$src" "$raw_params" "$raw_keys" "$raw_values" || true
  done

  [[ -s "$ROOT_DIR/crawling.txt" ]] && \
    extract_params_from_urls "$ROOT_DIR/crawling.txt" "$raw_params" "$raw_keys" "$raw_values" || true

  if [[ -d "$SCAN_DIR/js_bodies" ]]; then
    while IFS= read -r -d '' jsbody; do
      extract_params_from_js_body "$jsbody" "$raw_keys" "$raw_values"
    done < <(find "$SCAN_DIR/js_bodies" -type f -print0 2>/dev/null)
  fi

  filter_in_scope < "$raw_params" | sort -u > "$ROOT_DIR/url_params.txt" || true
  sort -u "$raw_keys"   > "$ROOT_DIR/url_param_keys.txt"
  sort -u "$raw_values" > "$ROOT_DIR/url_param_values.txt"
}

# ── JavaScript analysis ──────────────────────────────────────────────────────

run_js_analysis() {
  : > "$ROOT_DIR/js_findings.txt"
  mkdir -p "$SCAN_DIR/js_bodies"

  {
    grep -E '\.js([?#][^[:space:]]*)?$' "$ROOT_DIR/crawling.txt"        2>/dev/null || true
    grep -E '\.js([?#][^[:space:]]*)?$' "$SCAN_DIR/waybackurls.txt"     2>/dev/null || true
    grep -E '\.js([?#][^[:space:]]*)?$' "$SCAN_DIR/gau.txt"             2>/dev/null || true
  } | sort -u > "$SCAN_DIR/js_urls.txt"

  if [[ ! -s "$SCAN_DIR/js_urls.txt" ]]; then
    echo "  [!] No JS URLs found; skipping JS analysis." >&2
    return
  fi

  local curl_delay
  curl_delay="$(echo "scale=3; 1 / ${RATE_LIMIT:-1}" | bc 2>/dev/null || echo 1)"

  local curl_h=()
  readarray -d '' curl_h < <(h_curl_args)

  while IFS= read -r jsurl || [[ -n "$jsurl" ]]; do
    local safe_name
    safe_name="$(echo "$jsurl" | sed 's|https\?://||;s|[/?&=:#]|_|g' | cut -c1-180).js"
    local body_file="$SCAN_DIR/js_bodies/${safe_name}"

    run_cmd curl -ksL --max-time 10 "${curl_h[@]}" "$jsurl" -o "$body_file" 2>/dev/null \
      || { rm -f "$body_file"; continue; }

    sleep "$curl_delay"
    [[ -s "$body_file" ]] || { rm -f "$body_file"; continue; }

    if command -v js-beautify >/dev/null 2>&1; then
      if (( VERBOSE )); then
        echo -n "${b_cyan}[CMD]${cyan} "
        js-beautify --replace "$body_file" || true
        echo -n "${color_off}"
      else
        js-beautify --replace "$body_file" 1>/dev/null || true
      fi
    fi

    _js_grep() {
      local type="$1" pattern="$2" opts="$3" extra_filter="${4:-}"
      local grep_cmd=( grep -n${opts}E "$pattern" "$body_file" )
      local out
      out="$( "${grep_cmd[@]}" 2>/dev/null | head -n 50 || true )"
      [[ -n "$extra_filter" ]] && out="$(echo "$out" | grep -ivE "$extra_filter" || true)"
      while IFS=: read -r line_no code; do
        { echo "[FINDING]"; echo "TYPE: $type"; echo "FILE: $jsurl"; echo "LINE: $line_no"; echo "CODE: $code"; echo; } \
          >> "$ROOT_DIR/js_findings.txt"
      done <<< "$out"
    }

    _js_grep JS_SINK    "$SINK_PATTERN"    ""  ""
    _js_grep JS_LEAK    "$LEAK_PATTERN"    "i" ""
    _js_grep JS_VERSION "$VERSION_PATTERN" "i" '<\?xml|<svg|encoding='

    while IFS= read -r match_line; do
      { echo "[FINDING]"; echo "TYPE: JS_DEBUG"; echo "FILE: $jsurl"; echo "LINE: $match_line"; echo; } \
        >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -inF 'debug' "$body_file" 2>/dev/null | head -n 10 || true)

    while IFS= read -r match_line; do
      { echo "[FINDING]"; echo "TYPE: JS_TECH"; echo "FILE: $jsurl"; echo "LINE: $match_line"; echo; } \
        >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -inE "$TECH_PATTERN" "$body_file" 2>/dev/null | head -n 20 || true)

  done < "$SCAN_DIR/js_urls.txt"

  if command -v secretfinder >/dev/null 2>&1; then
    while IFS= read -r jsurl || [[ -n "$jsurl" ]]; do
      run_cmd secretfinder -i "$jsurl" "${curl_h[@]}" -o cli >> "$ROOT_DIR/js_findings.txt" 2>/dev/null || true
    done < "$SCAN_DIR/js_urls.txt"
  fi

  if command -v linkfinder >/dev/null 2>&1; then
    while IFS= read -r jsurl || [[ -n "$jsurl" ]]; do
      run_cmd linkfinder -i "$jsurl" "${curl_h[@]}" -o cli >> "$ROOT_DIR/js_findings.txt" 2>/dev/null || true
    done < "$SCAN_DIR/js_urls.txt"
  fi
}

# ── Fuzz target selection ─────────────────────────────────────────────────────
# Reads live_urls.txt and writes fuzz_targets.txt — the subset of live base URLs
# (scheme + host, no path) whose hostname contains at least one label that matches
# INTERESTING_HOST_PATTERN.  Each hostname label (dot-separated token) is tested
# independently so "api-v2.prod.example.com" matches on "api" even though the
# full string wouldn't.  Scope is enforced via filter_in_scope.

build_fuzz_targets() {
  : > "$ROOT_DIR/fuzz_targets.txt"

  while IFS= read -r url || [[ -n "$url" ]]; do
    # Extract bare host (no port)
    local host
    host="$(echo "$url" | sed -E 's#https?://##' | cut -d/ -f1 | cut -d: -f1)"

    # Walk every dot-separated label of the hostname
    local label matched=0
    IFS='.' read -ra labels <<< "$host"
    for label in "${labels[@]}"; do
      if echo "$label" | grep -qiE "^(${INTERESTING_HOST_PATTERN})$"; then
        matched=1
        break
      fi
    done

    (( matched )) || continue

    # Emit scheme+host only (strip any path) — deduplicated at the end
    local base_url
    base_url="$(echo "$url" | grep -oE '^https?://[^/]+')"
    echo "$base_url"

  done < <(filter_in_scope < "$ROOT_DIR/live_urls.txt") \
  | sort -u > "$ROOT_DIR/fuzz_targets.txt"

  local count
  count="$(wc -l < "$ROOT_DIR/fuzz_targets.txt")"

  if (( count == 0 )); then
    echo "  [!] No interesting hosts found; falling back to scope entries." >&2
    # Use scheme+host only from SCOPE_URLS, filtered to what's actually live
    while IFS= read -r url || [[ -n "$url" ]]; do
      local base_url
      base_url="$(echo "$url" | grep -oE '^https?://[^/]+')"
      grep -qxF "$base_url" "$ROOT_DIR/live_urls.txt" 2>/dev/null && echo "$base_url" || true
    done < "$SCOPE_URLS" | sort -u > "$ROOT_DIR/fuzz_targets.txt"
    count="$(wc -l < "$ROOT_DIR/fuzz_targets.txt")"
    echo "  [*] Fallback fuzz targets: $count" >&2
  else
    echo "  [*] Fuzz targets selected: $count / $(wc -l < "$ROOT_DIR/live_urls.txt") live hosts" >&2
  fi
}

# ── Content discovery ─────────────────────────────────────────────────────────

run_content_discovery() {
  [[ -z "$WORDLIST" ]] && return

  if [[ ! -s "$ROOT_DIR/fuzz_targets.txt" ]]; then
    echo "  [!] No interesting fuzz targets found; skipping content discovery." >&2
    return
  fi

  local ffuf_dir="$SCAN_DIR/ffuf"
  mkdir -p "$ffuf_dir"
  : > "$ROOT_DIR/content_discovery.txt"

  local target_count word_count
  target_count="$(wc -l < "$ROOT_DIR/fuzz_targets.txt")"
  word_count="$(wc -l < "$WORDLIST")"
  echo "  [*] Content discovery: $target_count interesting targets x $word_count words (sequential, rate=${RATE_LIMIT}/s)"

  local curl_h=()
  readarray -d '' curl_h < <(h_curl_args)

  while IFS= read -r base_url || [[ -n "$base_url" ]]; do
    base_url="${base_url%/}"

    local safe_name out_file
    safe_name="$(echo "$base_url" | sed 's|https\?://||;s|[/:]|_|g' | cut -c1-120)"
    out_file="$ffuf_dir/${safe_name}.json"

    # -t 1 keeps ffuf single-threaded so -rate is the only pacing knob.
    # Running targets sequentially (this loop) means the global rate is
    # exactly RATE_LIMIT req/s — no cross-target concurrency.
    run_cmd ffuf \
      -u "${base_url}/FUZZ" \
      -w "$WORDLIST" \
      -s \
      "${curl_h[@]}" \
      -rate "$RATE_LIMIT" \
      -mc 200,201,202,204,301,302,307,401,403,405,500 \
      -o "$out_file" \
      -of json \
      -t 1 \
      $VERBOSE>/dev/null || true

    jq -r '.results[]? | [.url, (.status|tostring), (.length|tostring)] | @tsv' \
      "$out_file" 2>/dev/null \
    | awk -F'\t' '{printf "%-60s %-4s %s\n", $1,$2,$3}' \
    >> "$ROOT_DIR/content_discovery.txt" || true

  done < "$ROOT_DIR/fuzz_targets.txt"

  sort -u "$ROOT_DIR/content_discovery.txt" -o "$ROOT_DIR/content_discovery.txt"
}

# ── API fuzzing ───────────────────────────────────────────────────────────────

run_api_fuzz() {
  [[ -z "$WORDLIST" ]] && return

  if [[ ! -s "$ROOT_DIR/fuzz_targets.txt" ]]; then
    echo "  [!] No interesting fuzz targets found; skipping API fuzzing." >&2
    return
  fi

  local api_dir="$SCAN_DIR/api_fuzz"
  mkdir -p "$api_dir"
  : > "$ROOT_DIR/api_findings.txt"

  local target_count
  target_count="$(wc -l < "$ROOT_DIR/fuzz_targets.txt")"
  echo "  [*] API fuzzing: $target_count interesting targets x ${#API_BASE_PATHS[@]} base paths x 2 methods (sequential, rate=${RATE_LIMIT}/s)"

  local curl_h=()
  readarray -d '' curl_h < <(h_curl_args)

  while IFS= read -r base_url || [[ -n "$base_url" ]]; do
    base_url="${base_url%/}"

    local safe_base
    safe_base="$(echo "$base_url" | sed 's|https\?://||;s|[/:]|_|g' | cut -c1-100)"

    for api_path in "${API_BASE_PATHS[@]}"; do
      local target="${base_url}${api_path}/FUZZ"
      local safe_path
      safe_path="$(echo "$api_path" | tr '/' '_')"

      for method in GET POST; do
        local out_file="${api_dir}/${safe_base}${safe_path}_${method}.json"

        local method_args=()
        if [[ "$method" == "POST" ]]; then
          method_args+=("-X" "POST" "-d" "{}" "-H" "Content-Type: application/json")
        fi

        # -t 1: single-threaded so -rate is the sole pacing mechanism.
        # Targets, base paths, and methods are all looped sequentially here —
        # no concurrency anywhere in the fuzzing phase.
        run_cmd ffuf \
          -u "$target" \
          -w "$WORDLIST" \
          -s \
          "${curl_h[@]}" \
          "${method_args[@]}" \
          -rate "$RATE_LIMIT" \
          -mc 200,201,202,204,301,302,307,401,403,405,500 \
          -o "$out_file" \
          -of json \
          -t 1 \
          $VERBOSE>/dev/null || true

        jq -r --arg method "$method" \
          '.results[]? | [$method, .url, (.status|tostring), (.length|tostring)] | @tsv' \
          "$out_file" 2>/dev/null \
        | awk -F'\t' '{printf "%-5s %-60s %-4s %s\n", $1,$2,$3,$4}' \
        >> "$ROOT_DIR/api_findings.txt" || true

      done
    done
  done < "$ROOT_DIR/fuzz_targets.txt"

  sort -u "$ROOT_DIR/api_findings.txt" -o "$ROOT_DIR/api_findings.txt"
}

# ── Screenshots ───────────────────────────────────────────────────────────────

run_gowitness() {
  run_cmd gowitness scan file -f "$ROOT_DIR/live_urls.txt" --screenshot-path "$SS_DIR" >/dev/null 2>&1 || true
}

# ── 403 bypass ───────────────────────────────────────────────────────────────

run_ungate() {
  local delay_ms=$(( 1000 / (RATE_LIMIT > 0 ? RATE_LIMIT : 1) ))
  : > "$ROOT_DIR/403_bypass_ungate.txt"

  local curl_h=()
  readarray -d '' curl_h < <(h_curl_args)

  while IFS= read -r url || [[ -n "$url" ]]; do
    run_cmd ungate \
      -u "$url" \
      -k all \
      -d "$delay_ms" \
      -a "$USER_AGENT" \
      -i 127.0.0.1 \
      "${curl_h[@]}" \
      -o "$ROOT_DIR/403_bypass_ungate.txt" >/dev/null 2>&1 || true
  done < "$ROOT_DIR/forbidden_urls.txt"

  [[ -s "$ROOT_DIR/403_bypass_ungate.txt" ]] && sort -u "$ROOT_DIR/403_bypass_ungate.txt" -o "$ROOT_DIR/403_bypass_ungate.txt" || true
}

# ── Report generation ─────────────────────────────────────────────────────────

generate_report() {
  local sub_count live_count forbidden_count
  local js_count response_leak_count debug_count version_count tech_count
  local param_count content_disc_count api_finding_count

  sub_count=$(           wc -l < "$ROOT_DIR/domains.txt"              2>/dev/null || echo 0)
  live_count=$(          wc -l < "$ROOT_DIR/live_urls.txt"            2>/dev/null || echo 0)
  forbidden_count=$(     wc -l < "$ROOT_DIR/forbidden_urls.txt"       2>/dev/null || echo 0)
  param_count=$(         wc -l < "$ROOT_DIR/url_params.txt"           2>/dev/null || echo 0)

  js_count=$(            grep -c '^TYPE: JS_'        "$ROOT_DIR/js_findings.txt"       2>/dev/null || echo 0)
  js_count="${js_count%%$'\n'*}"
  version_count=$( {     grep -c '^TYPE: .*VERSION' "$ROOT_DIR/response_findings.txt" 2>/dev/null || echo 0; } | awk '{s+=$1} END{print s+0}')

  clean_x=$(grep -c '^TYPE: JS_VERSION' "$ROOT_DIR/js_findings.txt" 2>/dev/null || echo 0)
  clean_1="${clean_x%%$'\n'*}"
  version_count=$((version_count + clean_1))

  tech_count=$(    {     grep -c '^TYPE: .*TECH'    "$ROOT_DIR/response_findings.txt" 2>/dev/null || echo 0; } | awk '{s+=$1} END{print s+0}')

  clean_y=$(grep -c '^TYPE: JS_TECH'    "$ROOT_DIR/js_findings.txt" 2>/dev/null || echo 0)
  clean_2="${clean_y%%$'\n'*}"
  tech_count=$((tech_count + clean_2))

  response_leak_count=$( grep -c '^TYPE: RESPONSE_LEAK' "$ROOT_DIR/response_findings.txt" 2>/dev/null || echo 0)

  debug_count=$(
    { grep -c '^TYPE: .*DEBUG' "$ROOT_DIR/response_findings.txt" 2>/dev/null || echo 0; } | awk '{s+=$1} END{print s+0}'
    { grep -c '^TYPE: .*DEBUG' "$ROOT_DIR/js_findings.txt"       2>/dev/null || echo 0; } | awk '{s+=$1} END{print s+0}'
  ) 2>/dev/null
  debug_count=$(echo "$debug_count" | awk '{s+=$1} END{print s+0}')

  content_disc_count=$(  wc -l 2>/dev/null < "$ROOT_DIR/content_discovery.txt" || echo 0)
  api_finding_count=$(   wc -l 2>/dev/null < "$ROOT_DIR/api_findings.txt"      || echo 0)

  {
    echo "reabcon report"
    echo "Generated: $(date)"
    echo

    echo "== Statistics =="
    printf "%-30s %s\n" "Known/discovered hosts:"  "$sub_count"
    printf "%-30s %s\n" "Live URLs:"               "$live_count"
    printf "%-30s %s\n" "403 URLs:"                "$forbidden_count"
    printf "%-30s %s\n" "URLs with parameters:"    "$param_count"
    printf "%-30s %s\n" "JS findings:"             "$js_count"
    printf "%-30s %s\n" "Response body leaks:"     "$response_leak_count"
    printf "%-30s %s\n" "Debug string hits:"       "$debug_count"
    printf "%-30s %s\n" "Version strings found:"   "$version_count"
    printf "%-30s %s\n" "Tech fingerprints found:" "$tech_count"
    printf "%-30s %s\n" "Content discovery hits:"  "$content_disc_count"
    printf "%-30s %s\n" "API fuzz findings:"       "$api_finding_count"
    echo

    echo "== Interesting endpoints =="
    grep -Ei "$INTERESTING_PATH_PATTERN" "$ROOT_DIR/crawling.txt" 2>/dev/null | sort -u | head -n 100 || true
    echo

    echo "== Content discovery hits =="
    [[ -s "$ROOT_DIR/content_discovery.txt" ]] && head -n 100 "$ROOT_DIR/content_discovery.txt" || echo "(none - wordlist not provided or no hits)"
    echo

    echo "== API fuzz findings =="
    [[ -s "$ROOT_DIR/api_findings.txt" ]] && head -n 100 "$ROOT_DIR/api_findings.txt" || echo "(none - wordlist not provided or no hits)"
    echo

    echo "== High-risk parameters =="
    grep -Ei "$PARAM_PATTERN" "$ROOT_DIR/url_params.txt" 2>/dev/null | head -n 100 || true
    echo

    echo "== Response body leaks =="
    awk '
      /^\[FINDING\]/ { in_block=1; type=""; file=""; line="" }
      in_block && /^TYPE: RESPONSE_LEAK/ { type=$0 }
      in_block && /^FILE:/  { file=$0 }
      in_block && /^LINE:/  { line=substr($0, 7) }
      in_block && /^$/ && type != "" {
        printf "%s\n  %s\n  MATCH: %s\n\n", file, type, line
        in_block=0; count++
        if (count >= 50) exit
      }
    ' "$ROOT_DIR/response_findings.txt" 2>/dev/null || true
    echo

    echo "== Debug strings in responses / JS =="
    awk '
      /^\[FINDING\]/ { in_block=1; type=""; file=""; line="" }
      in_block && /^TYPE: (DEBUG_STRING|JS_DEBUG)/ { type=$0 }
      in_block && /^FILE:/  { file=$0 }
      in_block && /^LINE:/  { line=substr($0, 7) }
      in_block && /^CODE:/  { line=substr($0, 7) }
      in_block && /^$/ && type != "" {
        printf "%s\n  %s\n  MATCH: %s\n\n", file, type, line
        in_block=0; count++
        if (count >= 30) exit
      }
    ' "$ROOT_DIR/response_findings.txt" "$ROOT_DIR/js_findings.txt" 2>/dev/null || true
    echo

    echo "== JS sinks / leaks =="
    grep -EA4 '^TYPE: JS_SINK|^TYPE: JS_LEAK' "$ROOT_DIR/js_findings.txt" 2>/dev/null | head -n 100 || true
    echo

    echo "== Successful 403 bypass indicators =="
    grep -Ei '200|201|202|204|success|bypass' "$ROOT_DIR/403_bypass_ungate.txt" 2>/dev/null | head -n 50 || true
    echo

    echo "== Technologies (httpx) =="
    jq -r '.tech[]?' "$SCAN_DIR/httpx.json" 2>/dev/null | sort | uniq -c | sort -nr | head -n 20 || true
    echo

    echo "== Version strings =="
    {
      grep -A3 '^TYPE: RESPONSE_VERSION' "$ROOT_DIR/response_findings.txt" 2>/dev/null | head -n 60 || true
      grep -A4 '^TYPE: JS_VERSION'       "$ROOT_DIR/js_findings.txt"       2>/dev/null | head -n 60 || true
    }
    echo

    echo "== Tech fingerprints (response bodies / JS) =="
    {
      grep -A3 '^TYPE: RESPONSE_TECH' "$ROOT_DIR/response_findings.txt" 2>/dev/null | head -n 60 || true
      grep -A4 '^TYPE: JS_TECH'       "$ROOT_DIR/js_findings.txt"       2>/dev/null | head -n 60 || true
    }

  } > "$ROOT_DIR/report.txt"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  echo "$draw_line"
  banner
  echo "$draw_line"
  build_headers

  echo "${star} Normalizing scope...${color_off}"
  normalize_scope

  if [[ -s "$WILDCARD_ROOTS" ]]; then
    echo "${star} Running passive Amass...${color_off}"
    run_pool amass_worker "$WILDCARD_ROOTS"

    echo "${star} Running Subfinder...${color_off}"
    run_pool subfinder_worker "$WILDCARD_ROOTS"

    echo "${star} Running Sublist3r...${color_off}"
    run_pool sublist3r_worker "$WILDCARD_ROOTS"
  fi

  echo "${star} Building master domains.txt...${color_off}"
  build_domains

  echo "${star} Running httpx (probing + storing responses)...${color_off}"
  run_httpx

  echo "${star} Running archive collectors...${color_off}"
  run_archives

  echo "${star} Crawling with Katana...${color_off}"
  run_katana

  echo "${star} Analysing stored response bodies...${color_off}"
  run_response_analysis

  echo "${star} Analysing JavaScript files...${color_off}"
  run_js_analysis

  echo "${star} Parsing URL parameters (all sources)...${color_off}"
  parse_params

  if [[ -n "$WORDLIST" ]]; then
    echo "${star} Selecting interesting fuzz targets from live hosts...${color_off}"
    build_fuzz_targets

    echo "${star} Running content discovery...${color_off}"
    run_content_discovery

    echo "${star} Running API fuzzing (GET + POST)...${color_off}"
    run_api_fuzz
  else
    echo "${star} Skipping content discovery and API fuzzing (no -w wordlist supplied)${color_off}"
  fi

  echo "${star} Taking screenshots...${color_off}"
  run_gowitness

  if (( BYPASS )); then
    echo "${star} Running ungate on 403 URLs...${color_off}"
    run_ungate
  else
    echo "${star} Skipping 403 bypass (use -b to enable)${color_off}"
  fi

  echo "${star} Generating report...${color_off}"
  generate_report

  echo
  echo "${b_green}[+]${green} Recon finished"
  echo "    Hosts      : $(wc -l < "$ROOT_DIR/domains.txt")"
  echo "    Live URLs  : $(wc -l < "$ROOT_DIR/live_urls.txt" 2>/dev/null || echo 0)"
  echo "    JS files   : $(wc -l < "$SCAN_DIR/js_urls.txt" 2>/dev/null || echo 0)"
  echo "    Report     : $ROOT_DIR/report.txt${color_off}"

  echo "$draw_line"
  head -n 14 $ROOT_DIR/report.txt

  echo "$draw_line"
}

main "$@"
