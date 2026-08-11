#!/usr/bin/env bash
set -Eeuo pipefail

trap 'echo "${red}[-] ERROR -> Failed at line $LINENO: ${b_red}$BASH_COMMAND${red} -> (exit $?)${color_off}" >&2' ERR

# reabcon - Bug bounty reconnaissance helper
# Requirements:
#   amass, subfinder, sublist3r, httpx, gau, waybackurls, katana, gowitness, ungate, ffuf
# Optional:
#   SecretFinder.py, linkfinder.py

RATE_LIMIT=5
HTTP_HEADER="X-Bugbounty: "
MAX_WORKERS=5
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

ROOT_DIR="$PWD"
SCAN_DIR="$ROOT_DIR/scans"
SS_DIR="$ROOT_DIR/ss"
RESPONSE_DIR="$SCAN_DIR/responses"

color_off=$'\e[0;0m'
cyan=$'\e[0;96m'
green=$'\e[0;92m'
red=$'\e[0;31m'

#b_green=$'\e[1;32m'
b_green=$'\e[1;92m'
b_red=$'\e[1;31m'
b_cyan=$'\e[1;96m'

star="${b_green}[*]${green}"
draw_line="${red}----------------------------------------------------------------------------------${color_off}"

# ── Patterns ────────────────────────────────────────────────────────────────

# Regex for URL parameters worth saving
PARAM_PATTERN='redirect=|url=|next=|return=|returnTo=|callback=|continue=|dest=|destination=|target=|view=|file=|path=|folder=|template=|page=|lang=|locale=|token=|access_token=|refresh_token=|jwt=|auth=|session=|api_key=|apikey=|key=|secret=|signature='

# Regex for info-leak strings in response bodies / JS
LEAK_PATTERN='password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|aws_|BEGIN (RSA|EC|OPENSSH|PGP)|Authorization:|Basic [A-Za-z0-9+/=]{8,}|Bearer [A-Za-z0-9._\-]{8,}|-----BEGIN|mysql://|postgres://|mongodb://|redis://|smtp://|\.env|\.git/config|internal error|stack trace|traceback|exception in|at [A-Za-z]+\.[A-Za-z]+\(.*:[0-9]+\)'

# Regex for XSS / injection sinks in JS
SINK_PATTERN='innerHTML|outerHTML|document\.write|eval\(|new Function\(|location\.hash|location\.search|postMessage|addEventListener\([\"'\'']message|onmessage\s*='

# Regex for version number strings in responses / JS bodies.
# Matches common formats: X.Y, X.Y.Z, X.Y.Z.W, optionally preceded by a
# word boundary so "v2.1.3", "version=3.0", "jQuery/1.11.1" all match.
# Regex for version number strings in responses / JS bodies.
# XML declarations and SVG version attrs are excluded at grep time to avoid false positives.
VERSION_PATTERN='[Vv]ersion["'\''\s:=]+[0-9]+\.[0-9]+|[Vv][0-9]+\.[0-9]+\.[0-9]+|/[0-9]+\.[0-9]+\.[0-9]+["'\''\s/]|"version"\s*:\s*"[0-9]+\.[0-9]+'

# Regex for technology / framework fingerprints in response headers and bodies.
# Covers server banners, generator meta tags, JS globals, and common headers.
TECH_PATTERN='X-Powered-By:|X-Generator:|X-AspNet-Version:|X-AspNetMvc-Version:|X-Drupal|X-Joomla|Server:\s*(Apache|nginx|IIS|LiteSpeed|Caddy|Tomcat|JBoss|WebLogic|WebSphere|Jetty|Gunicorn|uWSGI|Kestrel|OpenResty)|wp-content|wp-includes|Drupal\.settings|Joomla!|generator.*WordPress|generator.*Drupal|generator.*Joomla|laravel_session|XSRF-TOKEN|__rails|csrfmiddlewaretoken|ASP\.NET_SessionId|JSESSIONID|struts|backbone\.js|angular\.js|react\.development|vue\.runtime|ember\.js|jquery[.-][0-9]|bootstrap[.-][0-9]|moment\.js|lodash\.js|GraphQL|ApolloClient|grpc-status|x-amz-|x-goog-|x-ms-|CF-Ray:|x-cache:|x-varnish:|x-envoy|x-kong-|x-forwarded-by'

# Regex for endpoints worth flagging in the report
INTERESTING_PATH_PATTERN='admin|administrator|manage|dashboard|console|internal|private|debug|test|staging|dev|qa|uat|beta|preview|backup|old|temp|upload|import|export|config|settings|graphql|swagger|openapi|api-docs|prometheus|metrics|actuator|health|env|\.git|\.svn|phpinfo|jenkins|kibana|grafana|sonar|nexus|artifactory|pgadmin'

# Common API base paths used during API fuzzing
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
${cyan}Usage: reabcon -s scope.txt [-r RATE] [-w wordlist.txt] [-c "Cookie: session=..."] [-h "Header: value"] [-b] [-v]

  -s   Scope file (required)
  -r   Rate limit in requests/sec (default: 5)
  -w   Wordlist for content discovery and API fuzzing (enables those phases)
  -c   Session cookie header, e.g. "Cookie: session=abc123" (forwarded to all tools)
  -h   Additional HTTP header (repeatable)
  -b   Enable 403 bypass with ungate (opt-in; can be noisy)
  -v   Verbose: print each tool invocation and its arguments before running

Examples:
  reabcon -s scope.txt
  reabcon -s scope.txt -r 10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
  reabcon -s scope.txt -w wordlist.txt -c "Cookie: PHPSESSID=deadbeef" -h "Authorization: Bearer TOKEN"${color_off}
EOF
}

# ── CLI argument parsing ─────────────────────────────────────────────────────

EXTRA_HEADERS=()
WORDLIST=""
SESSION_COOKIE=""
VERBOSE=0
BYPASS=0

while getopts ":s:r:w:c:h:bv" opt; do
  case "$opt" in
    s) SCOPE_FILE="$OPTARG" ;;
    r) RATE_LIMIT="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    c) SESSION_COOKIE="$OPTARG" ;;
    h) EXTRA_HEADERS+=("$OPTARG") ;;
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

# HEADER_ARGS holds all headers as repeated -H flags (curl / katana / ffuf / ungate style).
# httpx uses -header instead of -H; run_httpx converts locally with a simple substitution.
HEADER_ARGS=()

build_header_args() {
  HEADER_ARGS+=("-H" "User-Agent: $USER_AGENT")
  HEADER_ARGS+=("-H" "$HTTP_HEADER")
  [[ -n "$SESSION_COOKIE" ]] && HEADER_ARGS+=("-H" "$SESSION_COOKIE")
  for h in "${EXTRA_HEADERS[@]}"; do
    HEADER_ARGS+=("-H" "$h")
  done
}


# run_cmd TOOL [ARGS...]
# Prints the full invocation to stderr when -v is set, then executes it.
# Shell redirections written at the call site (>, >>, <, 2>/dev/null) are
# handled by the shell before run_cmd sees them and won't appear in the output;
# the tool name and all explicit arguments will.
run_cmd() {
  if (( VERBOSE )); then
    printf "${b_cyan}" >&2
    printf "[CMD]${cyan}" >&2
    printf ' %q' "$@" >&2
    printf ${color_off} >&2
    printf '\n' >&2
  fi
  "$@"
}

show_usage() {
  if [ $VERBOSE -eq 1 ]; then
    echo -n "${b_cyan}[CMD]${cyan} " ; echo "$1" ; echo -n "${color_off}"
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


# in_scope HOST
# Returns 0 if host matches a wildcard root or a known explicit host, 1 otherwise.
# Used to filter out-of-scope entries from URL lists and findings.
in_scope() {
  local host="$1"
  # Strip port if present
  host="${host%%:*}"

  # Exact match against known hosts
  if grep -qxF "$host" "$KNOWN_HOSTS" 2>/dev/null; then
    return 0
  fi

  # Suffix match against wildcard roots: host must equal root or end with .root
  while IFS= read -r root || [[ -n "$root" ]]; do
    [[ "$host" == "$root" || "$host" == *."$root" ]] && return 0
  done < "$WILDCARD_ROOTS"

  return 1
}

# filter_in_scope
# Reads URLs from stdin, prints only those whose host is in scope.
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
  show_usage "amass enum -passive -d "$domain" >/dev/null 2>&1 || true"

  run_cmd amass subs -names -d "$domain" > "$tmp" 2>/dev/null || true
  show_usage "amass subs -names -d "$domain" > "$tmp" 2>/dev/null || true"

  [[ -s "$tmp" ]] && cat "$tmp" >> "$SCAN_DIR/amass.txt" || true
}

subfinder_worker() {
  local domain="$1"
  local tmp="$SCAN_DIR/subfinder_${domain}.txt"

  run_cmd subfinder -silent -d "$domain" -o "$tmp" 2>/dev/null || true
  show_usage "subfinder -silent -d "$domain" -o "$tmp" 2>/dev/null || true"

  [[ -s "$tmp" ]] && cat "$tmp" >> "$SCAN_DIR/subfinder.txt" || true
}

sublist3r_worker() {
  local domain="$1"
  local tmp="$SCAN_DIR/sublister_${domain}.txt"

  run_cmd sublist3r -d "$domain" -t 3 -o "$tmp" >/dev/null 2>&1 || true
  show_usage "sublist3r -d "$domain" -t 3 -o "$tmp" >/dev/null 2>&1 || true"

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
  # httpx uses -header instead of -H; convert HEADER_ARGS locally
  local httpx_headers=()
  local _i=0
  while (( _i < ${#HEADER_ARGS[@]} )); do
    httpx_headers+=("-header" "${HEADER_ARGS[_i+1]}")
    (( _i += 2 ))
  done

  run_cmd httpx \
    -l "$ROOT_DIR/domains.txt" \
    "${httpx_headers[@]}" \
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

  jq -r '.url'                             "$SCAN_DIR/httpx.json" 2>/dev/null | filter_in_scope | sort -u > "$ROOT_DIR/live_urls.txt"
  jq -r 'select(.status_code==403) | .url'   "$SCAN_DIR/httpx.json" 2>/dev/null | filter_in_scope | sort -u > "$ROOT_DIR/forbidden_urls.txt"
}

# ── Response body analysis (httpx saved responses) ───────────────────────────
# Greps all stored response bodies for info-leak patterns and the literal
# string "debug", writing structured findings to response_findings.txt.

run_response_analysis() {
  : > "$ROOT_DIR/response_findings.txt"

  local find_dirs=()
  [[ -d "$RESPONSE_DIR" ]]                  && find_dirs+=("$RESPONSE_DIR")
  [[ -d "$SCAN_DIR/katana_responses" ]]     && find_dirs+=("$SCAN_DIR/katana_responses")

  [[ ${#find_dirs[@]} -eq 0 ]] && { echo "  [!] No stored responses found; skipping body analysis." >&2; return; }

  while IFS= read -r -d '' resp_file; do
    # Skip JS files — handled separately by run_js_analysis
    [[ "$resp_file" == *.js ]] && continue || true
	grep -qiE '^Content-Type:.*javascript' "$resp_file" 2>/dev/null && continue || true

    # httpx stores responses as <host>/<path>.txt - derive a label from the path
    local label
    label="$(basename "$(dirname "$resp_file")")/$(basename "$resp_file")"

    # Info-leak patterns
    while IFS= read -r match_line; do
      {
        echo "[FINDING]"
        echo "TYPE: RESPONSE_LEAK"
        echo "FILE: $label"
        echo "LINE: $match_line"
        echo
      } >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inE "$LEAK_PATTERN" "$resp_file" 2>/dev/null | head -n 20 || true)

    # Debug string - may indicate dev/staging code pushed to prod
    while IFS= read -r match_line; do
      {
        echo "[FINDING]"
        echo "TYPE: DEBUG_STRING"
        echo "FILE: $label"
        echo "LINE: $match_line"
        echo
      } >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inF 'debug' "$resp_file" 2>/dev/null | head -n 10 || true)

    # Version number strings
    while IFS= read -r match_line; do
      {
        echo "[FINDING]"
        echo "TYPE: RESPONSE_VERSION"
        echo "FILE: $label"
        echo "LINE: $match_line"
        echo
      } >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inE "$VERSION_PATTERN" "$resp_file" 2>/dev/null | grep -ivE '<\?xml|<svg|encoding=' | head -n 20 || true)

    # Technology / framework fingerprints
    while IFS= read -r match_line; do
      {
        echo "[FINDING]"
        echo "TYPE: RESPONSE_TECH"
        echo "FILE: $label"
        echo "LINE: $match_line"
        echo
      } >> "$ROOT_DIR/response_findings.txt"
    done < <(grep -inE "$TECH_PATTERN" "$resp_file" 2>/dev/null | head -n 20 || true)
  done < <(find "${find_dirs[@]}" -type f -print0 2>/dev/null)
}

# ── Archive collectors ────────────────────────────────────────────────────────

run_archives() {
  run_cmd waybackurls < "$ROOT_DIR/domains.txt" >> "$SCAN_DIR/waybackurls.txt" 2>/dev/null || true
  show_usage "waybackurls < $ROOT_DIR/domains.txt >> $SCAN_DIR/waybackurls.txt 2>/dev/null || true"

  run_cmd getallurls -random-agent < "$ROOT_DIR/domains.txt" >> "$SCAN_DIR/gau.txt" 2>/dev/null || true
  show_usage "getallurls -random-agent < $ROOT_DIR/domains.txt >> $SCAN_DIR/gau.txt 2>/dev/null || true"

  sort -u "$SCAN_DIR/waybackurls.txt" -o "$SCAN_DIR/waybackurls.txt" 2>/dev/null || true
  sort -u "$SCAN_DIR/gau.txt"         -o "$SCAN_DIR/gau.txt"         2>/dev/null || true
}

# ── Katana crawler ───────────────────────────────────────────────────────────

run_katana() {
  mkdir -p "$SCAN_DIR/katana_responses"

  run_cmd katana \
    -list "$ROOT_DIR/live_urls.txt" \
    -silent \
    -d 3 \
    -jc \
    -kf all \
    -c 5 \
    -rl "$RATE_LIMIT" \
    "${HEADER_ARGS[@]}" \
    -store-response \
    -store-response-dir "$SCAN_DIR/katana_responses" \
    -o "$ROOT_DIR/crawling.txt" \
	$VERBOSE>/dev/null || true

  [[ -s "$ROOT_DIR/crawling.txt" ]] && sort -u "$ROOT_DIR/crawling.txt" -o "$ROOT_DIR/crawling.txt" || true

  # Filter crawling output to in-scope URLs only
  if [[ -s "$ROOT_DIR/crawling.txt" ]]; then
    filter_in_scope < "$ROOT_DIR/crawling.txt" | sort -u > "$ROOT_DIR/crawling_scoped.txt" || true
    mv "$ROOT_DIR/crawling_scoped.txt" "$ROOT_DIR/crawling.txt"
  fi
}

# ── URL parameter mining ─────────────────────────────────────────────────────
# Sources: waybackurls, gau, katana crawling output, and inline JS content.
# Deduplication is applied to both the URL list and the extracted key/value sets.

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

# Mine ?key=value pairs out of raw JS source text.
extract_params_from_js_body() {
  local js_file="$1"   # path to a downloaded JS file on disk
  local out_keys="$2"
  local out_values="$3"

  # Match patterns like: someFunc("key", value), fetch("url?a=1&b=2"), URLSearchParams,
  # or plain key=value strings that look like query parameters.
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

  : > "$raw_params"
  : > "$raw_keys"
  : > "$raw_values"

  # 1. Waybackurls + gau
  for src in "$SCAN_DIR/waybackurls.txt" "$SCAN_DIR/gau.txt"; do
    [[ -s "$src" ]] && extract_params_from_urls "$src" "$raw_params" "$raw_keys" "$raw_values" || true
  done

  # 2. Katana crawling output
  [[ -s "$ROOT_DIR/crawling.txt" ]] && \
    extract_params_from_urls "$ROOT_DIR/crawling.txt" "$raw_params" "$raw_keys" "$raw_values" || true

  # 3. JS file bodies (already downloaded by run_js_analysis into SCAN_DIR/js_bodies/)
  if [[ -d "$SCAN_DIR/js_bodies" ]]; then
    while IFS= read -r -d '' jsbody; do
      extract_params_from_js_body "$jsbody" "$raw_keys" "$raw_values"
    done < <(find "$SCAN_DIR/js_bodies" -type f -print0 2>/dev/null)
  fi

  # Deduplicate everything
  # Filter params to in-scope URLs only before deduplication
  filter_in_scope < "$raw_params" | sort -u > "$ROOT_DIR/url_params.txt" || true
  sort -u "$raw_keys"    > "$ROOT_DIR/url_param_keys.txt"
  sort -u "$raw_values"  > "$ROOT_DIR/url_param_values.txt"
}

# ── JavaScript analysis ──────────────────────────────────────────────────────
# Downloads each JS URL discovered during crawling, then:
#   - Checks for XSS / injection sinks
#   - Checks for info-leak / secret patterns
#   - Checks for the literal string "debug"
#   - Runs SecretFinder and LinkFinder if available
# Bodies are retained in SCAN_DIR/js_bodies/ so parse_params() can mine them.

run_js_analysis() {
  : > "$ROOT_DIR/js_findings.txt"
  mkdir -p "$SCAN_DIR/js_bodies"

  # Collect JS URLs from crawling output; also check archive sources.
  # The regex anchors on .js with optional query/fragment so minified
  # files like bundle.js?v=123 are not missed.
  {
    grep -E '\.js([?#][^[:space:]]*)?$' "$ROOT_DIR/crawling.txt" 2>/dev/null || true
    grep -E '\.js([?#][^[:space:]]*)?$' "$SCAN_DIR/waybackurls.txt" 2>/dev/null || true
    grep -E '\.js([?#][^[:space:]]*)?$' "$SCAN_DIR/gau.txt" 2>/dev/null || true
  } | sort -u > "$SCAN_DIR/js_urls.txt"

  if [[ ! -s "$SCAN_DIR/js_urls.txt" ]]; then
    echo "  [!] No JS URLs found; skipping JS analysis." >&2
    return
  fi

  # Delay between curl fetches to honour RATE_LIMIT.
  # bc produces a decimal like "0.200" or "1.000" that sleep accepts.
  local curl_delay
  curl_delay="$(echo "scale=3; 1 / ${RATE_LIMIT:-1}" | bc 2>/dev/null || echo 1)"

  while IFS= read -r jsurl || [[ -n "$jsurl" ]]; do
    # Derive a safe filename from the URL for persistent storage
    local safe_name
    safe_name="$(echo "$jsurl" | sed 's|https\?://||;s|[/?&=:#]|_|g' | cut -c1-180).js"
    local body_file="$SCAN_DIR/js_bodies/${safe_name}"

    run_cmd curl -ksL --max-time 10 \
      "${HEADER_ARGS[@]}" \
      "$jsurl" -o "$body_file" 2>/dev/null \
    || { rm -f "$body_file"; continue; }

    sleep "$curl_delay"

    [[ -s "$body_file" ]] || { rm -f "$body_file"; continue; }

    # Deobfuscate / pretty-print minified JS so pattern matching works on
    # readable token boundaries rather than a single concatenated line.
    if command -v js-beautify >/dev/null 2>&1; then
		if [[ $VERBOSE -eq 1 ]]; then
		  echo -n "${b_cyan}[CMD]${cyan} "
		  js-beautify --replace "$body_file" || true
		  echo -n "${color_off}"
		else
		  js-beautify --replace "$body_file" 1>/dev/null || true
		fi
    fi

    # XSS / injection sinks
    while IFS=: read -r line_no code; do
      {
        echo "[FINDING]"
        echo "TYPE: JS_SINK"
        echo "FILE: $jsurl"
        echo "LINE: $line_no"
        echo "CODE: $code"
        echo
      } >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -nE "$SINK_PATTERN" "$body_file" 2>/dev/null | head -n 50 || true)

    # Info-leak / secret patterns
    while IFS=: read -r line_no code; do
      {
        echo "[FINDING]"
        echo "TYPE: JS_LEAK"
        echo "FILE: $jsurl"
        echo "LINE: $line_no"
        echo "CODE: $code"
        echo
      } >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -inE "$LEAK_PATTERN" "$body_file" 2>/dev/null | head -n 30 || true)

    # Debug strings
    while IFS=: read -r line_no code; do
      {
        echo "[FINDING]"
        echo "TYPE: JS_DEBUG"
        echo "FILE: $jsurl"
        echo "LINE: $line_no"
        echo "CODE: $code"
        echo
      } >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -inF 'debug' "$body_file" 2>/dev/null | head -n 10 || true)

    # Version number strings
    while IFS=: read -r line_no code; do
      {
        echo "[FINDING]"
        echo "TYPE: JS_VERSION"
        echo "FILE: $jsurl"
        echo "LINE: $line_no"
        echo "CODE: $code"
        echo
      } >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -inE "$VERSION_PATTERN" "$body_file" 2>/dev/null | grep -ivE '<\?xml|<svg|encoding=' | head -n 20 || true)

    # Technology / framework fingerprints
    while IFS=: read -r line_no code; do
      {
        echo "[FINDING]"
        echo "TYPE: JS_TECH"
        echo "FILE: $jsurl"
        echo "LINE: $line_no"
        echo "CODE: $code"
        echo
      } >> "$ROOT_DIR/js_findings.txt"
    done < <(grep -inE "$TECH_PATTERN" "$body_file" 2>/dev/null | head -n 20 || true)

  done < "$SCAN_DIR/js_urls.txt"

  if command -v secretfinder >/dev/null 2>&1; then
    while IFS= read -r jsurl || [[ -n "$jsurl" ]]; do
      run_cmd secretfinder -i "$jsurl" "${HEADER_ARGS[@]}" -o cli >> "$ROOT_DIR/js_findings.txt" 2>/dev/null || true
    done < "$SCAN_DIR/js_urls.txt"
  fi

  if command -v linkfinder >/dev/null 2>&1; then
    while IFS= read -r jsurl || [[ -n "$jsurl" ]]; do
      run_cmd linkfinder -i "$jsurl" "${HEADER_ARGS[@]}" -o cli >> "$ROOT_DIR/js_findings.txt" 2>/dev/null || true
    done < "$SCAN_DIR/js_urls.txt"
  fi
}

# ── Content discovery ─────────────────────────────────────────────────────────
# Runs ffuf with the supplied wordlist against every live URL (GET).
# Results are written per-host to SCAN_DIR/ffuf/ and aggregated.

run_content_discovery() {
  [[ -z "$WORDLIST" ]] && return

  local ffuf_dir="$SCAN_DIR/ffuf"
  mkdir -p "$ffuf_dir"
  : > "$ROOT_DIR/content_discovery.txt"

  echo "  [*] Content discovery: $(wc -l < "$ROOT_DIR/live_urls.txt") targets x $(wc -l < "$WORDLIST") words"

  while IFS= read -r base_url || [[ -n "$base_url" ]]; do
    # Strip trailing slash for consistent FUZZ placement
    base_url="${base_url%/}"

    local safe_name
    safe_name="$(echo "$base_url" | sed 's|https\?://||;s|[/:]|_|g' | cut -c1-120)"
    local out_file="$ffuf_dir/${safe_name}.json"

    run_cmd ffuf \
      -u "${base_url}/FUZZ" \
      -w "$WORDLIST" \
      -s \
      "${HEADER_ARGS[@]}" \
      -rate "$RATE_LIMIT" \
      -mc 200,201,202,204,301,302,307,401,403,405,500 \
      -o "$out_file" \
      -of json \
      -t 5 \
      $VERBOSE>/dev/null || true

    # Extract hits and append to the aggregated file
    jq -r '.results[]? | [.url, (.status|tostring), (.length|tostring)] | @tsv' \
      "$out_file" 2>/dev/null \
    | awk -F'\t' '{printf "%-60s %-4s %s\n", $1,$2,$3}' \
    >> "$ROOT_DIR/content_discovery.txt" || true

  done < "$ROOT_DIR/live_urls.txt"

  sort -u "$ROOT_DIR/content_discovery.txt" -o "$ROOT_DIR/content_discovery.txt"
}

# ── API fuzzing ───────────────────────────────────────────────────────────────
# For each live URL, appends known API base paths and fuzzes with the wordlist
# using both GET and POST.  A session cookie (if provided) is included so
# authenticated endpoints are reachable.

run_api_fuzz() {
  [[ -z "$WORDLIST" ]] && return

  local api_dir="$SCAN_DIR/api_fuzz"
  mkdir -p "$api_dir"
  : > "$ROOT_DIR/api_findings.txt"

  echo "  [*] API fuzzing: $(wc -l < "$ROOT_DIR/live_urls.txt") targets x ${#API_BASE_PATHS[@]} base paths x 2 methods"

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
          # Send an empty JSON body so JSON APIs don't reject the request
          method_args+=("-X" "POST" "-d" "{}" "-H" "Content-Type: application/json")
        fi

        run_cmd ffuf \
          -u "$target" \
          -w "$WORDLIST" \
          -s \
          "${HEADER_ARGS[@]}" \
          "${method_args[@]}" \
          -rate "$RATE_LIMIT" \
          -mc 200,201,202,204,301,302,307,401,403,405,500 \
          -o "$out_file" \
          -of json \
          -t 5 \
          $VERBOSE>/dev/null || true

        jq -r --arg method "$method" \
          '.results[]? | [$method, .url, (.status|tostring), (.length|tostring)] | @tsv' \
          "$out_file" 2>/dev/null \
        | awk -F'\t' '{printf "%-5s %-60s %-4s %s\n", $1,$2,$3,$4}' \
        >> "$ROOT_DIR/api_findings.txt" || true

      done
    done
  done < "$ROOT_DIR/live_urls.txt"

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

  while IFS= read -r url || [[ -n "$url" ]]; do
    run_cmd ungate \
      -u "$url" \
      -k all \
      -d "$delay_ms" \
      -a "$USER_AGENT" \
      -i 127.0.0.1 \
      "${HEADER_ARGS[@]}" \
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

  tech_count=$((tech_count    + clean_2  ))
  response_leak_count=$( grep -c '^TYPE: RESPONSE_LEAK' "$ROOT_DIR/response_findings.txt" 2>/dev/null || echo 0)

  debug_count=$(
    { grep -c '^TYPE: .*DEBUG' "$ROOT_DIR/response_findings.txt" 2>/dev/null || echo 0; } | awk '{s+=$1} END{print s+0}'
    { grep -c '^TYPE: .*DEBUG' "$ROOT_DIR/js_findings.txt"       2>/dev/null || echo 0; } | awk '{s+=$1} END{print s+0}'
  ) 2>/dev/null

  debug_count=$(echo "$debug_count" | awk '{s+=$1} END{print s+0}')
  content_disc_count=$(  wc -l 2>/dev/null < "$ROOT_DIR/content_discovery.txt" || echo 0)
  api_finding_count=$(   wc -l 2>/dev/null < "$ROOT_DIR/api_findings.txt"      || echo 0)

  #declare -p sub_count live_count forbidden_count param_count js_count version_count tech_count response_leak_count debug_count content_disc_count api_finding_count

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
    grep -A3 '^TYPE: RESPONSE_LEAK' "$ROOT_DIR/response_findings.txt" 2>/dev/null | head -n 100 || true
    echo

    echo "== Debug strings in responses / JS =="
    {
      grep -A3 '^TYPE: DEBUG_STRING' "$ROOT_DIR/response_findings.txt" 2>/dev/null | head -n 50 || true
      grep -A4 '^TYPE: JS_DEBUG'     "$ROOT_DIR/js_findings.txt"       2>/dev/null | head -n 50 || true
    }
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
  build_header_args

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
