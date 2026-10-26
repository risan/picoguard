#!/usr/bin/env bash
# Usage: audit-history.sh --names FILE --report FILE --summary FILE
#            [--known-public FILE] [--personal-terms FILE]
#            [--public-lists GLOB] [--repo DIR]
#
# Audits every commit reachable from every local ref, every remote-tracking ref
# and every object id the remote "origin" advertises, before a repository is
# made public. It looks for
#   - names from a private query file (--names, first column) in any file
#     version, with gzip files decompressed,
#   - secrets, with gitleaks over the full content of every file version plus
#     a few token patterns,
#   - personal identifiers: commit identities, home paths, private addresses,
#     host names of a home network and any word from --personal-terms.
#
# --report gets the detailed findings, names included, and must lie outside the
# repository. --summary gets counts and a verdict only and may be committed; it
# avoids ordinary words such as "local" that a one-word query name could equal.
# --public-lists is a glob, relative to the repository, of list files whose
# names are public; a query name found there or in --known-public is explained.
#
# Exit 0: nothing unresolved. 1: an unexplained query name, a secret, or a
# remote object missing locally (fetch first). 2: usage or a missing tool.
set -euo pipefail

export LC_ALL=C
tab=$'\t'

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
}

usage_error() {
    echo "error: $*" >&2
    echo >&2
    usage
    exit 2
}

names_file=
report_file=
summary_file=
known_public_file=
personal_terms_file=
public_lists='tests/fixtures/lists/*.txt.gz'
repo=.

while [ "$#" -gt 0 ]; do
    if [ "$#" -lt 2 ] && [ "$1" != "--help" ]; then
        usage_error "$1 needs a value"
    fi

    case $1 in
        --names) names_file=$2 ;;
        --report) report_file=$2 ;;
        --summary) summary_file=$2 ;;
        --known-public) known_public_file=$2 ;;
        --personal-terms) personal_terms_file=$2 ;;
        --public-lists) public_lists=$2 ;;
        --repo) repo=$2 ;;
        --help)
            usage
            exit 0
            ;;
        *) usage_error "unknown option $1" ;;
    esac

    shift 2
done

[ -n "$names_file" ] || usage_error "--names is required"
[ -n "$report_file" ] || usage_error "--report is required"
[ -n "$summary_file" ] || usage_error "--summary is required"

for tool in git gitleaks jq; do
    command -v "$tool" >/dev/null 2>&1 || usage_error "$tool is needed on PATH"
done

for file in "$names_file" "$known_public_file" "$personal_terms_file"; do
    if [ -n "$file" ] && [ ! -f "$file" ]; then
        usage_error "$file is not a file"
    fi
done

repo_root=$(git -C "$repo" rev-parse --show-toplevel 2>/dev/null) || usage_error "$repo is not a git repository"
repo_root=$(realpath "$repo_root")

report_path=$(realpath -m "$report_file")
case $report_path in
    "$repo_root" | "$repo_root"/*)
        usage_error "the report must lie outside the repository, or it could be committed"
        ;;
esac

git_repo() {
    git -C "$repo_root" "$@"
}

umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
blob_dir=$work/blobs
mkdir "$blob_dir"

# --- roots: every commit any ref or the remote can reach ----------------------

git_repo for-each-ref --format='%(refname)%09%(objectname)' >"$work/local-refs.tsv"

: >"$work/remote-refs.tsv"
if git_repo remote get-url origin >/dev/null 2>&1; then
    git_repo ls-remote origin >"$work/remote-refs.tsv" || {
        echo "error: git ls-remote origin failed, so the remote refs cannot be audited" >&2
        exit 2
    }
fi

: >"$work/roots.txt"
: >"$work/missing-remote.txt"

while IFS="$tab" read -r _ id; do
    git_repo rev-parse --verify --quiet "$id^{commit}" >>"$work/roots.txt" || true
done <"$work/local-refs.tsv"

while IFS="$tab" read -r id ref; do
    if ! git_repo cat-file -e "$id" 2>/dev/null; then
        echo "missing-remote $ref $id" >>"$work/missing-remote.txt"
    else
        git_repo rev-parse --verify --quiet "$id^{commit}" >>"$work/roots.txt" || true
    fi
done <"$work/remote-refs.tsv"

sort -u -o "$work/roots.txt" "$work/roots.txt"
[ -s "$work/roots.txt" ] || usage_error "$repo_root has no commits"

git_repo rev-list --reverse --stdin <"$work/roots.txt" >"$work/commits.txt"
commit_count=$(wc -l <"$work/commits.txt")

# --- tree map: (blob, first commit, path), oldest commit first ----------------

while read -r commit; do
    git_repo ls-tree -r --full-tree "$commit" |
        awk -F'\t' -v commit="$commit" -v OFS='\t' '{
            split($1, meta, " ")
            if (meta[2] == "blob") {
                print meta[3], commit, $2
            }
        }'
done <"$work/commits.txt" |
    awk -F'\t' '!seen[$1 FS $3]++' >"$work/treemap.tsv"

sort -t "$tab" -k1,1 "$work/treemap.tsv" >"$work/treemap.sorted.tsv"
cut -f1 "$work/treemap.tsv" | sort -u >"$work/blobs.txt"
blob_count=$(wc -l <"$work/blobs.txt")

# Every unique file version is written once, named by blob id. A gzip file is
# stored decompressed, so every later scan reads its content.
gzip_count=0
while read -r blob; do
    git_repo cat-file blob "$blob" >"$blob_dir/$blob"
    if [ "$(head -c2 "$blob_dir/$blob" | od -An -tx1 | tr -d ' \n')" = 1f8b ]; then
        if gzip -dc "$blob_dir/$blob" >"$blob_dir/$blob.unzipped" 2>/dev/null; then
            mv "$blob_dir/$blob.unzipped" "$blob_dir/$blob"
            gzip_count=$((gzip_count + 1))
        else
            rm -f "$blob_dir/$blob.unzipped"
        fi
    fi
done <"$work/blobs.txt"

# blob_of_file: turns "<dir>/<blob>:<rest>" lines into "<blob><tab><rest>".
blob_of_file() {
    awk -F: -v OFS='\t' '{
        n = split($1, parts, "/")
        rest = $2
        for (i = 3; i <= NF; i++) {
            rest = rest ":" $i
        }
        print parts[n], rest
    }'
}

# attach_locations <blob-tab-detail file>: prints blob, detail, commit, path.
attach_locations() {
    sort -t "$tab" -k1,1 "$1" | join -t "$tab" - "$work/treemap.sorted.tsv"
}

# --- query names --------------------------------------------------------------

normalize_names() {
    awk 'NF { print $1 }' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' | sort -u
}

domain_tokens='[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?'

normalize_names "$names_file" >"$work/names.txt"

# The lists that explain a name are read from the HEAD commit, never from the
# working tree, so an untracked or edited file cannot hide a finding.
{ git_repo ls-tree -r --name-only HEAD 2>/dev/null || true; } |
    while read -r path; do
        # shellcheck disable=SC2254
        case $path in
            $public_lists) echo "$path" ;;
        esac
    done >"$work/public-list-paths.txt"

{
    while read -r list; do
        case $list in
            *.gz) git_repo show "HEAD:$list" | gzip -dc 2>/dev/null || true ;;
            *) git_repo show "HEAD:$list" ;;
        esac
    done <"$work/public-list-paths.txt" |
        tr '[:upper:]' '[:lower:]' | { grep -a -o -E "$domain_tokens" || true; } | sed 's/\.$//'

    if [ -n "$known_public_file" ]; then
        normalize_names "$known_public_file"
    fi
} | sort -u >"$work/public-names.txt"

comm -12 "$work/names.txt" "$work/public-names.txt" >"$work/explained-names.txt"

# A name without a dot is a token only when it stands alone: "name.example" and
# "my-name" are other names, not a use of "name".
grep -v '\.' "$work/names.txt" | sed 's,[][\\.*^$+?(){}|/],\\&,g' | paste -s -d'|' >"$work/single-names.txt" || true

{
    { grep -a -r -o -i -H -E "$domain_tokens" "$blob_dir" || true; } |
        tr '[:upper:]' '[:lower:]' | sed 's/\.$//'

    if [ -s "$work/single-names.txt" ]; then
        { grep -a -r -o -i -H -E "(^|[^a-z0-9_.-])($(cat "$work/single-names.txt"))([^a-z0-9_.-]|$)" "$blob_dir" || true; } |
            tr '[:upper:]' '[:lower:]' | sed -E 's/:[^a-z0-9_.-]+/:/; s/[^a-z0-9_.-]+$//'
    fi
} | blob_of_file | awk -F'\t' -v OFS='\t' '{ print $2, $1 }' |
    sort -t "$tab" -k1,1 -k2,2 -u >"$work/tokens.tsv"

join -t "$tab" "$work/names.txt" "$work/tokens.tsv" |
    awk -F'\t' -v OFS='\t' '{ print $2, $1 }' >"$work/name-hits.tsv"

attach_locations "$work/name-hits.tsv" |
    awk -F'\t' -v OFS='\t' '{ print $2, $3, $4 }' | sort -t "$tab" -k1,1 -k3,3 -k2,2 >"$work/name-findings.tsv"

# Every place of every name is listed, explained or not.
awk -F'\t' 'FILENAME == ARGV[1] { explained[$1] = 1; next }
    !($1 in explained) { print "query-name unexplained " $1 " " $2 " " $3 }' \
    "$work/explained-names.txt" "$work/name-findings.tsv" >"$work/name-unexplained.txt"

awk -F'\t' 'FILENAME == ARGV[1] { explained[$1] = 1; next }
    ($1 in explained) { print "query-name explained " $1 " " $2 " " $3 }' \
    "$work/explained-names.txt" "$work/name-findings.tsv" | sort >"$work/name-explained.txt"

awk -F'\t' 'tolower($3) ~ /quer(y|ies)|querylog|\.env$|\.pem$|\.key$|id_(rsa|ed25519)|credential/ {
    print "path-review " $2 " " $3
}' "$work/treemap.tsv" >"$work/path-review.txt"

# --- secrets ------------------------------------------------------------------

# gitleaks runs from the work directory so it reads no ignore file or config of
# the audited repository, and --ignore-gitleaks-allow stops a "gitleaks:allow"
# comment in the audited content from hiding a finding.
(
    cd "$work"
    gitleaks dir "$blob_dir" --redact --report-format json --report-path "$work/gitleaks.json" \
        --no-banner --no-color --log-level error --exit-code 0 --ignore-gitleaks-allow
) >"$work/gitleaks.out" 2>&1 || {
    cat "$work/gitleaks.out" >&2
    echo "error: gitleaks failed" >&2
    exit 2
}

: >"$work/secret-hits.tsv"

if [ -s "$work/gitleaks.json" ]; then
    jq -r '.[] | [(.File | split("/") | last), .RuleID, (.StartLine | tostring)] | @tsv' \
        "$work/gitleaks.json" >>"$work/secret-hits.tsv"
fi

# The matched text never leaves grep: only the file and the line number do. The
# brackets keep this list from matching itself.
token_patterns=(
    'private-key|-----BEGIN [A-Z ]*PRIVATE KEY-----'
    'github-token|gh[pousr]_[0-9A-Za-z]{36}'
    'github-pat|github_pa[t]_'
    'crates-token|cio[0-9A-Za-z]{32}'
    'aws-key|AKIA[0-9A-Z]{16}'
    'slack-token|xox[abprs]-'
)

for entry in "${token_patterns[@]}"; do
    kind=${entry%%|*}
    pattern=${entry#*|}
    { grep -a -r -n -E -e "$pattern" "$blob_dir" || true; } |
        cut -d: -f1,2 | blob_of_file |
        awk -F'\t' -v OFS='\t' -v kind="$kind" '{ print $1, kind, $2 }' >>"$work/secret-hits.tsv"
done

sort -u -o "$work/secret-hits.tsv" "$work/secret-hits.tsv"
attach_locations "$work/secret-hits.tsv" |
    awk -F'\t' '{ print "secret " $2 " " $4 " " $5 " line " $3 }' | sort >"$work/secrets.txt"

# --- personal identifiers -----------------------------------------------------

git_repo log --reverse --stdin --format='%H%x09%an <%ae>%x09%cn <%ce>' <"$work/roots.txt" |
    awk -F'\t' '{
        roles["author"] = $2
        roles["committer"] = $3
        for (role in roles) {
            key = role "\t" roles[role]
            count[key]++
            if (!(key in first)) {
                first[key] = $1
            }
            last[key] = $1
        }
    }
    END {
        for (key in count) {
            split(key, parts, "\t")
            print "identity " parts[1] " " parts[2] " commits " count[key] " first " first[key] " last " last[key]
        }
    }' | sort >"$work/identities.txt"

sed "s|^|$blob_dir/|" "$work/blobs.txt" >"$work/personal-files.txt"

scan_personal() {
    local kind=$1
    shift

    if [ -s "$work/personal-files.txt" ]; then
        { xargs -a "$work/personal-files.txt" grep -a -o -i -H -w "$@" || true; } |
            blob_of_file | awk -F'\t' -v OFS='\t' -v kind="$kind" '{ print $1, kind, $2 }'
    fi
}

{
    scan_personal home-path -E '/home/[a-z0-9._-]+'
    scan_personal private-address -E '(10(\.[0-9]{1,3}){3}|192\.168(\.[0-9]{1,3}){2}|172\.(1[6-9]|2[0-9]|3[01])(\.[0-9]{1,3}){2})'
    scan_personal local-host -E '[a-z0-9-]+(\.[a-z0-9-]+)*\.(home\.arpa|lan|home|local|internal|localdomain)'
    if [ -n "$personal_terms_file" ] && [ -s "$personal_terms_file" ]; then
        scan_personal term -F -f "$personal_terms_file"
    fi
} | sort -u >"$work/personal-hits.tsv"

attach_locations "$work/personal-hits.tsv" |
    awk -F'\t' '{ print "personal " $2 " " $3 " " $4 " " $5 }' | sort >"$work/personal.txt"

# --- report, summary, verdict -------------------------------------------------

count_lines() {
    wc -l <"$1" | tr -d ' '
}

local_ref_count=$(count_lines "$work/local-refs.tsv")
remote_ref_count=$(count_lines "$work/remote-refs.tsv")
unexplained_count=$(count_lines "$work/name-unexplained.txt")
explained_count=$(cut -d' ' -f3 "$work/name-explained.txt" | sort -u | wc -l | tr -d ' ')
secret_count=$(count_lines "$work/secrets.txt")
missing_count=$(count_lines "$work/missing-remote.txt")
review_count=$(count_lines "$work/path-review.txt")
identity_count=$(count_lines "$work/identities.txt")

personal_count() {
    grep -c -E "^personal $1 " "$work/personal.txt" || true
}

{
    echo "# History audit report"
    echo
    echo "repository $repo_root"
    echo "commits $commit_count"
    echo "file versions $blob_count ($gzip_count decompressed)"
    echo "local refs $local_ref_count, remote refs advertised $remote_ref_count"
    echo
    echo "## Refs"
    awk -F'\t' '{ print "ref " $1 " " $2 }' "$work/local-refs.tsv"
    awk -F'\t' '{ print "remote-ref " $2 " " $1 }' "$work/remote-refs.tsv"
    echo
    echo "## Remote objects missing locally (fetch first)"
    cat "$work/missing-remote.txt"
    echo
    echo "## Query names"
    cat "$work/name-unexplained.txt" "$work/name-explained.txt"
    echo
    echo "## Paths to review"
    cat "$work/path-review.txt"
    echo
    echo "## Secrets"
    cat "$work/secrets.txt"
    echo
    echo "## Identities"
    cat "$work/identities.txt"
    echo
    echo "## Personal identifiers"
    cat "$work/personal.txt"
} >"$report_file"

verdict=PASS
if [ "$unexplained_count" -gt 0 ] || [ "$secret_count" -gt 0 ] || [ "$missing_count" -gt 0 ]; then
    verdict=FAIL
fi

{
    echo "# History audit summary"
    echo
    echo "commits: $commit_count"
    echo "refs: $local_ref_count in this clone, $remote_ref_count advertised by the remote"
    echo "file versions scanned: $blob_count"
    echo "query names: $unexplained_count unexplained findings, $explained_count explained names"
    echo "secrets: $secret_count findings"
    echo "remote objects not in this clone: $missing_count"
    echo "paths to review: $review_count"
    echo "identities: $identity_count"
    echo "personal: $(personal_count home-path) home paths, $(personal_count private-address) private addresses," \
        "$(personal_count local-host) home-network host names, $(personal_count term) personal terms"
    echo "verdict: $verdict"
} >"$summary_file"

cat "$summary_file"

if [ "$verdict" = FAIL ]; then
    exit 1
fi
