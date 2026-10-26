#!/usr/bin/env bash
# Tests for scripts/audit-history.sh. Run by hand: it needs gitleaks, jq and git
# on PATH, which CI does not have.
set -euo pipefail

cd "$(dirname "$0")/.."
audit=$PWD/scripts/audit-history.sh

for tool in git gitleaks jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is needed on PATH" >&2
        exit 2
    fi
done

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

case_name=
report=$scratch/report.md
summary=$scratch/summary.md

fail() {
    echo "FAIL $case_name: $*" >&2
    exit 1
}

run_case() {
    case_name=$1
    "$1"
    echo "ok $1"
}

# The strings below are built from pieces so that this file never holds a
# complete credential: the audit of this repository must not flag its own test.
fake_github_token() {
    printf 'ghp_%s' "$(printf 'aB3xY9%.0s' 1 2 3 4 5 6)"
}

fake_stripe_key() {
    printf 'sk_%s_%s' live 4eC39HqLyjWDarjtT1zdp7dcXk
}

new_repo() {
    local dir=$scratch/$1

    rm -rf "$dir"
    git init -q -b main "$dir"
    git -C "$dir" config user.name "Test Author"
    git -C "$dir" config user.email "test@example.org"
    echo "$dir"
}

# commit_file <repo> <path> <content>: prints the new commit id.
commit_file() {
    mkdir -p "$(dirname "$1/$2")"
    printf '%s\n' "$3" >"$1/$2"
    git -C "$1" add "$2"
    git -C "$1" commit -q -m "add $2"
    git -C "$1" rev-parse HEAD
}

# run_audit <repo> [extra options]: sets $status, keeps the output.
run_audit() {
    local repo=$1
    shift

    status=0
    "$audit" --repo "$repo" --names "$scratch/names.txt" --report "$report" --summary "$summary" \
        "$@" >"$scratch/audit.out" 2>&1 || status=$?
}

expect_status() {
    if [ "$status" -ne "$1" ]; then
        cat "$scratch/audit.out" >&2
        fail "expected exit $1, got $status"
    fi
}

# expect_line <pattern> <word>...: one report line matching the pattern holds every word.
expect_line() {
    local pattern=$1 word
    shift

    grep -E -- "$pattern" "$report" >"$scratch/lines" || fail "no report line matches $pattern"
    for word in "$@"; do
        if ! grep -q -F -- "$word" "$scratch/lines"; then
            cat "$scratch/lines" >&2
            fail "no line matching $pattern holds: $word"
        fi
    done
}

write_names() {
    printf 'secret-host.home.arpa A\nGitHub.com. AAAA\n' >"$scratch/names.txt"
}

# main_scenario: commit 1 holds a public list, commit 2 holds a
# private name and a token, commit 3 holds a public name.
main_scenario() {
    local repo

    write_names
    repo=$(new_repo main)
    commit_file "$repo" lists/public.txt '0.0.0.0 github.com' >/dev/null
    c2=$(commit_file "$repo" notes.txt "see secret-host.home.arpa, token $(fake_github_token)")
    c3=$(commit_file "$repo" docs/links.txt 'https://github.com/example')
    main_repo=$repo
}

audit_reports_a_private_name() {
    main_scenario
    run_audit "$main_repo" --public-lists 'lists/*.txt'

    expect_status 1
    expect_line '^query-name unexplained secret-host\.home\.arpa ' "$c2" notes.txt
}

audit_marks_public_names_explained() {
    main_scenario
    run_audit "$main_repo" --public-lists 'lists/*.txt'

    expect_line '^query-name explained github\.com '
    ! grep -q -E '^query-name unexplained github\.com' "$report" || fail "github.com is public"
}

audit_reports_a_secret_without_its_value() {
    main_scenario
    run_audit "$main_repo" --public-lists 'lists/*.txt'

    expect_line '^secret github-token ' "$c2" notes.txt
    ! grep -q -F "$(fake_github_token)" "$report" || fail "the token value is in the report"
    ! grep -q -F "$(fake_github_token)" "$scratch/audit.out" || fail "the token value is in the output"
}

audit_summary_has_no_names() {
    main_scenario
    run_audit "$main_repo" --public-lists 'lists/*.txt'

    [ -s "$summary" ] || fail "no summary"
    ! grep -q -i -F -e secret-host.home.arpa -e github.com "$summary" || fail "a name is in the summary"
    ! grep -q -F "$(fake_github_token)" "$summary" || fail "the token is in the summary"
}

audit_covers_refs_and_commits() {
    main_scenario
    run_audit "$main_repo" --public-lists 'lists/*.txt'

    expect_line '^commits 3$'
    expect_line '^ref refs/heads/main ' "$c3"
}

audit_clean_repo_exits_0() {
    local repo

    write_names
    repo=$(new_repo clean)
    commit_file "$repo" README.txt 'nothing to see' >/dev/null
    run_audit "$repo"

    expect_status 0
}

audit_refuses_a_report_inside_the_repo() {
    local repo

    write_names
    repo=$(new_repo inside)
    commit_file "$repo" README.txt 'nothing to see' >/dev/null

    status=0
    "$audit" --repo "$repo" --names "$scratch/names.txt" --report "$repo/report.md" \
        --summary "$summary" >"$scratch/audit.out" 2>&1 || status=$?

    expect_status 2
    [ ! -e "$repo/report.md" ] || fail "the report was written into the repository"
}

audit_scans_a_commit_only_a_remote_branch_has() {
    local remote repo commit

    write_names
    remote=$(new_repo remote_a)
    commit_file "$remote" README.txt 'base' >/dev/null
    git -C "$remote" switch -q -c feature
    commit=$(commit_file "$remote" feature.txt 'uses secret-host.home.arpa')
    git -C "$remote" switch -q main

    repo=$scratch/local_a
    git clone -q "$remote" "$repo"
    git -C "$repo" fetch -q origin feature

    [ -z "$(git -C "$repo" branch --list feature)" ] || fail "the scratch repo has a local feature branch"
    run_audit "$repo"

    expect_status 1
    expect_line '^query-name unexplained secret-host\.home\.arpa ' "$commit" feature.txt
}

audit_fails_on_a_remote_object_it_does_not_have() {
    local remote repo

    write_names
    remote=$(new_repo remote_b)
    commit_file "$remote" README.txt 'base' >/dev/null
    repo=$scratch/local_b
    git clone -q "$remote" "$repo"

    git -C "$remote" switch -q -c later
    commit_file "$remote" later.txt 'not fetched yet' >/dev/null
    run_audit "$repo"

    expect_status 1
    expect_line '^missing-remote refs/heads/later '
}

audit_reports_a_blob_under_every_path() {
    local repo first second

    write_names
    repo=$(new_repo renamed)
    first=$(commit_file "$repo" a.txt 'resolves secret-host.home.arpa')
    second=$(commit_file "$repo" logs/querylog.json 'resolves secret-host.home.arpa')
    run_audit "$repo"

    expect_line '^query-name unexplained secret-host\.home\.arpa ' "$first" a.txt
    expect_line '^query-name unexplained secret-host\.home\.arpa .*logs/querylog\.json' "$second"
    expect_line '^path-review ' "$second" logs/querylog.json
}

audit_lists_personal_findings() {
    local repo commit

    write_names
    printf 'dns0\n' >"$scratch/terms.txt"
    repo=$(new_repo personal)
    commit=$(commit_file "$repo" infra.txt 'proxmox at hv0.lan runs dns0')
    run_audit "$repo" --personal-terms "$scratch/terms.txt"

    expect_line '^personal local-host hv0\.lan ' "$commit" infra.txt
    expect_line '^personal term dns0 ' "$commit" infra.txt
}

audit_lists_identities() {
    local repo first last

    write_names
    repo=$(new_repo identities)
    first=$(commit_file "$repo" a.txt one)
    commit_file "$repo" b.txt two >/dev/null
    last=$(commit_file "$repo" c.txt three)
    run_audit "$repo"

    expect_line '^identity author Test Author <test@example\.org> commits 3 ' "first $first" "last $last"
    expect_line '^identity committer Test Author <test@example\.org> commits 3 '
}

# A commit with no ref of its own is still audited when the remote advertises
# it, and gitleaks finds a credential the grep patterns do not know.
audit_scans_a_commit_the_remote_advertises() {
    local remote repo commit

    write_names
    remote=$(new_repo remote_c)
    commit_file "$remote" README.txt 'base' >/dev/null
    git -C "$remote" switch -q -c hidden
    commit=$(commit_file "$remote" payments.txt "key = \"$(fake_stripe_key)\"")
    git -C "$remote" switch -q main

    repo=$scratch/local_c
    git clone -q "$remote" "$repo"
    git -C "$repo" fetch -q origin hidden:refs/tmp/hidden
    git -C "$repo" update-ref -d refs/tmp/hidden
    git -C "$repo" update-ref -d refs/remotes/origin/hidden
    [ -n "$(git -C "$repo" cat-file -t "$commit")" ] || fail "the commit is not in the scratch repo"
    [ -z "$(git -C "$repo" for-each-ref --contains "$commit")" ] || fail "a ref still reaches the commit"
    run_audit "$repo"

    expect_status 1
    expect_line '^secret stripe-access-token ' "$commit" payments.txt
}

audit_scans_a_credential_only_a_merge_holds() {
    local repo merge

    write_names
    repo=$(new_repo merged)
    commit_file "$repo" f.txt base >/dev/null
    git -C "$repo" switch -q -c side
    commit_file "$repo" f.txt side >/dev/null
    git -C "$repo" switch -q main
    commit_file "$repo" f.txt main >/dev/null
    git -C "$repo" merge -q side >/dev/null 2>&1 || true
    printf 'key = "%s"\n' "$(fake_stripe_key)" >"$repo/f.txt"
    git -C "$repo" add f.txt
    git -C "$repo" commit -q --no-edit
    merge=$(git -C "$repo" rev-parse HEAD)
    run_audit "$repo"

    expect_status 1
    expect_line '^secret stripe-access-token ' "$merge" f.txt
}

# A list that only the working tree has, or an edit nobody committed, must not
# explain a name: the audit reads the lists from HEAD.
audit_explains_names_only_from_committed_lists() {
    local repo

    write_names
    repo=$(new_repo uncommitted-list)
    commit_file "$repo" lists/other.txt '0.0.0.0 example.org' >/dev/null
    commit_file "$repo" docs/links.txt 'https://github.com/example' >/dev/null
    printf '0.0.0.0 github.com\n' >"$repo/lists/untracked.txt"
    printf '0.0.0.0 github.com\n' >>"$repo/lists/other.txt"
    run_audit "$repo" --public-lists 'lists/*.txt'

    expect_status 1
    expect_line '^query-name unexplained github\.com ' docs/links.txt
}

audit_lists_every_place_of_an_explained_name() {
    local repo first second

    write_names
    repo=$(new_repo explained-places)
    commit_file "$repo" lists/public.txt '0.0.0.0 github.com' >/dev/null
    first=$(commit_file "$repo" a.txt 'see github.com')
    second=$(commit_file "$repo" b.txt 'see github.com again')
    run_audit "$repo" --public-lists 'lists/*.txt'

    expect_line '^query-name explained github\.com .* a\.txt$' "$first"
    expect_line '^query-name explained github\.com .* b\.txt$' "$second"
}

# A name without a dot is found when it stands alone, but not inside another
# name, and a --known-public entry explains it like any other.
audit_finds_a_name_without_a_dot() {
    local repo alone inside

    printf 'singlelabel A\n' >"$scratch/names.txt"
    repo=$(new_repo single-label)
    alone=$(commit_file "$repo" a.txt 'host singlelabel is up')
    inside=$(commit_file "$repo" b.txt 'singlelabel.example and my-singlelabel only')
    run_audit "$repo"

    expect_status 1
    expect_line '^query-name unexplained singlelabel ' "$alone" a.txt
    ! grep -E '^query-name ' "$report" | grep -q -F "$inside" || fail "a longer name counted as the single name"
    ! grep -q -F singlelabel "$summary" || fail "the summary holds a name"

    printf 'singlelabel\n' >"$scratch/known.txt"
    run_audit "$repo" --known-public "$scratch/known.txt"

    expect_status 0
    expect_line '^query-name explained singlelabel ' "$alone" a.txt
}

# A list path is no exemption: a personal term, a home path, a private address
# and a host name inside one are all reported.
audit_scans_public_lists_for_personal_findings() {
    local repo commit

    write_names
    printf 'dns0\n' >"$scratch/terms.txt"
    repo=$(new_repo personal-in-list)
    commit=$(commit_file "$repo" lists/public.txt $'0.0.0.0 hv0.lan\ndns0 /home/alice 192.168.1.5')
    run_audit "$repo" --public-lists 'lists/*.txt' --personal-terms "$scratch/terms.txt"

    expect_line '^personal term dns0 ' "$commit" lists/public.txt
    expect_line '^personal home-path /home/alice ' "$commit" lists/public.txt
    expect_line '^personal private-address 192\.168\.1\.5 ' "$commit" lists/public.txt
    expect_line '^personal local-host hv0\.lan ' "$commit" lists/public.txt
}

run_case audit_reports_a_private_name
run_case audit_marks_public_names_explained
run_case audit_reports_a_secret_without_its_value
run_case audit_summary_has_no_names
run_case audit_covers_refs_and_commits
run_case audit_clean_repo_exits_0
run_case audit_refuses_a_report_inside_the_repo
run_case audit_scans_a_commit_only_a_remote_branch_has
run_case audit_fails_on_a_remote_object_it_does_not_have
run_case audit_reports_a_blob_under_every_path
run_case audit_lists_personal_findings
run_case audit_lists_identities
run_case audit_scans_a_commit_the_remote_advertises
run_case audit_scans_a_credential_only_a_merge_holds
run_case audit_explains_names_only_from_committed_lists
run_case audit_lists_every_place_of_an_explained_name
run_case audit_finds_a_name_without_a_dot
run_case audit_scans_public_lists_for_personal_findings
