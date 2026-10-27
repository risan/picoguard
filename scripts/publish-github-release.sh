#!/usr/bin/env bash
# Usage: publish-github-release.sh <tag> <tag-object> <prerelease: true|false> <release-dir>
#
# Needs gh, GH_TOKEN and GITHUB_REPOSITORY. Creates the release as a draft,
# uploads the seven assets, checks that all of them arrived and only then
# publishes it, so releases/latest never shows a partial release. A leftover
# draft from a failed run is replaced; a published release is never touched.
# The notes come from the tag object this run was started for, and the tag must
# still point at it when the draft is created and again when it is published.
set -euo pipefail

if [ "$#" -ne 4 ] || { [ "$3" != true ] && [ "$3" != false ]; }; then
    echo "usage: $0 <tag> <tag-object> <true|false> <release-dir>" >&2
    exit 2
fi

tag=$1
tag_object=$2
prerelease=$3
release_dir=$4

repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
asset_names=(
    picoguard-x86_64-unknown-linux-musl
    picoguard-aarch64-unknown-linux-musl
    picoguard-armv7-unknown-linux-musleabihf
    install.sh
    proxmox-lxc.sh
    SHA256SUMS
    SHA256SUMS.sig
)

die() {
    echo "error: $*" >&2
    exit 1
}

assets=()
for name in "${asset_names[@]}"; do
    [ -f "$release_dir/$name" ] || die "$release_dir/$name is missing"
    assets+=("$release_dir/$name")
done

if [ "$(find "$release_dir" -mindepth 1 | wc -l)" -ne "${#asset_names[@]}" ]; then
    die "$release_dir holds something besides the ${#asset_names[@]} release assets"
fi

# The list includes drafts; releases/tags/<tag> does not.
export TAG=$tag
states=$(gh api --paginate "repos/$repo/releases" --jq '.[] | select(.tag_name == env.TAG) | .draft') ||
    die "could not list the releases of $repo"

for state in $states; do
    if [ "$state" = false ]; then
        die "release $tag is already published, not changing it"
    fi
done

for _ in $states; do
    gh release delete "$tag" --yes
done

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

# --notes-from-tag reads the tag from the local checkout, which may not hold
# this tag object.
gh api "repos/$repo/git/tags/$tag_object" --jq .message >"$work_dir/notes.md" ||
    die "could not read tag object $tag_object"
[ -s "$work_dir/notes.md" ] || die "tag object $tag_object has no message"

check_tag_unmoved() {
    local current

    current=$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.sha) ||
        die "could not read the tag $tag"
    if [ "$current" != "$tag_object" ]; then
        die "tag $tag now points to $current, not to $tag_object it was started for"
    fi
}

create_flags=(--draft --verify-tag --title "picoguard $tag" --notes-file "$work_dir/notes.md")
publish_flags=(--draft=false)
if [ "$prerelease" = true ]; then
    create_flags+=(--prerelease)
else
    publish_flags+=(--latest)
fi

check_tag_unmoved
gh release create "$tag" "${create_flags[@]}" "${assets[@]}"

uploaded=$(gh release view "$tag" --json assets --jq '.assets | length')
if [ "$uploaded" -ne "${#asset_names[@]}" ]; then
    die "release $tag has $uploaded assets instead of ${#asset_names[@]}; it stays a draft"
fi

check_tag_unmoved
gh release edit "$tag" "${publish_flags[@]}"
