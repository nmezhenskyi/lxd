#!/bin/bash
set -eu

hash_before="lxd/metadata-before.txt"
hash_after="lxd/metadata-after.txt"
json_metadata="lxd/metadata/configuration.json"
doc_config_options="doc/metadata.txt"

metadata_hash() {
  files_to_check="${json_metadata} ${doc_config_options}"
  for f in $files_to_check; do
    if [ -f "$f" ]; then
      md5sum "$f"
    fi
  done | sort -k 2 > "$1"
}

echo "Checking that the metadata is up to date..."

# make sure the YAML metadata file and the documentation config option file are up to date
metadata_hash "$hash_before"
make update-metadata --silent 2>&1 | grep -vF ' Found lxddoc at '
metadata_hash "$hash_after"
git restore -- "${json_metadata}" "${doc_config_options}"

d="$(diff -Nau "$hash_before" "$hash_after" || true)"
rm "$hash_before" "$hash_after"

if [ -z "$d" ]; then
    echo "==> metadata is up to date"
else
    echo "==> Please update the metadata in your commit (make update-metadata)"
    echo "==> Differences detected:"
    echo "$d"
    exit 1
fi
