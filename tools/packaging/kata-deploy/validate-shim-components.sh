#!/bin/sh
#
# Copyright (c) 2026 Kata Contributors
#
# SPDX-License-Identifier: Apache-2.0
#

set -eu

manifest="${1:?usage: $0 MANIFEST TARBALLS_DIR [ARCH]}"
tarballs_dir="${2:?usage: $0 MANIFEST TARBALLS_DIR [ARCH]}"
arch="${3:-$(uname -m)}"

case "${arch}" in
	amd64) arch="x86_64" ;;
	arm64) arch="aarch64" ;;
	powerpc64le) arch="ppc64le" ;;
esac

if ! jq -e --arg arch "${arch}" '
	(.shims | type == "object") and
	([.shims | to_entries[] | select(.value[$arch] != null)] | length > 0) and
	(
		.requiredComponents == null or
		(
			(.requiredComponents | type == "object") and
			(
				.requiredComponents[$arch] == null or
				(
					(.requiredComponents[$arch] | type == "array") and
					all(
						.requiredComponents[$arch][];
						type == "string" and
						test("^[a-z0-9][a-z0-9.-]*$")
					)
				)
			)
		)
	) and
	all(
		.shims | to_entries[];
		(.value | type == "object") and
		(
			.value[$arch] == null or
			(
				(.value[$arch] | type == "array") and
				(.value[$arch] | length > 0) and
				all(
					.value[$arch][];
					type == "string" and
					test("^[a-z0-9][a-z0-9.-]*$")
				)
			)
		)
	)
' "${manifest}" >/dev/null; then
	echo "ERROR: ${manifest} has invalid or no component metadata for architecture ${arch}" >&2
	exit 1
fi

components_file="$(mktemp)"
trap 'rm -f "${components_file}"' EXIT

jq -r --arg arch "${arch}" \
	'(
		.requiredComponents[$arch]? // empty | .[]
	), (
		.shims | to_entries[] | .value[$arch]? // empty | .[]
	)' \
	"${manifest}" | sort -u > "${components_file}"

missing=0
while IFS= read -r component; do
	tarball="${tarballs_dir}/kata-static-${component}.tar.zst"
	if [ ! -f "${tarball}" ]; then
		echo "ERROR: shim-components.json references missing ${tarball}" >&2
		missing=1
	fi
done < "${components_file}"

invalid=0
for tarball in "${tarballs_dir}"/kata-static-*.tar.zst "${tarballs_dir}"/kata-deploy-static-*.tar.zst; do
	[ -f "${tarball}" ] || continue
	if ! zstd -t -- "${tarball}" >/dev/null 2>&1; then
		echo "ERROR: corrupt zstd archive ${tarball}" >&2
		invalid=1
		continue
	fi
	if ! zstd -dc -- "${tarball}" | tar -tf - >/dev/null 2>&1; then
		echo "ERROR: invalid tar archive ${tarball}" >&2
		invalid=1
	fi
done

if [ "${missing}" -ne 0 ] || [ "${invalid}" -ne 0 ]; then
	exit 1
fi
