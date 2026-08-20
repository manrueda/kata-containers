#!/usr/bin/env bats
#
# Copyright (c) 2026 Kata Containers Contributors
#
# SPDX-License-Identifier: Apache-2.0
#

CHART_PATH="${BATS_TEST_DIRNAME}/../../../tools/packaging/kata-deploy/helm-chart/kata-deploy"

@test "kata-monitor mounts both sandbox paths and probes readiness" {
	local rendered
	rendered="$(helm template kata-deploy "${CHART_PATH}" \
		--set monitor.enabled=true \
		--show-only templates/kata-monitor.yaml)"

	[[ "${rendered}" == *$'- name: sbs\n          mountPath: /run/vc/sbs/\n          readOnly: true'* ]]
	[[ "${rendered}" == *$'- name: runtime-rs\n          mountPath: /run/kata\n          readOnly: true'* ]]
	[[ "${rendered}" == *$'- name: sbs\n        hostPath:\n          path: /run/vc/sbs/\n          type: DirectoryOrCreate'* ]]
	[[ "${rendered}" == *$'- name: runtime-rs\n        hostPath:\n          path: /run/kata\n          type: DirectoryOrCreate'* ]]
	[[ "${rendered}" == *$'readinessProbe:\n          httpGet:\n            path: /readyz\n            port: 8090'* ]]
}
