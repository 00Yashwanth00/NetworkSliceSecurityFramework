// tc_id -> operator-facing title, copied verbatim from each attack test
// case's own TestSpec (tester/src/testcases/attacks/*.py) so this stays
// the same wording the tester itself considers authoritative. There's no
// live API to fetch this from (the tester is a CLI tool, not a service),
// and the catalog is small and effectively static, so hardcoding it here
// is the right call rather than building new integration just for display.
//
// If a new attack test case is added to the tester, add its tc_id + title
// here too -- copy the `title=` string from that file's `TestSpec(...)`
// exactly, don't paraphrase it.

export const TEST_CATALOG = {
  'TC-SEC-109': "Cross-slice isolation + DoS: attacker UE's two slices exhaust a shared UPF/DNN pool and deny the victim UE",
  'TC-SEC-015': 'Mixed-authenticity concurrent slice attach: 64 valid + 64 unauthenticated UEs on SST=1',
  'TC-SEC-117': 'Cross-slice PDU session ID hijacking: attacker reuses high-trust session ID on low-trust slice to hijack user-plane path',
  'TC-SEC-118': 'NRF slice-NF deregistration abuse: attacker knocks victim SMF out of discovery to disable slice',
  'TC-SEC-151': 'Pending / Rejected-NSSAI signaling storm: slice-state table exhaustion via NSSAA churn',
  'TC-SEC-113': 'NSSF slice spoofing: attacker registers on default slice, injects new spoofed slice into NSSF, and redirects victim',
  'TC-SEC-106': 'Roaming/SEPP desync: N32 access persists after agreement revocation until the framework blocks the peer',
  'TC-SEC-105': "Admission-source poisoning: unauthorised S-NSSAI written into the AMF's plmn_nssai support set without ownership check",
  'TC-SEC-119': 'RAN RRMPolicyRatio manipulation: attacker starves victim slice PRB allocation at gNB',
  'TC-SEC-120': 'Malicious xApp / near-RT RIC slice-policy conflict: two xApps race over victim slice SLA -- rogue wins via last-write',
};

// TC-SEC-105 and TC-SEC-106 are admin-API-only attacks (see VERIFY.md /
// FINAL_VERIFICATION.md) -- they never produce telemetry, so this banner
// may show them as "running" while the Verdicts/Mitigation panels stay
// quiet. That's expected, not a bug: it's proof those two attacks are
// invisible to the ML pipeline by design, not that detection failed.
export const TELEMETRY_INVISIBLE = new Set(['TC-SEC-105', 'TC-SEC-106']);

export function testTitle(tcId) {
  return TEST_CATALOG[tcId] || null;
}
