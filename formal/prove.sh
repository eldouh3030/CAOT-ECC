#!/bin/sh
export LANG=C.UTF-8 LC_ALL=C.UTF-8
: > caot3-hidden-proof.txt
for l in dev_state_origin chain_key_origin chain_key_index srv_state_origin frames_executable critical_executable reading_secrecy critical_signature_hidden window_signature_hidden critical_non_repudiation window_non_repudiation reading_authentication; do
  r=$(timeout 1200 tamarin-prover --prove=$l caot3-hidden.spthy 2>/dev/null | grep -E "^  $l |processing time" | tr '\n' ' ')
  echo "$l => ${r:-TIMEOUT}" | tee -a caot3-hidden-proof.txt
done
