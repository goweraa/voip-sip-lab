#!/usr/bin/env bash
# VoIP/SIP troubleshooting lab: an Asterisk PBX, two pjsua softphones and a
# SIPp test generator on an isolated podman network. Each scenario runs a
# call (healthy or deliberately broken), captures every packet the PBX sees
# into captures/<scenario>.pcap and prints a triage summary.
set -euo pipefail

LAB="$(cd "$(dirname "$0")" && pwd)"
NET=siplab
PBX=10.50.0.10 ALICE=10.50.0.21 BOB=10.50.0.22 SIPP=10.50.0.30
PJ_COMMON="--null-audio --no-vad --no-tcp --realm=* --app-log-level=3 --log-level=3"
ALICE_ACC="--id=sip:1001@$PBX --registrar=sip:$PBX --username=1001"
BOB_ACC="--id=sip:1002@$PBX --registrar=sip:$PBX --username=1002 --password=bob-lab-pw"

SCENARIOS=(healthy-call auth-failure not-found unavailable busy codec-mismatch
           one-way-audio dead-trunk packet-loss-jitter)

describe() {
  case $1 in
    healthy-call)       echo "Alice calls Bob, 10 s of two-way G.711 audio. Your baseline." ;;
    auth-failure)       echo "Alice registers with the wrong password: 401 challenge, rejected again." ;;
    not-found)          echo "Alice dials 9999, which has no dialplan match: 404 Not Found." ;;
    unavailable)        echo "Bob's phone is offline (not registered) when Alice calls: 480." ;;
    busy)               echo "Bob's phone rejects the call as busy: 486 Busy Here." ;;
    codec-mismatch)     echo "SIPp offers only G.722 to a PBX that allows only G.711 u-law: 488." ;;
    one-way-audio)      echo "Alice advertises an unreachable private IP in her SDP (classic NAT bug)." ;;
    dead-trunk)         echo "Alice dials an outside number; the carrier trunk is down." ;;
    packet-loss-jitter) echo "Alice's network adds 5% loss and 40+/-30 ms delay. Watch RTCP and jitter." ;;
  esac
}

pbx_up() { podman container exists asterisk && [ "$(podman inspect -f '{{.State.Running}}' asterisk)" = true ]; }

up() {
  podman image exists siplab || podman build -q -t siplab "$LAB" >/dev/null
  podman network exists $NET || podman network create --subnet 10.50.0.0/24 $NET >/dev/null
  if ! pbx_up; then
    podman rm -f asterisk >/dev/null 2>&1 || true
    podman run -d --name asterisk --network $NET --ip $PBX \
      -v "$LAB/asterisk:/etc/asterisk-lab:ro,Z" siplab \
      sh -c 'cp /etc/asterisk-lab/*.conf /etc/asterisk/ && exec asterisk -f -U root' >/dev/null
    for _ in $(seq 1 30); do
      podman exec asterisk asterisk -rx "core show uptime" >/dev/null 2>&1 && break; sleep 1
    done
  fi
  # Hosts that are up but run no SIP/RTP service: the NAT router Alice's
  # broken SDP points at, and the carrier SBC whose SIP service has crashed.
  # They answer with ICMP port unreachable, as real dead services do.
  for h in nat-router:10.50.0.250 carrier-sbc:10.50.0.99; do
    podman container exists "${h%%:*}" || podman run -d --name "${h%%:*}" --network $NET \
      --ip "${h#*:}" siplab sleep infinity >/dev/null
  done
  bob_start
  echo "Lab up: PBX $PBX, Alice (1001) $ALICE, Bob (1002) $BOB, SIPp $SIPP"
}

down() {
  podman rm -f -t0 bob cap asterisk nat-router carrier-sbc >/dev/null 2>&1 || true
  podman network rm $NET >/dev/null 2>&1 || true
  echo "Lab stopped."
}

# Bob's phone. Extra pjsua flags change its behaviour (e.g. auto-answer 486).
bob_start() {
  podman rm -f bob >/dev/null 2>&1 || true
  podman run -d --name bob --network $NET --ip $BOB -v "$LAB/media:/media:ro,Z" siplab \
    sh -c "sleep infinity | pjsua $PJ_COMMON $BOB_ACC --auto-answer=${1:-200} \
           --play-file=/media/tones.wav --auto-play" >/dev/null
  sleep 2
}
bob_stop() {
  # Killing the phone leaves its registration behind, so register once more
  # and quit: pjsua unregisters (Expires: 0) on exit and the PBX drops Bob.
  podman rm -f bob >/dev/null 2>&1 || true
  timeout 20 podman run --rm --network $NET --ip $BOB siplab \
    sh -c "(sleep 3; echo q) | pjsua $PJ_COMMON $BOB_ACC" >/dev/null 2>&1 || true
}

# Alice places one call (or just registers when no target is given).
#   alice <seconds-to-run> <extra pjsua flags...> [-- target]
alice() {
  local secs=$1; shift
  local pre="" args=() target=""
  while [ $# -gt 0 ]; do
    case $1 in
      --netem=*) pre="tc qdisc add dev eth0 root netem ${1#--netem=} && " ;;
      --) target=$2; shift ;;
      *) args+=("$1") ;;
    esac
    shift
  done
  timeout $((secs + 15)) podman run --rm --cap-add NET_ADMIN --network $NET --ip $ALICE siplab \
    sh -c "${pre}(sleep $secs; echo q) | pjsua $PJ_COMMON $ALICE_ACC ${args[*]} $target" 2>&1 |
    grep -v ALSA | grep -E "state changed|registration|status=|Call [0-9]+ is DISCONNECTED" || true
}

capture_start() {
  podman rm -f cap >/dev/null 2>&1 || true
  podman run -d --name cap --cap-add NET_RAW,NET_ADMIN --network container:asterisk \
    -v "$LAB/captures:/captures:Z" siplab tcpdump -i eth0 -s0 -U -w "/captures/$1.pcap" >/dev/null
  sleep 1
}
capture_stop() { sleep 1; podman stop -t2 cap >/dev/null; podman rm cap >/dev/null; }

scenario() {
  local call="sip:%s@$PBX"
  case $1 in
    healthy-call)
      alice 14 --password=alice-lab-pw --duration=10 -- "$(printf $call 1002)" ;;
    auth-failure)
      alice 6 --password=WRONG-password ;;
    not-found)
      alice 6 --password=alice-lab-pw -- "$(printf $call 9999)" ;;
    unavailable)
      bob_stop
      alice 6 --password=alice-lab-pw -- "$(printf $call 1002)"
      bob_start ;;
    busy)
      bob_start 486
      alice 6 --password=alice-lab-pw -- "$(printf $call 1002)"
      bob_start ;;
    codec-mismatch)
      podman run --rm --network $NET --ip $SIPP -v "$LAB/sipp:/sipp:ro,Z" siplab \
        sipp $PBX -sf /sipp/codec-mismatch.xml -m 1 -nostdin -timeout 10s 2>&1 |
        grep -E "Successful call|Failed call" | head -2 ;;
    one-way-audio)
      # 10.50.0.250 stands in for the phone's LAN address behind a NAT router:
      # the PBX sends its RTP there and nothing ever arrives at Alice.
      alice 14 --password=alice-lab-pw --ip-addr=10.50.0.250 --bound-addr=0.0.0.0 \
        --duration=10 -- "$(printf $call 1002)" ;;
    dead-trunk)
      alice 16 --password=alice-lab-pw -- "$(printf $call 8000)"
      # The PBX keeps retransmitting the INVITE to the carrier until SIP
      # timer B (32 s) expires; keep capturing so the whole pattern is visible.
      echo "(capturing until the PBX gives up on the carrier: ~20 s)"; sleep 20 ;;
    packet-loss-jitter)
      alice 19 --password=alice-lab-pw --netem="delay 40ms 30ms loss 5%" --duration=15 \
        -- "$(printf $call 1002)" ;;
    *) echo "Unknown scenario: $1 (try: $0 list)" >&2; exit 1 ;;
  esac
}

run() {
  pbx_up || up
  local s=$1
  echo "=== $s: $(describe "$s")"
  capture_start "$s"
  scenario "$s"
  capture_stop
  echo "--- capture: captures/$s.pcap"
  python3 "$LAB/tools/sip_triage.py" "$LAB/captures/$s.pcap"
  echo
}

case ${1:-help} in
  up) up ;;
  down) down ;;
  list) for s in "${SCENARIOS[@]}"; do printf '  %-20s %s\n' "$s" "$(describe "$s")"; done ;;
  run)
    [ $# -ge 2 ] || { echo "usage: $0 run <scenario>|all" >&2; exit 1; }
    if [ "$2" = all ]; then for s in "${SCENARIOS[@]}"; do run "$s"; done; else run "$2"; fi ;;
  pbx) shift; podman exec asterisk asterisk -rx "$*" ;;
  *) cat <<EOF
usage: $0 up | down | list | run <scenario>|all | pbx "<asterisk CLI command>"
  e.g. $0 run one-way-audio
       $0 pbx "pjsip show contacts"
EOF
  ;;
esac
