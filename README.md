# VoIP/SIP troubleshooting lab

A self-contained SIP lab for practising the work a UC escalation engineer
does every day: reproduce a voice fault, capture it, read the SIP call flow
and RTP/RTCP media, and write up the root cause with evidence.

Everything runs in rootless podman containers on an isolated network:

| Host | IP | Role |
|---|---|---|
| `asterisk` | 10.50.0.10 | PBX (Asterisk 20, PJSIP). Anchors all media, G.711 u-law only |
| `alice` | 10.50.0.21 | Softphone, extension 1001 (pjsua), started per scenario |
| `bob` | 10.50.0.22 | Softphone, extension 1002 (pjsua), auto-answers and plays tones |
| SIPp | 10.50.0.30 | SIP test generator, trusted by IP (no auth) |
| `carrier-sbc` | 10.50.0.99 | "Carrier" whose SIP service is down |
| `nat-router` | 10.50.0.250 | Address a misconfigured phone advertises in its SDP |

Dial plan: `1001`/`1002` = phones, `600` = echo test, `8XXX` = outside
numbers over the (dead) carrier trunk, anything else = no route.

## Quick start

```bash
./lab.sh up                    # build image, start PBX + Bob
./lab.sh list                  # scenarios
./lab.sh run healthy-call      # one scenario -> captures/healthy-call.pcap
./lab.sh run all               # every scenario
./lab.sh pbx "pjsip show contacts"   # any Asterisk CLI command
./lab.sh down                  # remove everything
```

Each run prints a first-pass triage from `tools/sip_triage.py`; open the
pcap in Wireshark for the real analysis.

## Scenarios

| Scenario | What breaks | Final SIP response |
|---|---|---|
| `healthy-call` | Nothing: the baseline to compare everything else against | 200 |
| `auth-failure` | Wrong password on REGISTER | 401, 401 (never 200) |
| `not-found` | Dialled number has no route | 404 |
| `unavailable` | Callee's phone is not registered | 480 |
| `busy` | Callee rejects as busy | 486 |
| `codec-mismatch` | Caller offers only G.722; PBX allows only G.711 | 488 |
| `one-way-audio` | Phone advertises an unreachable address in SDP `c=` | 200, but media only flows one way |
| `dead-trunk` | Carrier SBC is up but its SIP service is down | 503 to the caller; ICMP port unreachable from the carrier |
| `packet-loss-jitter` | 5% loss and 40±30 ms delay on Alice's network | 200, call degraded |

## Exercises

Do these yourself, in Wireshark, before reading the triage output. Write
each one up the way you'd write an escalation: symptom, evidence (frame
numbers), root cause and fix.

**Wireshark tools you'll use**
- Telephony → VoIP Calls → select call → **Flow Sequence** (ladder diagram)
- Telephony → RTP → **RTP Streams** → Analyze (loss, jitter, sequence errors)
- Telephony → RTP → RTP Player (listen to the call: the tones alternate 440/880 Hz each second)
- Filters: `sip`, `sdp`, `rtp`, `rtcp`, `icmp`, `sip.Status-Code >= 400`
- If RTP isn't decoded: Analyze → Enabled Protocols → enable `rtp_udp` and `rtcp_udp` heuristics

1. **healthy-call:** Draw the ladder from memory: REGISTER/401/REGISTER/200,
   INVITE/401/ACK/INVITE/100/200/ACK, BYE/200. Why does the first INVITE get
   a 401? Why are there **two** INVITE dialogs (Alice↔PBX and PBX↔Bob)? In
   the SDP, what did Alice offer and what did the PBX answer with? How many
   RTP streams are there, and why four?
2. **RTCP (healthy-call):** Find a Sender Report and a Receiver Report. Read
   *fraction lost*, *cumulative lost* and *interarrival jitter*. Convert the
   jitter from timestamp units to ms (G.711 is 8 kHz, so divide by 8).
3. **auth-failure:** How do you tell a normal 401 challenge from a real
   auth failure? Compare the nonce and the `Authorization` header across
   attempts. What would a 403 instead of a second 401 tell you?
4. **not-found vs unavailable:** Both calls fail instantly. What in the
   response separates "number doesn't exist" from "phone is offline"? Run
   `./lab.sh pbx "pjsip show contacts"` during each one.
   *Real-world note:* stock Asterisk sends **404** for an unregistered phone.
   This lab maps it to 480 in `extensions.conf`. Response codes differ between
   vendors, so always confirm with registration state, not the code alone.
5. **busy:** Where does the 486 originate (which leg), and how does the PBX
   pass it back to Alice?
6. **codec-mismatch:** Find the `m=` line and `a=rtpmap` in the INVITE.
   Why 488 and not 415 or 606? How would you fix it on the PBX side
   (`allow=` in `pjsip.conf`) versus the phone side?
7. **one-way-audio:** The call connects (200 OK) but compare the SDP `c=`
   address in Alice's INVITE with the IP header it was sent from. Which RTP
   streams exist and which direction is missing? What do the ICMP port
   unreachables tell you? Name three real-world fixes (NAT traversal on the
   phone, SIP ALG off on the router, `rtp_symmetric`/`force_rport` and
   `rewrite_contact` on the PBX, or an SBC doing media latching).
8. **dead-trunk:** Count the INVITE retransmissions to 10.50.0.99 and their
   timing (timer A doubling: 0.5 s, 1 s, 2 s…). What does each ICMP reply
   mean? What does the caller receive, and after how long?
9. **packet-loss-jitter:** In RTP Stream Analysis, find the lost sequence
   numbers and the max delta. Compare with what the RTCP Receiver Reports
   say. Why does loss on Alice's uplink also show up on the PBX→Bob leg?
   At what loss/jitter would users start complaining?

**Break it yourself next:** edit `asterisk/*.conf` and rerun. For example,
set `allow=alaw` only, change Bob's password, set `rtp_symmetric=yes` and
`rewrite_contact=yes` and rerun `one-way-audio`, or use
`--netem="loss 20%"` in `lab.sh`.

## Triage tool

`tools/sip_triage.py <pcap>` uses only Python 3 + tshark. It summarises every
SIP dialog with the meaning of its final response, the SDP media address and
codecs (flagging addresses that differ from the packet source), every RTP
stream's loss and jitter, streams with no return path, RTCP receiver reports
and ICMP port-unreachable replies. It works on any capture; pass
`--rtp-ports` to force-decode a PBX's RTP port range.

## How this maps to Cisco UC

These are general concepts only; this lab doesn't run any Cisco software.
- Asterisk's dialplan plays the role of CUCM route patterns and route lists.
- The PBX-anchored media (`direct_media=no`) is what an SBC such as CUBE does at the network edge.
- SIP response codes, SDP offer/answer, RTP and RTCP behave the same on any vendor.
