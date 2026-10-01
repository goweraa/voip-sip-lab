#!/usr/bin/env python3
"""First-pass triage of a SIP/RTP packet capture.

Summarises what an escalation engineer checks first:
  * every SIP dialog: who called whom, the response codes and what they mean
  * the SDP each side offered (codec and media address), flagging addresses
    that differ from where the packets really came from (the usual NAT bug)
  * every RTP stream: packets, loss, jitter, and streams with no return path
  * RTCP receiver reports: what each end says it is receiving
  * ICMP port-unreachable replies (host up, service down)

Needs only Python 3 and tshark (Wireshark's CLI).
Usage: sip_triage.py capture.pcap [--rtp-ports 10000-10100]
"""
import argparse
import collections
import re
import subprocess
import sys

STATUS_HINTS = {
    401: "auth challenge (normal once; repeated = wrong credentials)",
    403: "forbidden: credentials/ACL rejected",
    404: "not found: no route/dialplan match for the dialled number",
    407: "proxy auth challenge (normal once; repeated = wrong credentials)",
    408: "request timeout: next hop never answered",
    480: "temporarily unavailable: callee not registered/reachable",
    481: "call/transaction does not exist",
    486: "busy here",
    487: "request terminated (caller cancelled)",
    488: "not acceptable here: SDP/codec negotiation failed",
    500: "server internal error",
    502: "bad gateway: upstream/carrier failure",
    503: "service unavailable: overloaded or no usable trunk",
    504: "server timeout: upstream never answered",
    603: "decline",
}

# tshark decodes these as RTP/RTCP even without seeing the SDP first.
TSHARK_PREFS = ["-o", "rtp.heuristic_rtp:TRUE", "-o", "rtcp.heuristic_rtcp:TRUE"]


def tshark(pcap, *args):
    cmd = ["tshark", "-r", pcap, *TSHARK_PREFS, *args]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"tshark failed: {res.stderr.strip()}")
    return res.stdout


def fields(pcap, display_filter, names):
    out = tshark(pcap, "-Y", display_filter, "-T", "fields", "-E", "separator=\t",
                 *sum((["-e", n] for n in names), []))
    for line in out.splitlines():
        yield dict(zip(names, line.split("\t")))


def user(uri):
    m = re.search(r"sips?:([^@;>]+)@", uri or "")
    return m.group(1) if m else (uri or "?")


def sip_dialogs(pcap):
    names = ["frame.time_relative", "ip.src", "ip.dst", "sip.Call-ID", "sip.Method",
             "sip.Status-Code", "sip.CSeq.method", "sip.from.addr", "sip.to.addr",
             "sdp.connection_info.address", "sdp.media.port", "sdp.media.format"]
    dialogs = {}
    for p in fields(pcap, "sip", names):
        d = dialogs.setdefault(p["sip.Call-ID"], {"sdp": []})
        if p["sip.Method"]:
            label = p["sip.Method"]
            if p["sip.Method"] in ("INVITE", "REGISTER") and "from" not in d:
                d.update(method=p["sip.Method"], frm=user(p["sip.from.addr"]),
                         to=user(p["sip.to.addr"]))
        else:
            code = int(p["sip.Status-Code"] or 0)
            label = f"{code} ({p['sip.CSeq.method']})"
            if p["sip.CSeq.method"] == d.get("method"):
                d.setdefault("codes", []).append(code)
        d.setdefault("leg", f'{p["ip.src"]} -> {p["ip.dst"]}')
        if p["sdp.connection_info.address"]:
            # keep codec names, drop payload numbers, dynamic types and duplicates
            codecs = [c for c in dict.fromkeys(p["sdp.media.format"].split(","))
                      if c and not c.isdigit() and not c.startswith("DynamicRTP")]
            entry = (label, p["ip.src"], p["sdp.connection_info.address"],
                     p["sdp.media.port"], ", ".join(codecs))
            if entry not in d["sdp"]:
                d["sdp"].append(entry)
    return dialogs


def rtp_streams(pcap, rtp_ports):
    decode = ["-d", f"udp.port=={rtp_ports},rtp"] if rtp_ports else []
    out = tshark(pcap, *decode, "-q", "-z", "rtp,streams")
    row = re.compile(r"^\s*([\d.]+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+"
                     r"(.+?)\s+(\d+)\s+(-?\d+)\s+\((-?[\d.]+)%\)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+"
                     r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(X?)\s*$")
    streams = []
    for line in out.splitlines():
        m = row.match(line)
        if m:
            g = m.groups()
            streams.append(dict(src=g[2], sport=g[3], dst=g[4], dport=g[5], codec=g[7].strip(),
                                pkts=int(g[8]), lost=int(g[9]), lost_pct=float(g[10]),
                                max_delta=float(g[13]), mean_jitter=float(g[15]),
                                max_jitter=float(g[16]), problem=bool(g[17])))
    return streams


def rtcp_reports(pcap):
    names = ["ip.src", "ip.dst", "rtcp.pt", "rtcp.ssrc.fraction", "rtcp.ssrc.cum_nr",
             "rtcp.ssrc.jitter"]
    reports = collections.defaultdict(list)
    for p in fields(pcap, "rtcp.ssrc.fraction", names):
        frac = p["rtcp.ssrc.fraction"].split(",")[0]
        cum = p["rtcp.ssrc.cum_nr"].split(",")[0]
        jit = p["rtcp.ssrc.jitter"].split(",")[0]
        src = p["ip.src"].split(",")[0]
        dst = p["ip.dst"].split(",")[0]
        # fraction lost is n/256; jitter is in RTP timestamp units (8 kHz -> /8 = ms)
        reports[(src, dst)].append((int(frac) / 256 * 100, int(cum), int(jit) / 8))
    return reports


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap")
    ap.add_argument("--rtp-ports", default="10000-10100",
                    help="UDP port range to force-decode as RTP (default: lab PBX range)")
    a = ap.parse_args()

    findings = []
    print("SIP dialogs")
    dialogs = sip_dialogs(a.pcap)
    if not dialogs:
        print("  (no SIP found)")
    for d in dialogs.values():
        if "method" not in d:
            continue
        codes = d.get("codes", [])
        final = next((c for c in reversed(codes) if c >= 200), None)
        print(f"  {d['method']} {d['frm']} -> {d['to']}  [{d['leg']}]: "
              + " ".join(map(str, codes)) + (f"  => final {final}" if final else "  => no final response"))
        if d["method"] == "REGISTER" and codes.count(401) + codes.count(407) > 1 and final in (401, 407, 403):
            findings.append(f"REGISTER for {d['frm']} challenged repeatedly and never accepted: "
                            "wrong username/password or realm.")
        elif final and final >= 300 and final not in (401, 407):
            findings.append(f"{d['method']} {d['frm']} -> {d['to']} failed with {final}: "
                            f"{STATUS_HINTS.get(final, 'see RFC 3261')}.")
        elif final is None and d["method"] == "INVITE":
            findings.append(f"INVITE {d['frm']} -> {d['to']} got no final response.")
        for label, src, conn, port, fmt in d["sdp"]:
            print(f"      SDP in {label} from {src}: media {conn}:{port} codecs {fmt}")
            if conn != src:
                findings.append(f"SDP in {label} from {src} advertises media address {conn}, "
                                "which is not the address it sent from: NAT/SDP rewrite problem, "
                                "expect one-way or no audio.")

    print("\nRTP streams")
    streams = rtp_streams(a.pcap, a.rtp_ports)
    if not streams:
        print("  (no RTP found)")
    senders = {s["src"] for s in streams}
    for s in streams:
        print(f"  {s['src']}:{s['sport']} -> {s['dst']}:{s['dport']}  {s['codec']}  "
              f"{s['pkts']} pkts, lost {s['lost']} ({s['lost_pct']}%), "
              f"jitter mean {s['mean_jitter']:.1f} / max {s['max_jitter']:.1f} ms, "
              f"max gap {s['max_delta']:.0f} ms")
        if s["dst"] not in senders:
            findings.append(f"RTP flows {s['src']} -> {s['dst']} but {s['dst']} never sends RTP back: "
                            "one-way audio. Check the SDP c= address and NAT/firewall on that side.")
        if s["lost_pct"] >= 1:
            findings.append(f"{s['src']} -> {s['dst']}: {s['lost_pct']}% packet loss.")
        if s["max_jitter"] >= 30:
            findings.append(f"{s['src']} -> {s['dst']}: max jitter {s['max_jitter']:.0f} ms "
                            "(over ~30 ms is audible without a deep jitter buffer).")

    print("\nRTCP receiver reports (what each end says it receives)")
    reports = rtcp_reports(a.pcap)
    if not reports:
        print("  (no RTCP reports found)")
    for (src, dst), rs in reports.items():
        worst_loss = max(r[0] for r in rs)
        worst_jit = max(r[2] for r in rs)
        print(f"  {src} reports to {dst}: {len(rs)} reports, worst fraction lost {worst_loss:.1f}%, "
              f"cumulative lost {rs[-1][1]}, worst jitter {worst_jit:.1f} ms")

    unreachable = collections.Counter(
        (p["ip.src"].split(",")[0], p["udp.dstport"].split(",")[-1]) for p in
        fields(a.pcap, "icmp.type == 3 && icmp.code == 3", ["ip.src", "udp.dstport"]))
    for (host, port), n in unreachable.items():
        if n < 5:  # a few at call teardown (late RTP/RTCP) are normal
            continue
        findings.append(f"{host} answered {n} packet(s) to UDP port {port} with ICMP "
                        "port unreachable: the host is up but nothing is listening there "
                        "(service down, wrong port, or media sent to the wrong address).")

    print("\nFindings")
    for f in dict.fromkeys(findings) or ["Nothing abnormal: signalling completed and media flowed both ways."]:
        print(f"  - {f}")


if __name__ == "__main__":
    main()
