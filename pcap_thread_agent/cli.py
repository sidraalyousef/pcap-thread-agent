"""CLI entrypoint: pcap -> flows -> heuristic threads -> optional LLM narrative -> report."""
import argparse
import sys

from .detectors import run_all_detectors
from .flows import build_flows
from .report import generate_markdown_report
from .summarize import summarize_threads
from .tshark_runner import extract_packets


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Summarize security-relevant threads from a Wireshark capture.")
    parser.add_argument("pcap", help="Path to a .pcap/.pcapng file")
    parser.add_argument("-o", "--output", default="report.md", help="Path to write the Markdown report (default: report.md)")
    parser.add_argument("--no-llm", action="store_true", help="Skip Claude narration; report heuristic evidence only")
    args = parser.parse_args(argv)

    print(f"Extracting packets from {args.pcap} via tshark...", file=sys.stderr)
    packets = extract_packets(args.pcap)

    print("Reconstructing flows...", file=sys.stderr)
    flows = list(build_flows(packets).values())
    print(f"  {len(flows)} flow(s) reconstructed.", file=sys.stderr)

    print("Running heuristic detectors...", file=sys.stderr)
    threads = run_all_detectors(flows)
    print(f"  {len(threads)} thread(s) flagged.", file=sys.stderr)

    if threads and not args.no_llm:
        print("Summarizing flagged threads with Claude...", file=sys.stderr)
        summarize_threads(threads)

    report = generate_markdown_report(threads, source_file=args.pcap)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Report written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
