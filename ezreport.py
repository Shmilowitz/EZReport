#!/usr/bin/env python3
"""
EZReport — pentest report funnel
Parses nmap, nuclei, testssl, nikto, and ffuf output into a normalized schema,
deduplicates findings, enriches with remediation text, and emits a client-ready report.

Usage:
    python ezreport.py scan1.xml nuclei.json testssl.json --format html -o report.html
    python ezreport.py *.xml *.json --format docx --title "ACME Corp Pentest" --author "You"
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import List

from findings import Finding, enrich
from parsers import detect_parser
from reports import MarkdownReport, HtmlReport, DocxReport

FORMATS = {
    'md':   (MarkdownReport, '.md'),
    'html': (HtmlReport,     '.html'),
    'docx': (DocxReport,     '.docx'),
}


def parse_files(paths: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    for path in paths:
        if not path.exists():
            print(f'[!] File not found, skipping: {path}', file=sys.stderr)
            continue

        parser_cls = detect_parser(path)
        if parser_cls is None:
            print(f'[!] No parser matched: {path} — skipping', file=sys.stderr)
            continue

        print(f'[+] {parser_cls.__name__}: {path}')
        try:
            new = parser_cls(path).parse()
            print(f'    -> {len(new)} finding(s)')
            findings.extend(new)
        except Exception as exc:
            print(f'[!] Parse error in {path}: {exc}', file=sys.stderr)

    return findings


def deduplicate(findings: List[Finding]) -> List[Finding]:
    seen: dict = {}
    result: List[Finding] = []
    for f in findings:
        key = (f.title.lower().strip(), f.affected_asset.lower().strip())
        if key not in seen:
            seen[key] = f
            result.append(f)
        else:
            existing = seen[key]
            if f.evidence and f.evidence.strip() not in existing.evidence:
                existing.evidence += f'\n\n[Also seen via {f.tool_source}]\n{f.evidence}'
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Parse pentest tool output and generate a formatted report.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python ezreport.py nmap.xml nuclei.json -f html -o report.html\n'
            '  python ezreport.py *.xml *.json -f docx --title "Pentest Q2" --author "Alice"\n'
            '  python ezreport.py nmap.xml -f md --dump-json'
        ),
    )
    parser.add_argument('files', nargs='+', help='Tool output files to parse')
    parser.add_argument('-f', '--format', choices=FORMATS.keys(), default='html',
                        help='Output format (default: html)')
    parser.add_argument('-o', '--output', help='Output file path (auto-named if omitted)')
    parser.add_argument('--title',  default='Penetration Test Report', help='Report title')
    parser.add_argument('--author', default='',  help='Report author name')
    parser.add_argument('--scope',  default='',  help='Engagement scope description')
    parser.add_argument('--no-enrich', action='store_true',
                        help='Skip remediation enrichment')
    parser.add_argument('--dump-json', action='store_true',
                        help='Also write normalized_findings.json')
    args = parser.parse_args()

    # Resolve globs / paths
    input_paths: List[Path] = []
    for pattern in args.files:
        matches = list(Path('.').glob(pattern))
        if matches:
            input_paths.extend(matches)
        else:
            input_paths.append(Path(pattern))

    if not input_paths:
        print('[!] No input files provided.', file=sys.stderr)
        sys.exit(1)

    # Parse
    findings = parse_files(input_paths)
    if not findings:
        print('[!] No findings parsed from any input file.', file=sys.stderr)
        sys.exit(1)

    # Deduplicate
    before = len(findings)
    findings = deduplicate(findings)
    dupes = before - len(findings)
    if dupes:
        print(f'[~] Deduplicated {dupes} duplicate(s) → {len(findings)} unique finding(s)')

    # Enrich
    if not args.no_enrich:
        enrich(findings)

    # Optionally dump JSON
    if args.dump_json:
        json_path = Path('normalized_findings.json')
        json_path.write_text(
            json.dumps([f.to_dict() for f in findings], indent=2),
            encoding='utf-8',
        )
        print(f'[+] Wrote {json_path}')

    # Determine output path
    report_cls, ext = FORMATS[args.format]
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(f'report{ext}')

    # Generate
    metadata = {
        'title':  args.title,
        'author': args.author,
        'scope':  args.scope,
        'date':   str(date.today()),
    }

    report_cls(findings, metadata).generate(output_path)
    print(f'[+] Report written -> {output_path}')

    # Severity summary
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = '  '.join(f'{s}: {counts.get(s, 0)}' for s in ('critical', 'high', 'medium', 'low', 'info'))
    print(f'[+] {summary}')


if __name__ == '__main__':
    main()
