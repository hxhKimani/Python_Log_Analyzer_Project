import React, { useState } from 'react';
import { Check, Copy, Terminal } from 'lucide-react';
import { copyToClipboard } from '../utils/clipboard';

interface BuildGuideViewProps {
  onOpenSourceTab: () => void;
}

interface BuildStep {
  number: string;
  title: string;
  modulePath: string;
  summary: string;
  whyItMatters: string;
  codeSnippet: string;
}

const BUILD_STEPS: BuildStep[] = [
  {
    number: '01',
    title: 'Project Layout & Memory-Efficient Models',
    modulePath: 'sentinel_log/models.py',
    summary:
      'Define typed dataclasses (LogEvent, Alert, AnalysisReport) with slots=True and a Severity enum instead of passing untyped dictionaries across modules.',
    whyItMatters:
      'Using slots=True eliminates per-instance __dict__ allocations, reducing memory overhead by ~40% when parsing hundreds of thousands of log records.',
    codeSnippet: `mkdir -p sentinel-log/sentinel_log sentinel-log/tests sentinel-log/samples
cd sentinel-log
python3 -m venv .venv && source .venv/bin/activate`,
  },
  {
    number: '02',
    title: 'Streaming Multi-Format Regex Parsers',
    modulePath: 'sentinel_log/parsers.py',
    summary:
      'Pre-compile regular expressions for OpenSSH/PAM syslog, Apache/Nginx Combined Log Format, and UFW kernel drops. Yield normalized LogEvent records lazily via a Python generator.',
    whyItMatters:
      'Never call file.readlines() in a security log tool. Streaming line-by-line via yield allows constant O(1) I/O memory even on multi-gigabyte production logs.',
    codeSnippet: `def parse_stream(lines: Iterable[str]) -> Iterator[tuple[int, LogEvent | None]]:
    for idx, raw_line in enumerate(lines, start=1):
        if raw_line.strip():
            yield idx, parse_line(raw_line, line_number=idx)`,
  },
  {
    number: '03',
    title: 'Sliding-Window Brute-Force & Compromise Correlation',
    modulePath: 'sentinel_log/detectors.py',
    summary:
      'Use collections.deque per source IP to evict timestamps older than the configured window (e.g., 120 seconds) in O(1) amortized time, then correlate failures with subsequent accepted logins.',
    whyItMatters:
      'Flagging 5 failed logins followed by an Accepted password/publickey event elevates a routine scan into a high-priority post-compromise alert (MITRE T1078.003).',
    codeSnippet: `q: deque[LogEvent] = deque()
for ev in ip_events:
    q.append(ev)
    while q and (ev.timestamp - q[0].timestamp) > window:
        q.popleft()
    if len(q) >= threshold:
        triggered = True`,
  },
  {
    number: '04',
    title: 'URL Normalization Before Web Signature Matching',
    modulePath: 'sentinel_log/detectors.py',
    summary:
      'Apply urllib.parse.unquote_plus twice before running SQLi, XSS, and path-traversal regex rules so single- and double-encoded payloads cannot bypass inspection.',
    whyItMatters:
      'Attackers routinely encode quotes or brackets (%27, %2527, %3Cscript%3E) to evade naive regex checks. Canonicalizing input first closes this evasion gap.',
    codeSnippet: `def _normalize_url(path: str | None) -> str:
    if not path:
        return ""
    return unquote_plus(unquote_plus(path))`,
  },
  {
    number: '05',
    title: 'Firewall Reconnaissance & Statistical Burst Detection',
    modulePath: 'sentinel_log/detectors.py',
    summary:
      'Aggregate distinct blocked destination ports per source IP to catch horizontal/vertical scans, and calculate per-minute z-scores to surface anomalous traffic spikes.',
    whyItMatters:
      'Combining deterministic rules (signatures & thresholds) with lightweight statistical baselines (mean + standard deviation) demonstrates both rule engineering and anomaly detection.',
    codeSnippet: `z_score = (len(bucket_events) - mean) / std_dev
if z_score >= z_threshold and len(bucket_events) >= 10:
    # Flag minute bucket as anomalous burst`,
  },
  {
    number: '06',
    title: 'MITRE ATT&CK Enrichment, CLI & Unit Testing',
    modulePath: 'tests/test_analyzer.py',
    summary:
      'Attach MITRE ATT&CK technique IDs, tactics, and remediation steps to every alert. Expose JSON, CSV, and Markdown exporters through argparse and verify edge cases with unittest.',
    whyItMatters:
      'Hiring managers look for testable, maintainable security tooling. Including unit tests for evasion payloads and sliding-window boundaries sets your repository apart.',
    codeSnippet: `python3 -m unittest discover -s tests -t . -v
cat samples/*.log | python3 -m sentinel_log.cli -i - -f markdown -o incident_report.md`,
  },
];

export const BuildGuideView: React.FC<BuildGuideViewProps> = ({ onOpenSourceTab }) => {
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  const handleCopy = async (idx: number, text: string) => {
    const copied = await copyToClipboard(text);
    if (copied) {
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1600);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-lg p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="max-w-2xl">
          <h2 className="text-xl font-semibold text-slate-900">
            Build Blueprint: Zero-Dependency Python Log Analyzer
          </h2>
          <p className="text-sm text-slate-600 mt-1.5 leading-relaxed">
            Follow this 6-stage architecture to build, understand, and explain every engineering decision behind SentinelLog in technical cybersecurity interviews.
          </p>
        </div>
        <button
          type="button"
          onClick={onOpenSourceTab}
          className="inline-flex items-center gap-2 h-10 px-4 text-sm font-medium text-slate-900 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Terminal className="w-4 h-4" />
          Inspect Full Codebase
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {BUILD_STEPS.map((step, idx) => (
          <article
            key={step.number}
            className="bg-white border border-slate-200 rounded-lg p-6 flex flex-col justify-between gap-4"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2 text-xs text-slate-500">
                <span className="font-semibold text-slate-900">
                  {step.number}. {step.title}
                </span>
                <span className="font-mono text-slate-500 shrink-0">{step.modulePath}</span>
              </div>

              <p className="text-sm text-slate-700 leading-relaxed">{step.summary}</p>

              <p className="text-xs text-slate-600 leading-relaxed bg-slate-50 border border-slate-200 rounded-md p-3">
                <span className="font-semibold text-slate-800">Engineering Rationale: </span>
                {step.whyItMatters}
              </p>
            </div>

            <div className="bg-slate-950 rounded-md overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800">
                <span className="text-[11px] font-mono text-slate-400">Implementation Reference</span>
                <button
                  type="button"
                  onClick={() => handleCopy(idx, step.codeSnippet)}
                  className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-300 hover:text-white cursor-pointer"
                >
                  {copiedIdx === idx ? (
                    <Check className="w-3 h-3 text-green-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  {copiedIdx === idx ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="p-3 text-xs font-mono text-slate-200 overflow-x-auto leading-5">
                {step.codeSnippet}
              </pre>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
};
