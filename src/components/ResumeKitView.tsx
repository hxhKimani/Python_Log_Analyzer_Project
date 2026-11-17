import React, { useMemo, useState } from 'react';
import { Check, ChevronDown, ChevronRight, Copy } from 'lucide-react';
import { copyToClipboard } from '../utils/clipboard';

type TargetRole = 'soc' | 'sec_eng' | 'detection' | 'appsec';

interface RoleConfig {
  label: string;
  headline: string;
  bullets: string[];
  skillsLine: string;
}

const ROLE_CONFIGS: Record<TargetRole, RoleConfig> = {
  soc: {
    label: 'SOC Analyst (Tier 1 / Tier 2)',
    headline: 'Emphasizes triage speed, MITRE ATT&CK mapping, and incident reporting.',
    bullets: [
      'Engineered a streaming Python 3.11 security log analyzer to ingest and normalize OpenSSH auth.log, Nginx/Apache access logs, and UFW firewall telemetry via memory-efficient generators.',
      'Automated detection of SSH brute-force bursts, credential stuffing, and post-failure account compromises using sliding time-window correlation mapped to MITRE ATT&CK (T1110, T1078, T1190, T1046).',
      'Built structured JSON, CSV, and Markdown incident report exporters with IP aggregation and log evidence extraction, accelerating Tier-1 alert triage and handoff documentation.',
    ],
    skillsLine: 'Python 3.11, Regex, MITRE ATT&CK, Log Triage (Syslog / HTTP / UFW), Incident Reporting',
  },
  sec_eng: {
    label: 'Security Engineer',
    headline: 'Emphasizes O(1) algorithms, zero-dependency design, and testability.',
    bullets: [
      'Architected a zero-dependency Python CLI (SentinelLog) using typed dataclasses (slots=True), streaming generators, and collections.deque sliding windows to process multi-format security logs in constant memory.',
      'Implemented double URL-decoding normalization prior to regex signature evaluation to catch obfuscated SQL injection, XSS, and path-traversal evasion attempts (%2527 / %3C encodings).',
      'Authored a modular unittest suite covering parser edge cases, sliding-window boundary conditions, and multi-port reconnaissance rules, achieving deterministic sub-5ms local test runs.',
    ],
    skillsLine: 'Python 3.11, Data Structures (deque), CLI Tooling (argparse), Unit Testing, Threat Detection',
  },
  detection: {
    label: 'Detection Engineer',
    headline: 'Emphasizes rule correlation, evasion resistance, and statistical baselines.',
    bullets: [
      'Designed multi-stage detection logic combining deterministic signature rules, sliding-window behavioral correlation, and per-minute z-score anomaly detection for traffic burst identification.',
      'Mapped every detection rule to MITRE ATT&CK tactics and technique IDs with tunable CLI thresholds (--bf-threshold, --window, --port-threshold, --z-threshold) to minimize false positives across environments.',
      'Built correlation rules linking repeated SSH authentication failures to subsequent accepted logins from the same source IP, surfacing active credential compromise chains.',
    ],
    skillsLine: 'Detection Engineering, MITRE ATT&CK, Anomaly Detection (Z-Score), Regex Normalization, Python',
  },
  appsec: {
    label: 'AppSec / Blue Team',
    headline: 'Emphasizes web payload decoding, OWASP attack patterns, and remediation.',
    bullets: [
      'Built a Python web access log analyzer detecting OWASP Top-10 probing patterns (SQLi, reflected XSS, local file inclusion, and automated scanners such as sqlmap and Nuclei).',
      'Applied multi-pass URL unquoting before signature matching to defeat double-encoded payload obfuscation and preserve exact raw-line forensic evidence for incident response.',
      'Paired automated findings with actionable remediation playbooks and source-IP correlation across perimeter firewall drops and application HTTP error responses.',
    ],
    skillsLine: 'OWASP Top 10, HTTP Forensics, Python, Regex Evasion Defense, Blue Team Automation',
  },
};

const INTERVIEW_QA = [
  {
    q: 'How would you scale this analyzer to process a 50 GB log file without running out of RAM?',
    a: 'The parser uses a Python generator (parse_stream) that yields one normalized LogEvent at a time instead of loading the file into memory. To keep detector state bounded on 50 GB logs, I would convert the per-IP event lists in detectors.py to stream directly into fixed-window deques and periodically evict inactive IP keys whose newest timestamp is older than the sliding window, or shard files across multiprocessing workers by source IP hash.',
  },
  {
    q: 'How do you prevent Regular Expression Denial of Service (ReDoS) on untrusted log lines?',
    a: 'All regex patterns are pre-compiled at module import time using anchored or bounded character classes (such as \\S+, \\d{1,3}, and non-nested quantifiers) rather than nested ambiguous repetitions like (a+)+. For untrusted HTTP paths, I also bound line length or normalize once before matching.',
  },
  {
    q: 'How would you reduce false positives when legitimate users sit behind a shared corporate NAT or VPN IP?',
    a: 'First, expose tunable CLI thresholds (--bf-threshold, --window) and support an allowlist CIDR configuration for trusted corporate egress IPs. Second, distinguish single-user password typos from credential stuffing by counting distinct targeted usernames per IP rather than raw failure count alone.',
  },
  {
    q: 'Why does the web detector call unquote_plus twice before running SQLi and XSS rules?',
    a: 'Attackers frequently double-encode payloads (for example %2527 instead of %27) so that a single-pass decoder leaves %27 literal and slips past signature checks while the downstream application still decodes it. Running two passes catches single and double URL encoding cleanly.',
  },
];

export const ResumeKitView: React.FC = () => {
  const [role, setRole] = useState<TargetRole>('soc');
  const [projectName, setProjectName] = useState('SentinelLog — Python Cybersecurity Log Analyzer');
  const [githubSlug, setGithubSlug] = useState('github.com/yourhandle/sentinel-log');
  const [copiedBullets, setCopiedBullets] = useState(false);
  const [openQaIdx, setOpenQaIdx] = useState<number | null>(0);

  const activeConfig = ROLE_CONFIGS[role];

  const formattedMarkdown = useMemo(() => {
    return [
      `### ${projectName} | Python 3.11 | ${githubSlug}`,
      ...activeConfig.bullets.map((b) => `- ${b}`),
      `- **Tech Stack:** ${activeConfig.skillsLine}`,
    ].join('\n');
  }, [activeConfig, githubSlug, projectName]);

  const handleCopyBullets = async () => {
    const copied = await copyToClipboard(formattedMarkdown);
    if (copied) {
      setCopiedBullets(true);
      setTimeout(() => setCopiedBullets(false), 1800);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-slate-900">
              Cybersecurity Resume Bullets & Interview Preparation
            </h2>
            <p className="text-sm text-slate-600 mt-1">
              Select your target role to tailor project bullet points grounded directly in the Python implementation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-100 rounded-md self-start">
            {(Object.keys(ROLE_CONFIGS) as TargetRole[]).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setRole(key)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  role === key
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {ROLE_CONFIGS[key].label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-200">
          <div>
            <label htmlFor="resume-proj-title" className="block text-xs font-medium text-slate-600 mb-1.5">
              Resume Project Header
            </label>
            <input
              id="resume-proj-title"
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              className="w-full h-10 px-3 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
            />
          </div>
          <div>
            <label htmlFor="resume-gh-url" className="block text-xs font-medium text-slate-600 mb-1.5">
              Repository Link
            </label>
            <input
              id="resume-gh-url"
              type="text"
              value={githubSlug}
              onChange={(e) => setGithubSlug(e.target.value)}
              className="w-full h-10 px-3 text-sm font-mono bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
            />
          </div>
        </div>
      </div>

      {/* Formatted Resume Preview */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 bg-slate-50 border-b border-slate-200">
          <div>
            <div className="text-sm font-semibold text-slate-900">{activeConfig.label}</div>
            <div className="text-xs text-slate-600 mt-0.5">{activeConfig.headline}</div>
          </div>
          <button
            type="button"
            onClick={handleCopyBullets}
            className="inline-flex items-center gap-2 h-9 px-3.5 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {copiedBullets ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedBullets ? 'Copied Markdown' : 'Copy Resume Block'}
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-200 pb-3">
            <h3 className="text-base font-semibold text-slate-900">{projectName}</h3>
            <span className="text-xs font-mono text-slate-500">{githubSlug}</span>
          </div>

          <ul className="space-y-2.5 text-sm text-slate-700 leading-relaxed list-disc pl-5">
            {activeConfig.bullets.map((bullet, idx) => (
              <li key={idx}>{bullet}</li>
            ))}
          </ul>

          <div className="pt-2 text-xs text-slate-600">
            <span className="font-semibold text-slate-900">Technologies: </span>
            {activeConfig.skillsLine}
          </div>
        </div>
      </div>

      {/* Technical Interview Questions */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200">
          <h3 className="text-base font-semibold text-slate-900">
            Technical Interview Questions & Answers
          </h3>
          <p className="text-xs text-slate-600 mt-0.5">
            Prepare for follow-up architecture questions hiring managers ask when reviewing this project on your resume.
          </p>
        </div>

        <div className="divide-y divide-slate-200">
          {INTERVIEW_QA.map((item, idx) => {
            const isOpen = openQaIdx === idx;
            return (
              <div key={idx}>
                <button
                  type="button"
                  onClick={() => setOpenQaIdx(isOpen ? null : idx)}
                  className="w-full px-6 py-4 text-left flex items-center justify-between gap-4 hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  <span className="text-sm font-medium text-slate-900">{item.q}</span>
                  <span className="text-slate-400 shrink-0">
                    {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </span>
                </button>
                {isOpen && (
                  <div className="px-6 pb-5 text-sm text-slate-700 leading-relaxed bg-slate-50/60">
                    {item.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
