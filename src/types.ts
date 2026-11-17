export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ExportFormat = 'json' | 'csv' | 'markdown' | 'text';

export type ActiveTab = 'analyzer' | 'source' | 'guide' | 'resume';

export interface AlertItem {
  rule_id: string;
  title: string;
  severity: Severity;
  source_ip: string;
  description: string;
  mitre_id: string;
  mitre_tactic: string;
  mitre_technique: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
  evidence: string[];
  remediation: string;
}

export interface TopSourceIp {
  ip: string;
  event_count: number;
  alert_count: number;
  sources: string[];
}

export interface TimelineBucket {
  bucket: string;
  total: number;
  suspicious: number;
}

export interface AnalysisReport {
  total_lines: number;
  parsed_events: number;
  unparsed_lines: number;
  detected_formats: Record<string, number>;
  alerts: AlertItem[];
  top_source_ips: TopSourceIp[];
  timeline_buckets: TimelineBucket[];
  severity_counts: Record<Severity, number>;
  duration_ms: number;
}

export interface AnalyzeResponse {
  report: AnalysisReport;
  formattedExport: string;
  format: ExportFormat;
  cliCommand: string;
}

export interface ProjectFileEntry {
  path: string;
  name: string;
  directory: string;
  language: string;
  lines: number;
  bytes: number;
  content: string;
}

export interface TestRunResult {
  passed: boolean;
  exitCode: number;
  totalTests: number;
  durationMs: number;
  output: string;
}
