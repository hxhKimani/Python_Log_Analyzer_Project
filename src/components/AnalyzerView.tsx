import React, { useMemo, useRef, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  FileUp,
  Info,
  Play,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';
import type { AnalyzeResponse, ExportFormat, ProjectFileEntry, Severity } from '../types';
import { copyToClipboard } from '../utils/clipboard';

interface AnalyzerViewProps {
  sampleFiles: ProjectFileEntry[];
  logText: string;
  setLogText: (val: string) => void;
  bfThreshold: number;
  setBfThreshold: (val: number) => void;
  windowSeconds: number;
  setWindowSeconds: (val: number) => void;
  portThreshold: number;
  setPortThreshold: (val: number) => void;
  zThreshold: number;
  setZThreshold: (val: number) => void;
  exportFormat: ExportFormat;
  setExportFormat: (val: ExportFormat) => void;
  analysis: AnalyzeResponse | null;
  isAnalyzing: boolean;
  error: string | null;
  onRunAnalysis: (overrideFormat?: ExportFormat) => void;
}

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; textClass: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  critical: { label: 'Critical', textClass: 'text-red-700', Icon: AlertOctagon },
  high: { label: 'High', textClass: 'text-amber-700', Icon: AlertTriangle },
  medium: { label: 'Medium', textClass: 'text-sky-700', Icon: ShieldAlert },
  low: { label: 'Low', textClass: 'text-slate-600', Icon: Info },
  info: { label: 'Info', textClass: 'text-slate-500', Icon: Info },
};

export const AnalyzerView: React.FC<AnalyzerViewProps> = ({
  sampleFiles,
  logText,
  setLogText,
  bfThreshold,
  setBfThreshold,
  windowSeconds,
  setWindowSeconds,
  portThreshold,
  setPortThreshold,
  zThreshold,
  setZThreshold,
  exportFormat,
  setExportFormat,
  analysis,
  isAnalyzing,
  error,
  onRunAnalysis,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedPreset, setSelectedPreset] = useState<string>('combined');
  const [expandedAlertIdx, setExpandedAlertIdx] = useState<number | null>(0);
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [copiedExport, setCopiedExport] = useState(false);
  const [resultTab, setResultTab] = useState<'findings' | 'ips' | 'export'>('findings');

  const handlePresetChange = (presetKey: string) => {
    setSelectedPreset(presetKey);
    if (presetKey === 'combined') {
      const combined = sampleFiles.map((f) => f.content.trim()).join('\n');
      if (combined) setLogText(combined);
      return;
    }
    const found = sampleFiles.find((f) => f.name === presetKey);
    if (found) {
      setLogText(found.content.trim());
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setSelectedPreset('custom');
        setLogText(reader.result);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const filteredAlerts = useMemo(() => {
    if (!analysis) return [];
    if (severityFilter === 'all') return analysis.report.alerts;
    return analysis.report.alerts.filter((a) => a.severity === severityFilter);
  }, [analysis, severityFilter]);

  const maxBucketTotal = useMemo(() => {
    if (!analysis || analysis.report.timeline_buckets.length === 0) return 1;
    return Math.max(...analysis.report.timeline_buckets.map((b) => b.total), 1);
  }, [analysis]);

  const handleCopyExport = async () => {
    if (!analysis) return;
    const copied = await copyToClipboard(analysis.formattedExport);
    if (copied) {
      setCopiedExport(true);
      setTimeout(() => setCopiedExport(false), 1800);
    }
  };

  const handleDownloadExport = () => {
    if (!analysis) return;
    const extMap: Record<ExportFormat, string> = {
      json: 'json',
      csv: 'csv',
      markdown: 'md',
      text: 'txt',
    };
    const blob = new Blob([analysis.formattedExport], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinellog-report.${extMap[analysis.format]}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const lineCount = logText ? logText.split('\n').length : 0;

  return (
    <div className="space-y-6">
      {/* Control Toolbar */}
      <section className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 flex-1">
            <div className="sm:col-span-2 lg:col-span-1">
              <label htmlFor="dataset-select" className="block text-xs font-medium text-slate-600 mb-1.5">
                Log Dataset
              </label>
              <select
                id="dataset-select"
                value={selectedPreset}
                onChange={(e) => handlePresetChange(e.target.value)}
                className="w-full h-10 px-3 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
              >
                <option value="combined">Combined Incident Bundle</option>
                <option value="auth_bruteforce.log">SSH Brute Force (auth.log)</option>
                <option value="web_attacks.log">Web Attacks (access.log)</option>
                <option value="firewall_portscan.log">Firewall Scan (ufw.log)</option>
                {selectedPreset === 'custom' && <option value="custom">Uploaded / Custom Logs</option>}
              </select>
            </div>

            <div>
              <label htmlFor="bf-threshold" className="block text-xs font-medium text-slate-600 mb-1.5">
                SSH Fail Threshold
              </label>
              <input
                id="bf-threshold"
                type="number"
                min={2}
                max={50}
                value={bfThreshold}
                onChange={(e) => setBfThreshold(Number(e.target.value) || 5)}
                className="w-full h-10 px-3 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>

            <div>
              <label htmlFor="window-sec" className="block text-xs font-medium text-slate-600 mb-1.5">
                Sliding Window (sec)
              </label>
              <input
                id="window-sec"
                type="number"
                min={10}
                max={3600}
                step={10}
                value={windowSeconds}
                onChange={(e) => setWindowSeconds(Number(e.target.value) || 120)}
                className="w-full h-10 px-3 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>

            <div>
              <label htmlFor="port-threshold" className="block text-xs font-medium text-slate-600 mb-1.5">
                Port Scan Threshold
              </label>
              <input
                id="port-threshold"
                type="number"
                min={2}
                max={100}
                value={portThreshold}
                onChange={(e) => setPortThreshold(Number(e.target.value) || 5)}
                className="w-full h-10 px-3 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>

            <div>
              <label htmlFor="z-threshold" className="block text-xs font-medium text-slate-600 mb-1.5">
                Burst Z-Score
              </label>
              <input
                id="z-threshold"
                type="number"
                min={0.5}
                max={6}
                step={0.1}
                value={zThreshold}
                onChange={(e) => setZThreshold(Number(e.target.value) || 2.0)}
                className="w-full h-10 px-3 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.csv"
              onChange={handleFileUpload}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-2 h-10 px-4 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <FileUp className="w-4 h-4" />
              Upload Log
            </button>
            <button
              type="button"
              onClick={() => onRunAnalysis()}
              disabled={isAnalyzing || !logText.trim()}
              className="inline-flex items-center gap-2 h-10 px-5 text-sm font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-4 h-4" />
              {isAnalyzing ? 'Analyzing...' : 'Run Python Analyzer'}
            </button>
          </div>
        </div>
      </section>

      {error && (
        <div
          role="alert"
          className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-800 flex items-center justify-between"
        >
          <span>{error}</span>
        </div>
      )}

      {/* Main Split Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left: Raw Log Stream Input */}
        <div className="lg:col-span-5 flex flex-col bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 bg-slate-50">
            <div className="flex items-center gap-2 text-xs text-slate-600">
              <span className="font-semibold text-slate-900">Raw Log Stream</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{lineCount} lines</span>
            </div>
            <button
              type="button"
              onClick={() => handlePresetChange('combined')}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Sample
            </button>
          </div>

          <textarea
            aria-label="Raw log input"
            value={logText}
            onChange={(e) => {
              setSelectedPreset('custom');
              setLogText(e.target.value);
            }}
            spellCheck={false}
            placeholder="Paste OpenSSH auth.log, Apache/Nginx access logs, or UFW firewall logs here..."
            className="flex-1 min-h-[460px] w-full p-4 bg-slate-950 text-slate-100 font-mono text-xs leading-6 resize-none focus:outline-none"
          />

          <div className="px-4 py-2.5 bg-slate-900 border-t border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto whitespace-nowrap">
            $ {analysis?.cliCommand ?? `python3 -m sentinel_log.cli -i incident.log -f ${exportFormat}`}
          </div>
        </div>

        {/* Right: Python Analysis Report */}
        <div className="lg:col-span-7 flex flex-col bg-white border border-slate-200 rounded-lg overflow-hidden">
          {!analysis ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
              <h3 className="text-base font-semibold text-slate-900 mb-1">
                Ready to Execute Python Log Analysis
              </h3>
              <p className="text-sm text-slate-500 max-w-md mb-5">
                Click Run Python Analyzer to stream the raw log buffer through the Python 3.11 SentinelLog CLI and inspect normalized detections.
              </p>
              <button
                type="button"
                onClick={() => onRunAnalysis()}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 cursor-pointer"
              >
                <Play className="w-4 h-4" />
                Run Python Analyzer
              </button>
            </div>
          ) : (
            <>
              {/* 4-Column KPI Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 border-b border-slate-200 divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
                <div className="p-4">
                  <div className="text-xs text-slate-500">Lines Scanned</div>
                  <div className="mt-1 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
                    {analysis.report.total_lines}
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-xs text-slate-500">Normalized Events</div>
                  <div className="mt-1 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
                    {analysis.report.parsed_events}
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-xs text-slate-500">Alerts Triggered</div>
                  <div className="mt-1 text-2xl font-semibold text-red-700 font-mono tabular-nums">
                    {analysis.report.alerts.length}
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-xs text-slate-500">Python Runtime</div>
                  <div className="mt-1 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
                    {analysis.report.duration_ms.toFixed(2)} ms
                  </div>
                </div>
              </div>

              {/* Event Timeline Distribution */}
              {analysis.report.timeline_buckets.length > 0 && (
                <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/60">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-slate-700">
                      Per-Minute Event Distribution
                    </span>
                    <div className="flex items-center gap-4 text-xs text-slate-500">
                      <span className="inline-flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 bg-slate-300 inline-block" />
                        Total
                      </span>
                      <span className="inline-flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 bg-red-600 inline-block" />
                        Suspicious
                      </span>
                    </div>
                  </div>
                  <div className="flex items-end gap-1.5 h-20">
                    {analysis.report.timeline_buckets.map((bucket) => {
                      const totalPct = Math.max(8, Math.round((bucket.total / maxBucketTotal) * 100));
                      const suspPct =
                        bucket.total > 0 ? Math.round((bucket.suspicious / bucket.total) * 100) : 0;
                      const label = bucket.bucket.split(' ')[1] || bucket.bucket;
                      return (
                        <div
                          key={bucket.bucket}
                          title={`${bucket.bucket} UTC — ${bucket.total} events (${bucket.suspicious} suspicious)`}
                          className="flex-1 flex flex-col items-center gap-1 min-w-0"
                        >
                          <div className="w-full h-14 flex items-end bg-slate-100 rounded-sm overflow-hidden">
                            <div
                              style={{ height: `${totalPct}%` }}
                              className="w-full bg-slate-300 relative flex items-end"
                            >
                              {bucket.suspicious > 0 && (
                                <div
                                  style={{ height: `${suspPct}%` }}
                                  className="w-full bg-red-600"
                                />
                              )}
                            </div>
                          </div>
                          <span className="text-[11px] font-mono tabular-nums text-slate-500 truncate w-full text-center">
                            {label}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Sub-Navigation Bar for Report Views */}
              <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-slate-200">
                <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
                  <button
                    type="button"
                    onClick={() => setResultTab('findings')}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      resultTab === 'findings'
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Security Findings ({analysis.report.alerts.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setResultTab('ips')}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      resultTab === 'ips'
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Source IPs ({analysis.report.top_source_ips.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setResultTab('export')}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      resultTab === 'export'
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    CLI Output & Export
                  </button>
                </div>

                {resultTab === 'findings' && (
                  <div className="flex items-center gap-1">
                    {(['all', 'critical', 'high', 'medium'] as const).map((sev) => (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => setSeverityFilter(sev)}
                        className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          severityFilter === sev
                            ? 'bg-slate-900 text-white'
                            : 'text-slate-600 hover:bg-slate-100'
                        }`}
                      >
                        {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Findings View */}
              {resultTab === 'findings' && (
                <div className="flex-1 overflow-y-auto divide-y divide-slate-200 max-h-[420px]">
                  {filteredAlerts.length === 0 ? (
                    <div className="p-8 text-center text-sm text-slate-500">
                      No detections matched the active severity filter and threshold configuration.
                    </div>
                  ) : (
                    filteredAlerts.map((alert, idx) => {
                      const cfg = SEVERITY_CONFIG[alert.severity];
                      const SevIcon = cfg.Icon;
                      const isExpanded = expandedAlertIdx === idx;
                      return (
                        <div key={`${alert.rule_id}-${alert.source_ip}-${idx}`}>
                          <button
                            type="button"
                            onClick={() => setExpandedAlertIdx(isExpanded ? null : idx)}
                            className="w-full px-5 py-3.5 text-left hover:bg-slate-50 transition-colors flex items-start justify-between gap-4 cursor-pointer"
                          >
                            <div className="flex items-start gap-3 min-w-0">
                              <span className="mt-0.5 text-slate-400 shrink-0">
                                {isExpanded ? (
                                  <ChevronDown className="w-4 h-4" />
                                ) : (
                                  <ChevronRight className="w-4 h-4" />
                                )}
                              </span>
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs mb-1">
                                  <span className={`inline-flex items-center gap-1 font-semibold ${cfg.textClass}`}>
                                    <SevIcon className="w-3.5 h-3.5" />
                                    {cfg.label}
                                  </span>
                                  <span aria-hidden="true" className="text-slate-300">·</span>
                                  <span className="font-mono text-slate-700">{alert.mitre_id}</span>
                                  <span aria-hidden="true" className="text-slate-300">·</span>
                                  <span className="text-slate-500">{alert.mitre_tactic}</span>
                                </div>
                                <div className="text-sm font-semibold text-slate-900">
                                  {alert.title}
                                </div>
                                <div className="text-xs text-slate-600 mt-0.5 line-clamp-2">
                                  {alert.description}
                                </div>
                              </div>
                            </div>
                            <div className="text-right shrink-0">
                              <div className="text-xs font-mono tabular-nums font-medium text-slate-900">
                                {alert.source_ip}
                              </div>
                              <div className="text-xs font-mono tabular-nums text-slate-500 mt-0.5">
                                {alert.event_count} events
                              </div>
                            </div>
                          </button>

                          {isExpanded && (
                            <div className="px-5 pb-4 pl-12 space-y-3 bg-slate-50/70">
                              <div>
                                <div className="text-xs font-medium text-slate-700 mb-1.5">
                                  Matched Log Evidence
                                </div>
                                <div className="bg-slate-950 text-slate-200 rounded-md p-3 font-mono text-xs space-y-1 overflow-x-auto">
                                  {alert.evidence.map((evLine, i) => (
                                    <div key={i} className="whitespace-nowrap">
                                      {evLine}
                                    </div>
                                  ))}
                                </div>
                              </div>
                              <div className="text-xs text-slate-700">
                                <span className="font-semibold text-slate-900">Recommended Remediation: </span>
                                {alert.remediation}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* Source IPs View */}
              {resultTab === 'ips' && (
                <div className="flex-1 overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                        <th className="py-2.5 px-5">Source IP</th>
                        <th className="py-2.5 px-4">Log Sources</th>
                        <th className="py-2.5 px-4 text-right">Events</th>
                        <th className="py-2.5 px-5 text-right">Alerts</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 text-sm">
                      {analysis.report.top_source_ips.map((row) => (
                        <tr key={row.ip} className="hover:bg-slate-50">
                          <td className="py-2.5 px-5 font-mono tabular-nums text-slate-900 font-medium">
                            {row.ip}
                          </td>
                          <td className="py-2.5 px-4 text-xs text-slate-600">
                            {row.sources.join(' · ')}
                          </td>
                          <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-700">
                            {row.event_count}
                          </td>
                          <td
                            className={`py-2.5 px-5 text-right font-mono tabular-nums font-medium ${
                              row.alert_count > 0 ? 'text-red-700' : 'text-slate-500'
                            }`}
                          >
                            {row.alert_count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Export Output View */}
              {resultTab === 'export' && (
                <div className="flex-1 flex flex-col">
                  <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 bg-slate-50 border-b border-slate-200">
                    <div className="flex items-center gap-1">
                      {(['json', 'csv', 'markdown', 'text'] as ExportFormat[]).map((fmt) => (
                        <button
                          key={fmt}
                          type="button"
                          onClick={() => {
                            setExportFormat(fmt);
                            onRunAnalysis(fmt);
                          }}
                          className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            exportFormat === fmt
                              ? 'bg-slate-900 text-white'
                              : 'bg-white border border-slate-300 text-slate-700 hover:bg-slate-100'
                          }`}
                        >
                          {fmt.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleCopyExport}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded hover:bg-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        {copiedExport ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedExport ? 'Copied' : 'Copy Output'}
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadExport}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 rounded hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Save Report
                      </button>
                    </div>
                  </div>
                  <pre className="flex-1 p-4 bg-slate-950 text-slate-200 font-mono text-xs leading-5 overflow-auto max-h-[380px]">
                    {analysis.formattedExport}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
