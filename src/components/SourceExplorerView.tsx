import React, { useMemo, useState } from 'react';
import { Check, CheckCircle2, Copy, FileCode2, Play, XCircle } from 'lucide-react';
import type { ProjectFileEntry, TestRunResult } from '../types';
import { copyToClipboard } from '../utils/clipboard';

interface SourceExplorerViewProps {
  files: ProjectFileEntry[];
  isLoading: boolean;
}

export const SourceExplorerView: React.FC<SourceExplorerViewProps> = ({ files, isLoading }) => {
  const [selectedPath, setSelectedPath] = useState<string>('sentinel_log/detectors.py');
  const [copiedFile, setCopiedFile] = useState(false);
  const [testResult, setTestResult] = useState<TestRunResult | null>(null);
  const [isRunningTests, setIsRunningTests] = useState(false);

  const activeFile = useMemo(() => {
    return files.find((f) => f.path === selectedPath) || files[0] || null;
  }, [files, selectedPath]);

  const groupedFiles = useMemo(() => {
    const groups: Record<string, ProjectFileEntry[]> = {};
    for (const file of files) {
      const groupKey =
        file.directory === 'root'
          ? 'Root & Documentation'
          : `${file.directory}/`;
      if (!groups[groupKey]) groups[groupKey] = [];
      groups[groupKey].push(file);
    }
    return groups;
  }, [files]);

  const handleCopyCode = async () => {
    if (!activeFile) return;
    const copied = await copyToClipboard(activeFile.content);
    if (copied) {
      setCopiedFile(true);
      setTimeout(() => setCopiedFile(false), 1800);
    }
  };

  const handleRunUnitTests = async () => {
    setIsRunningTests(true);
    try {
      const res = await fetch('/api/run-tests', { method: 'POST' });
      const data = (await res.json()) as TestRunResult;
      setTestResult(data);
    } catch {
      setTestResult({
        passed: false,
        exitCode: 1,
        totalTests: 0,
        durationMs: 0,
        output: 'Failed to execute Python test runner.',
      });
    } finally {
      setIsRunningTests(false);
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white border border-slate-200 rounded-lg p-12 text-center text-sm text-slate-500">
        Loading Python project source tree...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Live Python Test Runner Banner */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900">
            Python 3.11 Package & Automated Test Suite
          </h2>
          <p className="text-sm text-slate-600 mt-0.5">
            Zero external runtime dependencies. Inspect every module below or execute the real{' '}
            <code className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded">unittest</code> suite directly on the server.
          </p>
        </div>

        <button
          type="button"
          onClick={handleRunUnitTests}
          disabled={isRunningTests}
          className="inline-flex items-center gap-2 h-10 px-4 text-sm font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Play className="w-4 h-4" />
          {isRunningTests ? 'Running unittest...' : 'Run Python Unit Tests'}
        </button>
      </div>

      {testResult && (
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-medium">
              {testResult.passed ? (
                <span className="inline-flex items-center gap-1.5 text-green-700">
                  <CheckCircle2 className="w-4 h-4" />
                  All {testResult.totalTests} unit tests passed
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-red-700">
                  <XCircle className="w-4 h-4" />
                  Test run failed (exit code {testResult.exitCode})
                </span>
              )}
              <span className="text-slate-300" aria-hidden="true">·</span>
              <span className="text-xs font-mono tabular-nums text-slate-500">
                {testResult.durationMs.toFixed(1)} ms
              </span>
            </div>
            <button
              type="button"
              onClick={() => setTestResult(null)}
              className="text-xs font-medium text-slate-500 hover:text-slate-900 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
          <pre className="p-4 bg-slate-950 text-slate-200 font-mono text-xs leading-5 overflow-x-auto">
            {testResult.output}
          </pre>
        </div>
      )}

      {/* IDE File Explorer + Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 bg-white border border-slate-200 rounded-lg overflow-hidden">
        <aside className="lg:col-span-3 border-b lg:border-b-0 lg:border-r border-slate-200 bg-slate-50/70 p-4 space-y-5">
          {Object.entries(groupedFiles).map(([groupName, groupEntries]) => (
            <div key={groupName}>
              <div className="text-xs font-semibold text-slate-500 mb-2 px-2">
                {groupName}
              </div>
              <div className="space-y-0.5">
                {groupEntries.map((file) => {
                  const isActive = activeFile?.path === file.path;
                  return (
                    <button
                      key={file.path}
                      type="button"
                      onClick={() => setSelectedPath(file.path)}
                      className={`w-full flex items-center justify-between gap-2 px-2.5 py-2 text-left text-xs rounded-md transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-slate-900 text-white font-medium'
                          : 'text-slate-700 hover:bg-slate-200/70'
                      }`}
                    >
                      <span className="inline-flex items-center gap-2 min-w-0 truncate font-mono">
                        <FileCode2 className="w-3.5 h-3.5 shrink-0 opacity-75" />
                        <span className="truncate">{file.name}</span>
                      </span>
                      <span
                        className={`font-mono tabular-nums text-[11px] shrink-0 ${
                          isActive ? 'text-slate-300' : 'text-slate-400'
                        }`}
                      >
                        {file.lines}L
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </aside>

        <div className="lg:col-span-9 flex flex-col min-w-0">
          {activeFile && (
            <>
              <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-slate-200 bg-white">
                <div className="flex items-center gap-2 text-xs text-slate-500 min-w-0">
                  <span className="font-mono font-semibold text-slate-900 truncate">
                    {activeFile.path}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">{activeFile.lines} lines</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">
                    {(activeFile.bytes / 1024).toFixed(1)} KB
                  </span>
                </div>

                <button
                  type="button"
                  onClick={handleCopyCode}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedFile ? (
                    <Check className="w-3.5 h-3.5 text-green-600" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  {copiedFile ? 'Copied' : 'Copy File'}
                </button>
              </div>

              <div className="bg-slate-950 text-slate-100 overflow-auto max-h-[620px]">
                <table className="w-full border-collapse font-mono text-xs leading-6">
                  <tbody>
                    {activeFile.content.split('\n').map((line, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/70">
                        <td className="select-none text-right pr-4 pl-4 text-slate-500 w-12 align-top tabular-nums">
                          {idx + 1}
                        </td>
                        <td className="pr-6 whitespace-pre text-slate-100">
                          {line || ' '}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
