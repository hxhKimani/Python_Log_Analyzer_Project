import { useCallback, useEffect, useMemo, useState } from 'react';
import { Download } from 'lucide-react';
import { AnalyzerView } from './components/AnalyzerView';
import { BuildGuideView } from './components/BuildGuideView';
import { ResumeKitView } from './components/ResumeKitView';
import { SourceExplorerView } from './components/SourceExplorerView';
import type { ActiveTab, AnalyzeResponse, ExportFormat, ProjectFileEntry } from './types';

const NAV_ITEMS: { id: ActiveTab; label: string }[] = [
  { id: 'analyzer', label: 'Analyzer' },
  { id: 'source', label: 'Python Source' },
  { id: 'guide', label: 'Build Guide' },
  { id: 'resume', label: 'Resume Kit' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('analyzer');
  const [projectFiles, setProjectFiles] = useState<ProjectFileEntry[]>([]);
  const [filesLoading, setFilesLoading] = useState<boolean>(true);

  const [logText, setLogText] = useState<string>('');
  const [bfThreshold, setBfThreshold] = useState<number>(5);
  const [windowSeconds, setWindowSeconds] = useState<number>(120);
  const [portThreshold, setPortThreshold] = useState<number>(5);
  const [zThreshold, setZThreshold] = useState<number>(2.0);
  const [exportFormat, setExportFormat] = useState<ExportFormat>('json');

  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  const sampleFiles = useMemo(
    () => projectFiles.filter((f) => f.directory === 'samples'),
    [projectFiles]
  );

  const runAnalysis = useCallback(
    async (
      logsToRun: string,
      formatToRun: ExportFormat,
      thresholds: { bf: number; win: number; port: number; z: number }
    ) => {
      if (!logsToRun.trim()) return;
      setIsAnalyzing(true);
      setAnalysisError(null);
      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            logs: logsToRun,
            format: formatToRun,
            bfThreshold: thresholds.bf,
            windowSeconds: thresholds.win,
            portThreshold: thresholds.port,
            zThreshold: thresholds.z,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Python analysis failed');
        }
        setAnalysis(data as AnalyzeResponse);
      } catch (err) {
        setAnalysisError(err instanceof Error ? err.message : 'Unable to execute Python analyzer');
      } finally {
        setIsAnalyzing(false);
      }
    },
    []
  );

  useEffect(() => {
    let active = true;
    async function bootstrap() {
      try {
        const res = await fetch('/api/project-files');
        const data = (await res.json()) as { files: ProjectFileEntry[] };
        if (!active) return;
        const files = data.files || [];
        setProjectFiles(files);

        const initialSample = files
          .filter((f) => f.directory === 'samples')
          .map((f) => f.content.trim())
          .join('\n');

        if (initialSample) {
          setLogText(initialSample);
          await runAnalysis(initialSample, 'json', {
            bf: 5,
            win: 120,
            port: 5,
            z: 2.0,
          });
        }
      } catch {
        if (active) {
          setAnalysisError('Failed to load Python project files from backend.');
        }
      } finally {
        if (active) setFilesLoading(false);
      }
    }
    bootstrap();
    return () => {
      active = false;
    };
  }, [runAnalysis]);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* Three-Zone Top Navigation Bar */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-20">
        <div className="max-w-[1360px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-8">
          <button
            type="button"
            onClick={() => setActiveTab('analyzer')}
            className="text-lg font-display font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 cursor-pointer"
          >
            SentinelLog
          </button>

          <nav aria-label="Primary navigation" className="flex items-center gap-6 overflow-x-auto">
            {NAV_ITEMS.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`py-5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    isActive
                      ? 'border-slate-900 text-slate-900'
                      : 'border-transparent text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          <div className="shrink-0">
            <a
              href="/api/download-project"
              download="sentinel-log-python.zip"
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Download Python (.zip)
            </a>
          </div>
        </div>
      </header>

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-[1360px] w-full mx-auto px-4 sm:px-6 py-8">
        <div className="mb-6">
          <h1 className="text-2xl sm:text-3xl font-display font-semibold tracking-tight text-slate-900 [text-wrap:balance]">
            {activeTab === 'analyzer' && 'Python Cybersecurity Log Analyzer Workbench'}
            {activeTab === 'source' && 'Modular Python 3.11 Source & Unit Tests'}
            {activeTab === 'guide' && 'Build From Scratch Architecture Guide'}
            {activeTab === 'resume' && 'Cybersecurity Resume & Interview Kit'}
          </h1>
          <p className="mt-1.5 text-sm text-slate-600 max-w-3xl">
            {activeTab === 'analyzer' &&
              'Test the live Python detection engine against SSH authentication, web server, and firewall logs with MITRE ATT&CK enrichment.'}
            {activeTab === 'source' &&
              'Browse every Python module, inspect sample attack telemetry, and execute the unittest suite on the server.'}
            {activeTab === 'guide' &&
              'Understand the streaming parsers, sliding-window correlation, and URL normalization patterns powering this project.'}
            {activeTab === 'resume' &&
              'Tailor ATS-ready cybersecurity bullet points and prepare for technical architecture follow-up questions.'}
          </p>
        </div>

        {activeTab === 'analyzer' && (
          <AnalyzerView
            sampleFiles={sampleFiles}
            logText={logText}
            setLogText={setLogText}
            bfThreshold={bfThreshold}
            setBfThreshold={setBfThreshold}
            windowSeconds={windowSeconds}
            setWindowSeconds={setWindowSeconds}
            portThreshold={portThreshold}
            setPortThreshold={setPortThreshold}
            zThreshold={zThreshold}
            setZThreshold={setZThreshold}
            exportFormat={exportFormat}
            setExportFormat={setExportFormat}
            analysis={analysis}
            isAnalyzing={isAnalyzing}
            error={analysisError}
            onRunAnalysis={(overrideFormat) =>
              runAnalysis(logText, overrideFormat ?? exportFormat, {
                bf: bfThreshold,
                win: windowSeconds,
                port: portThreshold,
                z: zThreshold,
              })
            }
          />
        )}

        {activeTab === 'source' && (
          <SourceExplorerView files={projectFiles} isLoading={filesLoading} />
        )}

        {activeTab === 'guide' && (
          <BuildGuideView onOpenSourceTab={() => setActiveTab('source')} />
        )}

        {activeTab === 'resume' && <ResumeKitView />}
      </main>
    </div>
  );
}
