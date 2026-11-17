import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';

const PORT = 3000;
const PYTHON_PROJECT_DIR = path.resolve(process.cwd(), 'python_project');

interface ProjectFileEntry {
  path: string;
  name: string;
  directory: string;
  language: string;
  lines: number;
  bytes: number;
  content: string;
}

function detectLanguage(filePath: string): string {
  if (filePath.endsWith('.py')) return 'python';
  if (filePath.endsWith('.md')) return 'markdown';
  if (filePath.endsWith('.toml')) return 'toml';
  if (filePath.endsWith('.log')) return 'log';
  return 'text';
}

async function collectProjectFiles(dir: string, baseDir: string): Promise<ProjectFileEntry[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const results: ProjectFileEntry[] = [];

  for (const entry of entries) {
    if (entry.name === '__pycache__' || entry.name.startsWith('.')) continue;
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      const nested = await collectProjectFiles(fullPath, baseDir);
      results.push(...nested);
    } else if (entry.isFile()) {
      const content = await fs.readFile(fullPath, 'utf-8');
      const dirName = path.dirname(relPath) === '.' ? 'root' : path.dirname(relPath);
      results.push({
        path: relPath,
        name: entry.name,
        directory: dirName,
        language: detectLanguage(relPath),
        lines: content.split('\n').length,
        bytes: Buffer.byteLength(content, 'utf-8'),
        content,
      });
    }
  }

  return results;
}

function runPythonProcess(
  args: string[],
  stdinData?: string
): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number }> {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    const child = spawn('python3', args, {
      cwd: PYTHON_PROJECT_DIR,
      env: {
        ...process.env,
        PYTHONPATH: PYTHON_PROJECT_DIR,
        PYTHONDONTWRITEBYTECODE: '1',
      },
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, 10_000);

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf-8');
    });

    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf-8');
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      const durationMs = Math.round((performance.now() - start) * 100) / 100;
      if (timedOut) {
        reject(new Error('Python execution timed out after 10 seconds.'));
        return;
      }
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 1,
        durationMs,
      });
    });

    if (stdinData !== undefined) {
      child.stdin.write(stdinData);
    }
    child.stdin.end();
  });
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '5mb' }));

  app.get('/api/project-files', async (_req, res) => {
    try {
      const files = await collectProjectFiles(PYTHON_PROJECT_DIR, PYTHON_PROJECT_DIR);
      const orderWeight = (filePath: string) => {
        if (filePath === 'README.md') return 0;
        if (filePath === 'pyproject.toml') return 1;
        if (filePath === 'requirements.txt') return 2;
        if (filePath.startsWith('sentinel_log/')) return 3;
        if (filePath.startsWith('tests/')) return 4;
        if (filePath.startsWith('samples/')) return 5;
        return 6;
      };
      files.sort((a, b) => {
        const diff = orderWeight(a.path) - orderWeight(b.path);
        return diff !== 0 ? diff : a.path.localeCompare(b.path);
      });
      res.json({ files });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to load Python project files',
      });
    }
  });

  app.post('/api/analyze', async (req, res) => {
    try {
      const {
        logs,
        format = 'json',
        bfThreshold = 5,
        windowSeconds = 120,
        portThreshold = 5,
        zThreshold = 2.0,
      } = req.body as {
        logs?: string;
        format?: 'json' | 'csv' | 'markdown' | 'text';
        bfThreshold?: number;
        windowSeconds?: number;
        portThreshold?: number;
        zThreshold?: number;
      };

      if (typeof logs !== 'string' || !logs.trim()) {
        res.status(400).json({ error: 'Log input cannot be empty.' });
        return;
      }

      const safeFormat = ['json', 'csv', 'markdown', 'text'].includes(format) ? format : 'json';
      const bfVal = Math.max(1, Math.min(100, Number(bfThreshold) || 5));
      const winVal = Math.max(5, Math.min(86400, Number(windowSeconds) || 120));
      const portVal = Math.max(2, Math.min(1000, Number(portThreshold) || 5));
      const zVal = Math.max(0.5, Math.min(10, Number(zThreshold) || 2.0));

      const baseArgs = [
        '-m',
        'sentinel_log.cli',
        '-i',
        '-',
        '--bf-threshold',
        String(bfVal),
        '--window',
        String(winVal),
        '--port-threshold',
        String(portVal),
        '--z-threshold',
        String(zVal),
      ];

      const jsonResult = await runPythonProcess([...baseArgs, '-f', 'json'], logs);
      if (jsonResult.exitCode !== 0) {
        res.status(500).json({ error: jsonResult.stderr || 'Python analysis failed.' });
        return;
      }

      const report = JSON.parse(jsonResult.stdout);

      let formattedExport = jsonResult.stdout;
      if (safeFormat !== 'json') {
        const exportResult = await runPythonProcess([...baseArgs, '-f', safeFormat], logs);
        if (exportResult.exitCode === 0) {
          formattedExport = exportResult.stdout;
        }
      }

      res.json({
        report,
        formattedExport,
        format: safeFormat,
        cliCommand: `python3 -m sentinel_log.cli -i incident.log -f ${safeFormat} --bf-threshold ${bfVal} --window ${winVal} --port-threshold ${portVal} --z-threshold ${zVal}`,
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unexpected analysis error',
      });
    }
  });

  app.post('/api/run-tests', async (_req, res) => {
    try {
      const result = await runPythonProcess([
        '-m',
        'unittest',
        'discover',
        '-s',
        'tests',
        '-t',
        '.',
        '-v',
      ]);
      const combinedOutput = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
      const match = combinedOutput.match(/Ran (\d+) tests?/);
      const total = match ? Number(match[1]) : 0;
      res.json({
        passed: result.exitCode === 0,
        exitCode: result.exitCode,
        totalTests: total,
        durationMs: result.durationMs,
        output: combinedOutput,
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to run Python unit tests',
      });
    }
  });

  app.get('/api/download-project', async (_req, res) => {
    try {
      const zipScript = `
import io, os, sys, zipfile
root = sys.argv[1]
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__" and not d.startswith(".")]
        for fname in sorted(filenames):
            if fname.endswith(".pyc"):
                continue
            full = os.path.join(dirpath, fname)
            arc = os.path.join("sentinel-log", os.path.relpath(full, root))
            zf.write(full, arc)
sys.stdout.buffer.write(buf.getvalue())
`.trim();

      const child = spawn('python3', ['-c', zipScript, PYTHON_PROJECT_DIR]);
      const chunks: Buffer[] = [];
      let stderr = '';

      child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf-8');
      });

      child.on('close', (code) => {
        if (code !== 0) {
          res.status(500).json({ error: stderr || 'Failed to package Python project' });
          return;
        }
        const zipBuffer = Buffer.concat(chunks);
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename="sentinel-log-python.zip"');
        res.setHeader('Content-Length', String(zipBuffer.length));
        res.send(zipBuffer);
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to download project archive',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelLog workbench listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
