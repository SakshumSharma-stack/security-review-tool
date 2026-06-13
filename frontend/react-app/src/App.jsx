import { useState, useCallback } from 'react';
import './App.css';

const API_URL = 'https://security-review-sakshum.lemonriver-d0f61589.eastus.azurecontainerapps.io';

const LANGUAGES = [
  'python', 'javascript', 'java', 'typescript',
  'go', 'ruby', 'php', 'csharp', 'cpp', 'other',
];

const SEVERITY_CONFIG = {
  CRITICAL: { icon: '🔴', color: '#dc2626' },
  HIGH:     { icon: '🟠', color: '#ea580c' },
  MEDIUM:   { icon: '🟡', color: '#ca8a04' },
  LOW:      { icon: '🔵', color: '#2563eb' },
};

const CONFIDENCE_CONFIG = {
  HIGH:   { label: '🟢 High confidence',   color: '#16a34a', bg: '#f0fdf4' },
  MEDIUM: { label: '🟡 Medium confidence', color: '#ca8a04', bg: '#fefce8' },
  LOW:    { label: '🔴 Low confidence',    color: '#dc2626', bg: '#fef2f2' },
};

// ── Sub-components ───────────────────────────────────────────────────────────

function VulnerabilityCard({ vuln }) {
  const [expanded, setExpanded] = useState(false);
  const sev  = SEVERITY_CONFIG[vuln.severity]  ?? { icon: '⚪', color: '#6b7280' };
  const conf = CONFIDENCE_CONFIG[vuln.confidence ?? 'HIGH'] ?? CONFIDENCE_CONFIG.HIGH;

  return (
    <div className="vuln-card" style={{ borderLeftColor: sev.color }}>
      <button className="vuln-header" onClick={() => setExpanded(e => !e)}>
        <span className="vuln-title">
          <span className="sev-icon">{sev.icon}</span>
          <span className="sev-label" style={{ color: sev.color }}>{vuln.severity}</span>
          <span className="vuln-name">{vuln.name}</span>
        </span>
        <span className="vuln-meta">
          <span className="conf-badge" style={{ color: conf.color, background: conf.bg }}>
            {conf.label}
          </span>
          <span className="expand-icon">{expanded ? '▲' : '▼'}</span>
        </span>
      </button>

      {expanded && (
        <div className="vuln-body">
          <div className="vuln-row">
            <span className="label">Rule:</span>
            <code>{vuln.rule_id}</code>
          </div>
          <div className="vuln-row">
            <span className="label">OWASP Category:</span>
            <span>{vuln.owasp_category}</span>
          </div>
          {vuln.confidence === 'LOW' && (
            <div className="warning-banner">⚠️ Needs human review</div>
          )}
          <div className="vuln-row col">
            <span className="label">Explanation:</span>
            <p>{vuln.explanation}</p>
          </div>
          <div className="vuln-row col">
            <span className="label">Vulnerable Snippet:</span>
            <pre className="code-block small"><code>{vuln.vulnerable_snippet}</code></pre>
          </div>
        </div>
      )}
    </div>
  );
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <button className="copy-btn" onClick={handleCopy}>
      {copied ? '✅ Copied!' : '📋 Copy'}
    </button>
  );
}

function HistoryRow({ scan }) {
  const [expanded, setExpanded] = useState(false);
  const vulnCount = Array.isArray(scan.vulnerabilities_found)
    ? scan.vulnerabilities_found.length
    : 0;
  const ts = scan.timestamp
    ? new Date(scan.timestamp).toLocaleString()
    : '—';

  return (
    <>
      <tr className="history-row" onClick={() => setExpanded(e => !e)}>
        <td>{ts}</td>
        <td className="vuln-count-cell">{vulnCount}</td>
        <td className="summary-cell">
          {scan.summary
            ? scan.summary.slice(0, 120) + (scan.summary.length > 120 ? '…' : '')
            : '—'}
        </td>
        <td className="expand-cell">{expanded ? '▲' : '▼'}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={4}>
            <div className="history-detail">
              <p><strong>Summary:</strong> {scan.summary}</p>
              <p><strong>Code snippet:</strong></p>
              <pre className="code-block small">
                <code>
                  {scan.code_snippet
                    ? scan.code_snippet.slice(0, 600) + (scan.code_snippet.length > 600 ? '\n…' : '')
                    : '(none)'}
                </code>
              </pre>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [activeTab,     setActiveTab]     = useState('scan');
  const [apiKey,        setApiKey]        = useState('');
  const [code,          setCode]          = useState('');
  const [language,      setLanguage]      = useState('python');
  const [scanning,      setScanning]      = useState(false);
  const [scanError,     setScanError]     = useState(null);
  const [result,        setResult]        = useState(null);
  const [history,       setHistory]       = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError,  setHistoryError]  = useState(null);

  const handleScan = useCallback(async () => {
    if (!code.trim()) {
      setScanError('Please paste some code first.');
      return;
    }
    setScanError(null);
    setResult(null);
    setScanning(true);

    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey,
        },
        body: JSON.stringify({ code, language }),
      });

      if (res.status === 401) throw new Error('Invalid or missing API key.');
      if (res.status === 429) throw new Error('Rate limit exceeded. Try again later.');
      if (res.status === 400) {
        const d = await res.json();
        throw new Error(d.detail ?? 'Bad request');
      }
      if (!res.ok) throw new Error(`Server error (${res.status})`);

      setResult(await res.json());
    } catch (e) {
      setScanError(e.message);
    } finally {
      setScanning(false);
    }
  }, [code, language, apiKey]);

  const loadHistory = useCallback(async () => {
    setHistoryError(null);
    setHistoryLoading(true);

    try {
      const res = await fetch(`${API_URL}/history`, {
        headers: { 'X-API-Key': apiKey },
      });

      if (res.status === 401) throw new Error('Invalid or missing API key.');
      if (!res.ok) throw new Error(`Server error (${res.status})`);

      setHistory(await res.json());
    } catch (e) {
      setHistoryError(e.message);
    } finally {
      setHistoryLoading(false);
    }
  }, [apiKey]);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    if (tab === 'history' && history === null) loadHistory();
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>🔐 Security Review Tool</h1>
        <div className="api-key-row">
          <label htmlFor="apiKey">API Key</label>
          <input
            id="apiKey"
            type="password"
            placeholder="Enter your API key"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            className="api-key-input"
          />
        </div>
      </header>

      <nav className="tabs">
        <button
          className={`tab ${activeTab === 'scan' ? 'active' : ''}`}
          onClick={() => handleTabChange('scan')}
        >
          Scan
        </button>
        <button
          className={`tab ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => handleTabChange('history')}
        >
          History
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'scan' && (
          <div className="scan-tab">
            <div className="input-row">
              <label htmlFor="lang">Language</label>
              <select
                id="lang"
                value={language}
                onChange={e => setLanguage(e.target.value)}
                className="lang-select"
              >
                {LANGUAGES.map(l => (
                  <option key={l} value={l}>{l}</option>
                ))}
              </select>
            </div>

            <textarea
              className="code-input"
              placeholder="Paste your code here..."
              value={code}
              onChange={e => setCode(e.target.value)}
              spellCheck={false}
            />

            <button
              className="scan-btn"
              onClick={handleScan}
              disabled={scanning}
            >
              {scanning ? '⏳ Scanning…' : '🔍 Scan'}
            </button>

            {scanError && (
              <div className="error-banner">❌ {scanError}</div>
            )}

            {result && (
              <div className="results">
                <section className="result-section">
                  <h2>Summary</h2>
                  <div className="summary-box">
                    {result.summary || 'No summary returned.'}
                  </div>
                </section>

                <section className="result-section">
                  <h2>Vulnerabilities ({result.vulnerabilities?.length ?? 0} found)</h2>
                  {result.vulnerabilities?.length === 0 ? (
                    <div className="success-banner">✅ No vulnerabilities detected.</div>
                  ) : (
                    <div className="vuln-list">
                      {result.vulnerabilities.map((v, i) => (
                        <VulnerabilityCard key={i} vuln={v} />
                      ))}
                    </div>
                  )}
                </section>

                <section className="result-section">
                  <h2>Fixed Code</h2>
                  {result.fixed_code ? (
                    <div className="fixed-code-wrapper">
                      <div className="fixed-code-toolbar">
                        <span className="lang-tag">{language}</span>
                        <CopyButton text={result.fixed_code} />
                      </div>
                      <pre className="code-block large">
                        <code>{result.fixed_code}</code>
                      </pre>
                    </div>
                  ) : (
                    <p className="muted">No fixed code returned.</p>
                  )}
                </section>
              </div>
            )}
          </div>
        )}

        {activeTab === 'history' && (
          <div className="history-tab">
            <div className="history-toolbar">
              <h2>Scan History</h2>
              <button
                className="refresh-btn"
                onClick={loadHistory}
                disabled={historyLoading}
              >
                {historyLoading ? '⏳ Loading…' : '🔄 Refresh'}
              </button>
            </div>

            {historyError && (
              <div className="error-banner">❌ {historyError}</div>
            )}

            {!historyError && history === null && (
              <p className="muted">Loading history…</p>
            )}

            {history !== null && history.length === 0 && (
              <p className="muted">No scan history found.</p>
            )}

            {history !== null && history.length > 0 && (
              <table className="history-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Vulns</th>
                    <th>Summary</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {history.map(scan => (
                    <HistoryRow key={scan.id} scan={scan} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
