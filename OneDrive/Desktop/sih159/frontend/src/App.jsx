import React, { useState, useRef, useEffect, useMemo } from 'react'
import axios from 'axios'
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, AreaChart, Area
} from 'recharts'

// Severity and Status Color Constants
const SEV_COLORS = {
  critical: '#ff595e',
  high: '#ff924c',
  medium: '#ffca3a',
  low: '#1982c4',
  info: '#8ac926',
  safe: '#38a856',
}

const STATUS_COLORS = {
  PASS: '#38a856',
  FAIL: '#ff595e',
  'N/A': '#767270'
}

const VERDICT_COLORS = {
  COMPLIANT: '#38a856',
  'NON-COMPLIANT': '#ff595e',
  'N/A': '#767270'
}

const PROTOCOL_COLORS = {
  SMTP: '#ff924c',
  IMAP: '#6a4c93',
  POP3: '#1982c4',
  UNKNOWN: '#767270'
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function getPostureRating(score) {
  if (score === null || score === undefined) return { label: 'Unknown', color: '#767270' }
  if (score >= 85) return { label: 'Hardened', color: '#38a856', grade: 'A' }
  if (score >= 70) return { label: 'Adequate', color: '#1982c4', grade: 'B' }
  if (score >= 50) return { label: 'Moderate Risk', color: '#ffca3a', grade: 'C' }
  if (score >= 30) return { label: 'High Risk', color: '#ff924c', grade: 'D' }
  return { label: 'Critical Risk', color: '#ff595e', grade: 'F' }
}

/* ─── Animated Radial SVG Progress Ring ─── */
function PostureRing({ score, size = 54, strokeWidth = 5 }) {
  const rating = getPostureRating(score)
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const pct = Math.max(0, Math.min(100, score ?? 0))
  const offset = circumference - (pct / 100) * circumference
  const gradeSize = size < 44 ? 14 : size < 60 ? 17 : 22

  return (
    <div className="posture-ring-wrap" style={{ width: size, height: size }} title={`${rating.label} — ${score ?? '—'}/100`}>
      <svg className="posture-ring-svg" width={size} height={size}>
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={radius} strokeWidth={strokeWidth} />
        <circle
          className="ring-fill"
          cx={size / 2} cy={size / 2} r={radius}
          strokeWidth={strokeWidth}
          stroke={rating.color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ '--ring-circumference': circumference, '--ring-offset': offset }}
        />
      </svg>
      <div className="posture-ring-label">
        <span className="posture-ring-grade" style={{ fontSize: gradeSize, color: rating.color }}>
          {rating.grade || '?'}
        </span>
        {size >= 50 && <span className="posture-ring-score">{score ?? '—'}</span>}
      </div>
    </div>
  )
}

/* ─── Interactive Certificate Chain Visualizer ─── */
function CertChainVisualizer({ certificate }) {
  const [activeNode, setActiveNode] = useState(null)
  if (!certificate) return null

  const issuer = certificate.issuer || 'Unknown Issuer'
  const subject = certificate.subject || 'Unknown Subject'
  const isRootSelfSigned = certificate.self_signed

  // Build chain: if self-signed → [Root/Leaf], otherwise → [Root CA, Intermediate (optional), Leaf]
  const nodes = []
  if (!isRootSelfSigned) {
    // Approximate: issuer is the CA (could be root or intermediate)
    nodes.push({
      id: 'root',
      label: 'Root CA',
      cn: issuer.split(',')[0]?.replace(/^CN=/i, '') || issuer,
      icon: '🏛️',
      iconClass: 'root',
    })
    // If issuer !== subject, add intermediate inference
    if (issuer !== subject) {
      nodes.push({
        id: 'intermediate',
        label: 'Issuer CA',
        cn: issuer.split(',')[0]?.replace(/^CN=/i, '') || issuer,
        icon: '🔗',
        iconClass: 'intermediate',
        detail: certificate.public_key_algorithm || '',
      })
    }
  }
  nodes.push({
    id: 'leaf',
    label: isRootSelfSigned ? 'Self-Signed' : 'Leaf Cert',
    cn: subject.split(',')[0]?.replace(/^CN=/i, '') || subject,
    icon: '📜',
    iconClass: 'leaf',
    detail: [
      certificate.public_key_algorithm,
      certificate.key_size ? `${certificate.key_size}-bit` : '',
    ].filter(Boolean).join(' '),
    validity: certificate.expired
      ? 'EXPIRED'
      : certificate.days_to_expiry != null
        ? `${certificate.days_to_expiry}d left`
        : 'Valid',
    validityColor: certificate.expired ? '#ff595e' : '#38a856',
    sans: certificate.san_list || certificate.sans || [],
  })

  return (
    <div className="cert-chain-container">
      {nodes.map((node, idx) => (
        <React.Fragment key={node.id}>
          {idx > 0 && (
            <div className="cert-connector">
              <div className="cert-connector-line" />
              <span className="cert-connector-arrow">›</span>
            </div>
          )}
          <div className={`cert-node ${activeNode === node.id ? 'active' : ''}`} onClick={() => setActiveNode(activeNode === node.id ? null : node.id)}>
            <div className="cert-node-box">
              <div className={`cert-node-icon ${node.iconClass}`}>{node.icon}</div>
              <div className="cert-node-label">{node.label}</div>
              <div className="cert-node-cn">{node.cn}</div>
              {node.detail && <div className="cert-node-detail">{node.detail}</div>}
              {node.validity && (
                <div className="cert-node-detail" style={{ color: node.validityColor, fontWeight: 700 }}>
                  {node.validity}
                </div>
              )}
              {node.sans && node.sans.length > 0 && activeNode === node.id && (
                <details className="cert-san-list" open>
                  <summary>SANs ({node.sans.length})</summary>
                  <ul>
                    {node.sans.slice(0, 8).map((san, i) => <li key={i}>{san}</li>)}
                    {node.sans.length > 8 && <li style={{ color: 'var(--text-muted)' }}>+{node.sans.length - 8} more…</li>}
                  </ul>
                </details>
              )}
            </div>
          </div>
        </React.Fragment>
      ))}
    </div>
  )
}

/* ─── Comparison View Modal ─── */
function ComparisonView({ scans, onClose }) {
  if (!scans || scans.length !== 2) return null
  const [left, right] = scans

  const metrics = [
    { label: 'Posture Score', leftVal: left.avg_posture_score, rightVal: right.avg_posture_score, unit: '/100', higherBetter: true },
    { label: 'Sessions', leftVal: left.session_count, rightVal: right.session_count, unit: '', higherBetter: null },
    { label: 'Critical Flaws', leftVal: left.critical_findings, rightVal: right.critical_findings, unit: '', higherBetter: false },
    { label: 'High Flaws', leftVal: left.high_findings, rightVal: right.high_findings, unit: '', higherBetter: false },
    { label: 'Medium Flaws', leftVal: left.medium_findings, rightVal: right.medium_findings, unit: '', higherBetter: false },
  ]

  const getDelta = (l, r, higherBetter) => {
    if (l === r) return { cls: 'same', text: '=' }
    if (higherBetter === null) return { cls: 'same', text: l > r ? '↑' : '↓' }
    const better = higherBetter ? r > l : r < l
    return { cls: better ? 'better' : 'worse', text: better ? '↑' : '↓' }
  }

  return (
    <div className="compare-modal-backdrop" onClick={onClose}>
      <div className="compare-modal-card" onClick={e => e.stopPropagation()}>
        <div className="compare-modal-header">
          <h2>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M16 3h5v5M8 3H3v5M3 16v5h5M21 16v5h-5M12 3v18M3 12h18" /></svg>
            Side-by-Side Posture Comparison
          </h2>
          <button className="copy-mini-btn" style={{ fontSize: '16px', padding: '4px 8px' }} onClick={onClose}>✕</button>
        </div>

        <div className="compare-grid">
          <div className="compare-column">
            <PostureRing score={left.avg_posture_score} size={80} strokeWidth={7} />
            <div className="compare-column-title">{left.target_name}</div>
            <div className="compare-column-subtitle">{left.scan_type?.toUpperCase()} · {left.timestamp?.slice(0, 10)}</div>
          </div>
          <div className="compare-vs-divider">
            <div className="compare-vs-badge">VS</div>
          </div>
          <div className="compare-column">
            <PostureRing score={right.avg_posture_score} size={80} strokeWidth={7} />
            <div className="compare-column-title">{right.target_name}</div>
            <div className="compare-column-subtitle">{right.scan_type?.toUpperCase()} · {right.timestamp?.slice(0, 10)}</div>
          </div>
        </div>

        <div className="compare-metrics-table">
          {metrics.map(m => {
            const delta = getDelta(m.leftVal, m.rightVal, m.higherBetter)
            return (
              <div key={m.label} className="compare-metric-row">
                <div className="compare-metric-val left" style={{ color: delta.cls === 'worse' ? '#ff595e' : delta.cls === 'better' ? '#38a856' : 'var(--text-primary)' }}>
                  {m.leftVal ?? '—'}{m.unit}
                </div>
                <div className={`compare-delta ${delta.cls}`}>{delta.text}</div>
                <div className="compare-metric-label">{m.label}</div>
                <div className={`compare-delta ${delta.cls}`}>{delta.text}</div>
                <div className="compare-metric-val right" style={{ color: delta.cls === 'better' ? '#38a856' : delta.cls === 'worse' ? '#ff595e' : 'var(--text-primary)' }}>
                  {m.rightVal ?? '—'}{m.unit}
                </div>
              </div>
            )
          })}
        </div>

        <div style={{ padding: '0 24px 20px', textAlign: 'center' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {left.avg_posture_score > right.avg_posture_score
              ? `⬆ "${left.target_name}" scores ${(left.avg_posture_score - right.avg_posture_score).toFixed(1)} points higher`
              : left.avg_posture_score < right.avg_posture_score
                ? `⬆ "${right.target_name}" scores ${(right.avg_posture_score - left.avg_posture_score).toFixed(1)} points higher`
                : '⬌ Both scans have identical posture scores'}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function App() {
  // Core Data State
  const [file, setFile] = useState(null)
  const [useML, setUseML] = useState(true)
  const [maxSessions, setMaxSessions] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [jobId, setJobId] = useState(null)
  const [overall, setOverall] = useState(null)
  const [sessions, setSessions] = useState([])
  const [expandedSessions, setExpandedSessions] = useState(new Set())
  const [detailCache, setDetailCache] = useState({})
  const [activeTab, setActiveTab] = useState('analysis')
  const [copiedKey, setCopiedKey] = useState(null)
  const [isDragOver, setIsDragOver] = useState(false)

  // Interactive Filter & Search State
  const [searchQuery, setSearchQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('ALL')
  const [protocolFilter, setProtocolFilter] = useState('ALL')
  const [kpiFilter, setKpiFilter] = useState('ALL') // 'ALL' | 'ENCRYPTED' | 'PLAINTEXT' | 'ANOMALIES'
  const [sortOption, setSortOption] = useState('score_asc')

  // Compliance State
  const [compliance, setCompliance] = useState(null)
  const [complianceLoading, setComplianceLoading] = useState(false)
  const [complianceSearch, setComplianceSearch] = useState('')
  const [complianceStatusFilter, setComplianceStatusFilter] = useState('ALL')

  // Tools & Diagnostics State
  const [interfaces, setInterfaces] = useState([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [liveDuration, setLiveDuration] = useState(15)
  const [liveCapturing, setLiveCapturing] = useState(false)
  const [captureRemaining, setCaptureRemaining] = useState(0)
  const [wsConnected, setWsConnected] = useState(false)
  const [simulationMode, setSimulationMode] = useState(false)
  const [livePackets, setLivePackets] = useState([])
  const [liveSessions, setLiveSessions] = useState([])
  const [liveStats, setLiveStats] = useState({ packets: 0, bytes: 0, sessions: 0, elapsed: 0 })
  const [liveCompletedJob, setLiveCompletedJob] = useState(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [liveProtocolFilter, setLiveProtocolFilter] = useState('all')
  const [liveEngine, setLiveEngine] = useState('scapy')
  const [liveNotice, setLiveNotice] = useState(null)
  const wsRef = useRef(null)
  const terminalBodyRef = useRef(null)

  const [mlStatus, setMlStatus] = useState(null)
  const [mlStatusError, setMlStatusError] = useState(null)
  const [mlEval, setMlEval] = useState(null)
  const [mlEvaluating, setMlEvaluating] = useState(false)
  const [mlTraining, setMlTraining] = useState(false)
  const [trainSource, setTrainSource] = useState('synthetic')
  const [trainCsvFile, setTrainCsvFile] = useState(null)
  const [trainNPerClass, setTrainNPerClass] = useState(500)
  const [trainBaselineN, setTrainBaselineN] = useState(1500)
  const [trainResult, setTrainResult] = useState(null)

  const [diagnostics, setDiagnostics] = useState(null)
  const [diagnosticsError, setDiagnosticsError] = useState(null)
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false)

  // Hardening Modal State
  const [hardeningModalOpen, setHardeningModalOpen] = useState(false)
  const [hardeningSessionId, setHardeningSessionId] = useState(null)
  const [hardeningData, setHardeningData] = useState(null)
  const [hardeningLoading, setHardeningLoading] = useState(false)
  const [activeHardeningTab, setActiveHardeningTab] = useState('postfix')

  // Webhook Alerts State
  const [webhookModalOpen, setWebhookModalOpen] = useState(false)
  const [webhookUrl, setWebhookUrl] = useState('')
  const [webhookProvider, setWebhookProvider] = useState('slack')
  const [webhookMinSev, setWebhookMinSev] = useState('high')
  const [webhookTestResult, setWebhookTestResult] = useState(null)
  const [webhookTesting, setWebhookTesting] = useState(false)

  // Standout Features State: Domain Probe, Executive Summary, Email Auth, Trends & History
  const [scanMode, setScanMode] = useState('pcap') // 'pcap' | 'domain'
  const [targetDomain, setTargetDomain] = useState('')
  const [probingDomain, setProbingDomain] = useState(false)
  const [domainProbeStatus, setDomainProbeStatus] = useState('')
  const [emailAuth, setEmailAuth] = useState(null)
  const [executiveSummary, setExecutiveSummary] = useState(null)
  const [execSummaryLoading, setExecSummaryLoading] = useState(false)
  const [showRoadmap, setShowRoadmap] = useState(false)
  const [historyScans, setHistoryScans] = useState([])
  const [historyTrends, setHistoryTrends] = useState(null)
  const [historyLoading, setHistoryLoading] = useState(false)

  // Comparison Mode State
  const [compareMode, setCompareMode] = useState(false)
  const [compareSelections, setCompareSelections] = useState(new Set())
  const [compareModalOpen, setCompareModalOpen] = useState(false)

  const fileInputRef = useRef(null)

  // Copy-to-clipboard feedback
  const copyToClipboard = (text, key) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 1800)
  }

  const openHardeningModal = async (sessionId) => {
    setHardeningSessionId(sessionId)
    setHardeningModalOpen(true)
    setHardeningLoading(true)
    try {
      const resp = await axios.get(`/api/sessions/${sessionId}/hardening`)
      setHardeningData(resp.data)
      setActiveHardeningTab('postfix')
    } catch (e) {
      console.error('Failed to load hardening config:', e)
    } finally {
      setHardeningLoading(false)
    }
  }

  const doTestWebhook = async () => {
    setWebhookTesting(true)
    setWebhookTestResult(null)
    try {
      const resp = await axios.post('/api/alerts/test', {
        url: webhookUrl || undefined,
        provider: webhookProvider,
        min_severity: webhookMinSev,
        dry_run: !webhookUrl,
      })
      setWebhookTestResult(resp.data)
    } catch (e) {
      setWebhookTestResult({ error: e.response?.data?.detail || e.message })
    } finally {
      setWebhookTesting(false)
    }
  }


  // Process completed job
  const loadExecutiveSummary = async (id) => {
    setExecSummaryLoading(true)
    try {
      const resp = await axios.get(`/api/jobs/${id}/executive-summary`)
      setExecutiveSummary(resp.data)
    } catch (e) {
      console.error('Failed to load executive summary:', e)
    } finally {
      setExecSummaryLoading(false)
    }
  }

  const processJobData = async (data) => {
    setJobId(data.job_id)
    setOverall(data.overall)
    if (data.email_auth) {
      setEmailAuth(data.email_auth)
    } else {
      setEmailAuth(null)
    }
    const sumRes = await axios.get(`/api/jobs/${data.job_id}/summary`)
    setSessions(sumRes.data)
    loadExecutiveSummary(data.job_id)
  }

  const doProbeDomain = async (customDomain = null) => {
    const domain = (customDomain || targetDomain).trim()
    if (!domain) return
    setProbingDomain(true)
    setLoading(true)
    setError(null)
    setSessions([])
    setOverall(null)
    setDetailCache({})
    setCompliance(null)
    setEmailAuth(null)
    setExecutiveSummary(null)
    setExpandedSessions(new Set())
    setActiveTab('analysis')
    setDomainProbeStatus(`Querying MX records & auditing TLS for ${domain}...`)
    try {
      const resp = await axios.post('/api/tools/domain-probe', {
        domain: domain,
        use_ml: useML,
        timeout: 6.0,
      })
      await processJobData(resp.data)
    } catch (e) {
      setError('Domain Probe failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setLoading(false)
      setProbingDomain(false)
      setDomainProbeStatus('')
    }
  }

  const loadHistory = async () => {
    setHistoryLoading(true)
    try {
      const resp = await axios.get('/api/history')
      setHistoryScans(resp.data)
    } catch (e) {
      console.error('Failed to fetch history:', e)
    } finally {
      setHistoryLoading(false)
    }
  }

  const loadTrends = async () => {
    try {
      const resp = await axios.get('/api/history/trends')
      setHistoryTrends(resp.data)
    } catch (e) {
      console.error('Failed to fetch trends:', e)
    }
  }

  const rehydrateHistoryScan = async (scanId) => {
    setLoading(true)
    setActiveTab('analysis')
    try {
      const resp = await axios.get(`/api/history/${scanId}`)
      const scan = resp.data
      const p = scan.payload || {}
      setJobId(scanId)
      setOverall(p.overall || null)
      setSessions(p.sessions || [])
      setEmailAuth(p.email_auth || null)
      loadExecutiveSummary(scanId)
    } catch (e) {
      setError('Failed to reload historical scan: ' + (e.response?.data?.detail || e.message))
    } finally {
      setLoading(false)
    }
  }

  const deleteHistoryScan = async (scanId) => {
    try {
      await axios.delete(`/api/history/${scanId}`)
      loadHistory()
      loadTrends()
    } catch (e) {
      console.error('Failed to delete scan:', e)
    }
  }

  const clearAllHistory = async () => {
    if (!window.confirm('Clear all scan history? This action cannot be undone.')) return
    try {
      await axios.post('/api/history/clear')
      loadHistory()
      loadTrends()
    } catch (e) {
      console.error('Failed to clear history:', e)
    }
  }

  const downloadPlaybookPdf = (id = null) => {
    const targetId = id || jobId
    if (!targetId) return
    window.open(`/api/jobs/${targetId}/playbook/pdf`, '_blank')
  }

  const downloadHardeningScript = (platform = 'linux', id = null) => {
    const targetId = id || hardeningData?.session_id || hardeningSessionId || jobId
    if (!targetId) {
      alert('No active scan session available for hardening script generation.')
      return
    }
    window.open(`/api/jobs/${targetId}/hardening-script?platform=${platform}`, '_blank')
  }

  // Analyze uploaded PCAP
  const doAnalyze = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    setSessions([])
    setOverall(null)
    setDetailCache({})
    setCompliance(null)
    setExpandedSessions(new Set())
    setActiveTab('analysis')
    try {
      const fd = new FormData()
      fd.append('file', file)
      const resp = await axios.post(`/api/analyze?use_ml=${useML}`, fd)
      await processJobData(resp.data)
    } catch (e) {
      setError('Analysis failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setLoading(false)
    }
  }

  // Load sample demo PCAP
  const doLoadDemo = async () => {
    setLoading(true)
    setError(null)
    setSessions([])
    setOverall(null)
    setDetailCache({})
    setCompliance(null)
    setExpandedSessions(new Set())
    setActiveTab('analysis')
    try {
      const resp = await axios.post(`/api/tools/sample-pcap?use_ml=${useML}`)
      await processJobData(resp.data)
    } catch (e) {
      setError('Demo PCAP failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setLoading(false)
    }
  }

  // Drag & drop handlers
  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragOver(true)
  }

  const handleDragLeave = () => {
    setIsDragOver(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragOver(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0]
      if (droppedFile.name.endsWith('.pcap') || droppedFile.name.endsWith('.pcapng')) {
        setFile(droppedFile)
      } else {
        alert('Please upload a valid .pcap or .pcapng file')
      }
    }
  }

  // Compliance Matrix Loader
  const loadCompliance = async () => {
    if (compliance || !jobId) return
    setComplianceLoading(true)
    try {
      const resp = await axios.get(`/api/jobs/${jobId}/compliance`)
      setCompliance(resp.data)
    } catch (e) {
      console.error('Failed to load compliance:', e)
    } finally {
      setComplianceLoading(false)
    }
  }

  // Tools Loaders
  const loadInterfaces = async () => {
    try {
      const resp = await axios.get('/api/tools/interfaces')
      setInterfaces(resp.data.interfaces)
      if (resp.data.interfaces.length > 0 && !selectedInterface) {
        setSelectedInterface(resp.data.interfaces[0].name)
      }
    } catch (e) {
      console.error('Failed to load interfaces:', e)
    }
  }

  // WebSocket Lifecycle for Live Sniffing
  useEffect(() => {
    if (activeTab !== 'live') {
      if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
        wsRef.current.close()
      }
      return
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const wsUrl = `${protocol}//${host}/api/ws/live`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setWsConnected(true)
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'packet') {
          setLivePackets(prev => {
            const next = [msg.data, ...prev]
            return next.length > 100 ? next.slice(0, 100) : next
          })
          setLiveStats(prev => ({
            ...prev,
            packets: (prev.packets || 0) + 1,
            bytes: (prev.bytes || 0) + (msg.data.bytes || 0),
          }))
        } else if (msg.type === 'session') {
          setLiveSessions(prev => {
            const idx = prev.findIndex(s => s.session_id === msg.session.session_id)
            if (idx >= 0) {
              const updated = [...prev]
              updated[idx] = msg.session
              return updated
            }
            return [msg.session, ...prev]
          })
          setLiveStats(prev => ({
            ...prev,
            sessions: (prev.sessions || 0) + 1,
          }))
        } else if (msg.type === 'status') {
          if (msg.stats?.engine) setLiveEngine(msg.stats.engine)
          if (msg.stats?.note) setLiveNotice(msg.stats.note)
          if (msg.status === 'notice' && msg.stats) {
            setLiveNotice(msg.stats.message + (msg.stats.tip ? ` — ${msg.stats.tip}` : ''))
          } else if (msg.status === 'sniffing' && msg.stats) {
            setLiveStats(prev => ({
              ...prev,
              ...msg.stats,
            }))
            if (msg.stats.engine) setLiveEngine(msg.stats.engine)
            if (msg.stats.duration && msg.stats.elapsed) {
              setCaptureRemaining(Math.max(0, Math.round(msg.stats.duration - msg.stats.elapsed)))
            }
          } else if (msg.status === 'completed') {
            setLiveCapturing(false)
          } else if (msg.status === 'error') {
            alert('Live Sniffer Error: ' + (msg.stats?.message || 'Capture failed'))
            setLiveCapturing(false)
          }
        } else if (msg.type === 'completed') {
          setLiveCapturing(false)
          setLiveCompletedJob(msg)
        }
      } catch (err) {
        console.error('WebSocket message parsing error:', err)
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
    }

    ws.onerror = (e) => {
      console.error('WebSocket connection error:', e)
      setWsConnected(false)
    }

    return () => {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close()
      }
    }
  }, [activeTab])

  // Terminal scroll management
  useEffect(() => {
    if (autoScroll && terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = 0
    }
  }, [livePackets, autoScroll])

  const startLiveSniffing = () => {
    setLivePackets([])
    setLiveSessions([])
    setLiveCompletedJob(null)
    setLiveNotice(null)
    setLiveStats({ packets: 0, bytes: 0, sessions: 0, elapsed: 0 })
    setLiveCapturing(true)
    setCaptureRemaining(liveDuration)

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'start',
        interface: selectedInterface,
        duration: liveDuration,
        use_ml: useML,
        simulation: simulationMode,
        max_sessions: maxSessions,
        protocol_filter: liveProtocolFilter,
      }))
    } else {
      alert('WebSocket is connecting to backend. Please retry in a moment.')
      setLiveCapturing(false)
    }
  }

  const stopLiveSniffing = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'stop' }))
    }
    setLiveCapturing(false)
  }

  const openLiveAnalysis = async () => {
    if (liveCompletedJob?.job_id) {
      await processJobData(liveCompletedJob)
      setActiveTab('analysis')
    }
  }

  const loadMlStatus = async () => {
    setMlStatusError(null)
    try {
      const resp = await axios.get('/api/tools/ml/status')
      setMlStatus(resp.data)
    } catch (e) {
      console.error('Failed to load ML status:', e)
      setMlStatusError(e.response?.data?.detail || e.message || 'Failed to reach ML subsystem')
    }
  }

  const evaluateMl = async () => {
    setMlEvaluating(true)
    try {
      const resp = await axios.post('/api/tools/ml/evaluate')
      setMlEval(resp.data)
    } catch (e) {
      alert('ML Evaluation failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setMlEvaluating(false)
    }
  }

  const trainMl = async () => {
    setMlTraining(true)
    setTrainResult(null)
    try {
      let resp
      if (trainSource === 'csv') {
        if (!trainCsvFile) {
          alert('Please select a CSV baseline file first.')
          setMlTraining(false)
          return
        }
        const formData = new FormData()
        formData.append('file', trainCsvFile)
        resp = await axios.post(`/api/tools/ml/train-upload?n_per_class=${trainNPerClass}&baseline_n=${trainBaselineN}`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
      } else {
        resp = await axios.post('/api/tools/ml/train', {
          n_per_class: trainNPerClass,
          baseline_n: trainBaselineN,
          source: trainSource,
          job_id: jobId,
        })
      }
      setTrainResult(resp.data?.details || resp.data)
      loadMlStatus()
    } catch (e) {
      alert('ML Training failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setMlTraining(false)
    }
  }

  const loadDiagnostics = async () => {
    setDiagnosticsLoading(true)
    setDiagnosticsError(null)
    try {
      const resp = await axios.get('/api/tools/system/diagnostics')
      setDiagnostics(resp.data)
    } catch (e) {
      console.error('Failed to load diagnostics:', e)
      setDiagnosticsError(e.response?.data?.detail || e.message || 'Failed to reach diagnostics subsystem')
    } finally {
      setDiagnosticsLoading(false)
    }
  }

  const handleTabSwitch = (tab) => {
    setActiveTab(tab)
    if (tab === 'compliance') loadCompliance()
    if (tab === 'live') loadInterfaces()
    if (tab === 'ml') { loadMlStatus(); loadHistory(); }
    if (tab === 'diagnostics') loadDiagnostics()
    if (tab === 'history') { loadHistory(); loadTrends(); }
  }

  // Session Accordion Toggle
  const toggleSession = async (sessionId) => {
    const nextSet = new Set(expandedSessions)
    if (nextSet.has(sessionId)) {
      nextSet.delete(sessionId)
    } else {
      nextSet.add(sessionId)
      if (!detailCache[sessionId] && jobId) {
        try {
          const resp = await axios.get(`/api/jobs/${jobId}/sessions/${sessionId}`)
          setDetailCache(prev => ({ ...prev, [sessionId]: resp.data }))
        } catch (e) {
          console.error('Failed to fetch session detail:', e)
        }
      }
    }
    setExpandedSessions(nextSet)
  }

  const expandAllSessions = async () => {
    const allIds = new Set(sessions.map(s => s.session_id))
    setExpandedSessions(allIds)
    // Fetch details in parallel for un-cached sessions
    for (const s of sessions) {
      if (!detailCache[s.session_id] && jobId) {
        axios.get(`/api/jobs/${jobId}/sessions/${s.session_id}`).then(resp => {
          setDetailCache(prev => ({ ...prev, [s.session_id]: resp.data }))
        }).catch(() => { })
      }
    }
  }

  const collapseAllSessions = () => {
    setExpandedSessions(new Set())
  }

  const exportUrl = (fmt) => (jobId ? `/api/jobs/${jobId}/report/${fmt}` : null)

  // Filter & Sort Sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter(s => {
      // KPI Quick filter
      if (kpiFilter === 'ENCRYPTED' && !s.encrypted) return false
      if (kpiFilter === 'PLAINTEXT' && !s.plaintext) return false
      if (kpiFilter === 'ANOMALIES') {
        const detail = detailCache[s.session_id]
        if (detail && !detail.ml_anomaly) return false
      }

      // Protocol filter
      if (protocolFilter !== 'ALL' && (s.protocol || '').toUpperCase() !== protocolFilter) return false

      // Risk filter
      if (riskFilter !== 'ALL' && (s.risk_label || '').toUpperCase() !== riskFilter) return false

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matchSummary = (
          (s.protocol || '').toLowerCase().includes(q) ||
          (s.server_ip || '').toLowerCase().includes(q) ||
          (s.client_ip || '').toLowerCase().includes(q) ||
          String(s.server_port || '').includes(q) ||
          String(s.client_port || '').includes(q) ||
          (s.risk_label || '').toLowerCase().includes(q)
        )
        if (matchSummary) return true

        const detail = detailCache[s.session_id]
        if (detail) {
          const matchDetail = (
            (detail.tls?.version || '').toLowerCase().includes(q) ||
            (detail.tls?.cipher_suite || '').toLowerCase().includes(q) ||
            (detail.tls?.server_name || '').toLowerCase().includes(q) ||
            (detail.certificate?.subject || '').toLowerCase().includes(q) ||
            (detail.certificate?.issuer || '').toLowerCase().includes(q) ||
            (detail.findings || []).some(f => f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q))
          )
          return matchDetail
        }
        return false
      }
      return true
    }).sort((a, b) => {
      if (sortOption === 'score_asc') return (a.posture_score ?? 100) - (b.posture_score ?? 100)
      if (sortOption === 'score_desc') return (b.posture_score ?? 0) - (a.posture_score ?? 0)
      if (sortOption === 'findings_desc') return (b.finding_count || 0) - (a.finding_count || 0)
      if (sortOption === 'protocol') return (a.protocol || '').localeCompare(b.protocol || '')
      return 0
    })
  }, [sessions, searchQuery, protocolFilter, riskFilter, kpiFilter, sortOption, detailCache])

  // Filter Compliance Controls
  const filteredControls = useMemo(() => {
    if (!compliance?.controls_summary) return []
    return compliance.controls_summary.filter(ctrl => {
      if (complianceSearch.trim()) {
        const q = complianceSearch.toLowerCase()
        const match = ctrl.control_id.toLowerCase().includes(q) || ctrl.control_name.toLowerCase().includes(q)
        if (!match) return false
      }
      if (complianceStatusFilter !== 'ALL') {
        const hasStatus = Object.values(ctrl.frameworks).some(f => f.status === complianceStatusFilter)
        if (!hasStatus) return false
      }
      return true
    })
  }, [compliance, complianceSearch, complianceStatusFilter])

  // Chart Data Preparation
  const sevPieData = useMemo(() => {
    if (!overall) return []
    return Object.entries(overall.severity_counts)
      .filter(([_, count]) => count > 0)
      .map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v, rawKey: k }))
  }, [overall])

  const protoBarData = useMemo(() => {
    if (!overall) return []
    return Object.entries(overall.protocols).map(([k, v]) => ({
      name: k.toUpperCase(),
      sessions: v
    }))
  }, [overall])

  // Stream posture score curve data
  const streamScoreData = useMemo(() => {
    return sessions.map((s, idx) => ({
      index: `#${idx + 1}`,
      name: `${s.protocol?.toUpperCase() || 'S'}-${s.session_id.substring(0, 4)}`,
      score: s.posture_score ?? 0,
      findings: s.finding_count || 0,
      protocol: (s.protocol || '').toUpperCase()
    }))
  }, [sessions])

  // Encryption status breakdown
  const encryptionBreakdownData = useMemo(() => {
    if (!overall) return []
    const enc = overall.encrypted_sessions || 0
    const plain = overall.plaintext_sessions || 0
    return [
      { name: 'TLS Encrypted', value: enc, color: '#38a856' },
      { name: 'Plaintext Exposure', value: plain, color: '#ff595e' }
    ].filter(d => d.value > 0)
  }, [overall])

  const overallRating = useMemo(() => {
    return overall ? getPostureRating(overall.avg_posture_score) : null
  }, [overall])

  return (
    <div className="app-container">
      {/* Top Navbar */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div className="brand-title-group">
            <h1>
              SecureMailScope
              <span className="brand-version">v0.1.0</span>
            </h1>
            <p className="brand-subtitle">AI-Assisted Cryptographic Security Posture Assessment for Enterprise Email</p>
          </div>
        </div>

        <div className="header-status-group">
          <button
            className="chip-btn"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', padding: '6px 12px' }}
            onClick={() => setWebhookModalOpen(true)}
            title="Configure SIEM, Slack, or Discord Webhook Alerts"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" /></svg>
            <span>Webhook Alerts</span>
          </button>

          {sessions.length > 0 && (
            <button
              className="chip-btn"
              style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', padding: '6px 12px' }}
              onClick={() => openHardeningModal(sessions[0].session_id)}
              title="1-Click Hardening Config Generator for MTAs"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              <span>Hardening Guide</span>
            </button>
          )}

          <div className="status-pill">
            <div className="pulse-dot"></div>
            <span>Forensics Engine Ready</span>
          </div>
        </div>
      </header>


      {/* Main Navigation Tabs */}
      <nav className="nav-tabs">
        <button className={`nav-tab-btn ${activeTab === 'analysis' ? 'active' : ''}`} onClick={() => handleTabSwitch('analysis')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
          </svg>
          Analysis &amp; Forensics
          {sessions.length > 0 && <span className="tab-badge">{sessions.length}</span>}
        </button>

        <button className={`nav-tab-btn ${activeTab === 'compliance' ? 'active' : ''}`} onClick={() => handleTabSwitch('compliance')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" />
          </svg>
          Compliance Matrix
        </button>

        <button className={`nav-tab-btn ${activeTab === 'live' ? 'active' : ''}`} onClick={() => handleTabSwitch('live')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="2" /><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
          </svg>
          Live Sniffer
        </button>

        <button className={`nav-tab-btn ${activeTab === 'ml' ? 'active' : ''}`} onClick={() => handleTabSwitch('ml')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
          </svg>
          ML Studio
        </button>

        <button className={`nav-tab-btn ${activeTab === 'diagnostics' ? 'active' : ''}`} onClick={() => handleTabSwitch('diagnostics')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
          </svg>
          System Diagnostics
        </button>

        <button className={`nav-tab-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => handleTabSwitch('history')}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
          </svg>
          Trends &amp; History
          {historyScans.length > 0 && <span className="tab-badge">{historyScans.length}</span>}
        </button>
      </nav>

      {/* Mode Switcher: PCAP Upload vs Live Domain Probe */}
      <div className="upload-mode-tabs">
        <button
          className={`upload-mode-btn ${scanMode === 'pcap' ? 'active' : ''}`}
          onClick={() => setScanMode('pcap')}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
          <span>PCAP File Upload</span>
        </button>
        <button
          className={`upload-mode-btn ${scanMode === 'domain' ? 'active' : ''}`}
          onClick={() => setScanMode('domain')}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>
          <span>Live Domain Probe (No PCAP)</span>
        </button>
      </div>

      {scanMode === 'pcap' ? (
        /* Interactive PCAP Upload & Demo Hero */
        <div className={`upload-zone-wrapper ${isDragOver ? 'dragover' : ''}`}>
          <div
            className="dropzone-inner"
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              type="file"
              ref={fileInputRef}
              accept=".pcap,.pcapng"
              style={{ display: 'none' }}
              onChange={(e) => setFile(e.target.files[0] || null)}
            />
            <div className="dropzone-icon">
              <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
            </div>
            <div className="dropzone-title">
              {file ? file.name : 'Drag & drop capture file (.pcap, .pcapng) or click to browse'}
            </div>
            <div className="dropzone-subtitle">
              Passive inspection of SMTP, IMAP, and POP3 network streams
            </div>

            {file && (
              <div className="file-selected-badge" onClick={(e) => e.stopPropagation()}>
                <span>{file.name}</span>
                <span style={{ color: 'var(--text-muted)' }}>({(file.size / 1024).toFixed(1)} KB)</span>
                <button title="Remove file" onClick={() => setFile(null)}>✕</button>
              </div>
            )}
          </div>

          <div className="upload-actions-bar">
            <div className="upload-options-group">
              <label className="toggle-label">
                <input type="checkbox" checked={useML} onChange={(e) => setUseML(e.target.checked)} />
                <span>Use ML Posture &amp; Anomaly Models</span>
              </label>

              <div className="input-number-group">
                <span>Max Sessions:</span>
                <input
                  type="number"
                  min="0"
                  value={maxSessions}
                  onChange={(e) => setMaxSessions(Math.max(0, Number(e.target.value)))}
                  title="0 = analyze all streams"
                />
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>(0 = all)</span>
              </div>
            </div>

            <div className="upload-btn-group">
              <button className="btn-secondary" onClick={doLoadDemo} disabled={loading}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                </svg>
                Load Demo PCAP
              </button>

              <button className="btn-primary" onClick={doAnalyze} disabled={loading || !file}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                {loading ? 'Analyzing Streams…' : 'Run Posture Analysis'}
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* Live Domain Probe Box */
        <div className="domain-probe-box">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                Live Mail Server &amp; Email Authentication Scanner
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                Actively queries MX records, establishes SMTP STARTTLS handshake, validates certificates, tests ciphers &amp; checks DMARC/SPF/DKIM live — no PCAP required.
              </div>
            </div>
            <label className="toggle-label">
              <input type="checkbox" checked={useML} onChange={(e) => setUseML(e.target.checked)} />
              <span>Use ML Scoring</span>
            </label>
          </div>

          <div className="domain-input-row">
            <input
              type="text"
              className="domain-input-field"
              placeholder="Enter domain name (e.g. gmail.com, cloudflare.com, yourcollege.edu)"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') doProbeDomain() }}
            />
            <button
              className="domain-probe-btn"
              onClick={() => doProbeDomain()}
              disabled={loading || probingDomain || !targetDomain.trim()}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>
              {probingDomain ? 'Probing Mail Servers…' : 'Probe Domain Live'}
            </button>
          </div>

          <div className="domain-presets-row">
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>Quick Presets:</span>
            {['gmail.com', 'cloudflare.com', 'yahoo.com', 'proton.me', 'outlook.com'].map(d => (
              <button
                key={d}
                className="domain-preset-chip"
                onClick={() => { setTargetDomain(d); doProbeDomain(d); }}
                disabled={loading || probingDomain}
              >
                {d}
              </button>
            ))}
          </div>

          {domainProbeStatus && (
            <div style={{ fontSize: '12.5px', color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div className="spinner" style={{ width: '14px', height: '14px', borderWidth: '2px' }}></div>
              <span>{domainProbeStatus}</span>
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="alert-banner error" style={{ marginTop: '14px' }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <span>{error}</span>
        </div>
      )}

      {loading && (
        <div className="loading-card">
          <div className="spinner"></div>
          <span>Reconstructing TCP streams, parsing TLS handshakes, evaluating certificates &amp; calculating ML risk posture…</span>
        </div>
      )}

      {/* ==========================================================================
          ANALYSIS TAB
         ========================================================================== */}
      {activeTab === 'analysis' && overall && !loading && (
        <>
          {/* Standout Feature: AI-Assisted Executive Summary & CISO Risk Briefing */}
          {executiveSummary && (
            <div className="executive-summary-card">
              <div className="exec-header-row">
                <div className="exec-badge-group">
                  <PostureRing score={executiveSummary.posture_score} size={64} strokeWidth={6} />
                  <div>
                    <div className="exec-headline-text">{executiveSummary.headline}</div>
                    <div className="exec-target-subtext">
                      Target: <b>{executiveSummary.target_name}</b> &nbsp;|&nbsp;
                      Overall Score: <b>{executiveSummary.posture_score}/100</b> &nbsp;|&nbsp;
                      Encrypted: <b>{executiveSummary.encrypted_ratio}%</b>
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="chip-btn"
                    style={{ background: 'var(--bg-app)', border: '1px solid var(--border-color)', display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px' }}
                    onClick={() => copyToClipboard(executiveSummary.executive_brief, 'exec-brief')}
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                    <span>{copiedKey === 'exec-brief' ? '✓ Brief Copied' : 'Copy Brief'}</span>
                  </button>
                  <button
                    className="btn-primary"
                    style={{ padding: '6px 14px', fontSize: '12.5px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                    onClick={() => downloadPlaybookPdf()}
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                    <span>Remediation Playbook (PDF)</span>
                  </button>
                  <button
                    className="chip-btn"
                    style={{ background: 'var(--bg-app)', border: '1px solid var(--border-color)', display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 11px', fontSize: '12px' }}
                    onClick={() => downloadHardeningScript('linux')}
                    title="Download automated Postfix/Dovecot TLS hardening script (.sh)"
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                    <span>Hardening (.sh)</span>
                  </button>
                  <button
                    className="chip-btn"
                    style={{ background: 'var(--bg-app)', border: '1px solid var(--border-color)', display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 11px', fontSize: '12px' }}
                    onClick={() => downloadHardeningScript('windows')}
                    title="Download automated Windows SChannel TLS hardening script (.ps1)"
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                    <span>Hardening (.ps1)</span>
                  </button>
                </div>
              </div>

              {/* Briefing Paragraphs */}
              <div className="exec-brief-paragraphs">
                {executiveSummary.summary_paragraphs?.map((p, idx) => (
                  <p key={idx} style={{ margin: 0 }}>{p}</p>
                ))}
              </div>

              {/* Metrics Strip */}
              <div className="exec-metrics-strip">
                <div className="exec-metric-item">
                  <span className="exec-metric-label">HNDL Quantum Risk</span>
                  <span className="exec-metric-val" style={{ color: executiveSummary.post_quantum_assessment?.hndl_risk === 'LOW' ? 'var(--sev-safe)' : 'var(--sev-critical)' }}>
                    {executiveSummary.post_quantum_assessment?.hndl_risk || 'UNKNOWN'}
                  </span>
                </div>
                <div className="exec-metric-item">
                  <span className="exec-metric-label">Plaintext Credentials</span>
                  <span className="exec-metric-val" style={{ color: executiveSummary.credentials_leaked > 0 ? 'var(--sev-critical)' : 'var(--sev-safe)' }}>
                    {executiveSummary.credentials_leaked} Leaked
                  </span>
                </div>
                <div className="exec-metric-item">
                  <span className="exec-metric-label">STARTTLS Downgrades</span>
                  <span className="exec-metric-val" style={{ color: executiveSummary.downgrade_attacks > 0 ? 'var(--sev-critical)' : 'var(--sev-safe)' }}>
                    {executiveSummary.downgrade_attacks} Detected
                  </span>
                </div>
                <div className="exec-metric-item">
                  <span className="exec-metric-label">Regulatory Status</span>
                  <span className="exec-metric-val" style={{ color: executiveSummary.compliance_summary?.status === 'COMPLIANT' ? 'var(--sev-safe)' : 'var(--sev-high)' }}>
                    {executiveSummary.compliance_summary?.status || 'N/A'}
                  </span>
                </div>
              </div>

              {/* Actionable Remediation Roadmap Accordion */}
              <div>
                <button
                  className="exec-roadmap-toggle-btn"
                  onClick={() => setShowRoadmap(!showRoadmap)}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points={showRoadmap ? "18 15 12 9 6 15" : "6 9 12 15 18 9"} />
                  </svg>
                  <span>{showRoadmap ? 'Hide Prioritized Remediation Roadmap' : 'View Prioritized 3-Phase Remediation Roadmap'}</span>
                </button>

                {showRoadmap && (
                  <div className="exec-roadmap-container">
                    {executiveSummary.actionable_roadmap?.map((phase, pIdx) => (
                      <div key={pIdx} className="roadmap-phase-card" style={{ borderTopColor: phase.color }}>
                        <div>
                          <div className="phase-title">{phase.phase}</div>
                          <div className="phase-timeframe">{phase.timeframe} &nbsp;|&nbsp; {phase.priority}</div>
                        </div>
                        <ul className="phase-action-list">
                          {phase.actions.map((act, aIdx) => (
                            <li key={aIdx}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Standout Feature: DMARC, SPF, DKIM Email Authentication Card */}
          {emailAuth && (
            <div className="email-auth-card">
              <div className="email-auth-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div className="status-badge-compact" style={{ background: emailAuth.grade_color, color: '#fff', fontSize: '16px', fontWeight: 800, padding: '6px 14px' }}>
                    Grade {emailAuth.grade} ({emailAuth.overall_score}/100)
                  </div>
                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      Email Authentication &amp; Anti-Spoofing Posture ({emailAuth.domain})
                    </div>
                    <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                      {emailAuth.summary}
                    </div>
                  </div>
                </div>
              </div>

              <div className="email-auth-grid">
                {/* DMARC Subcard */}
                <div className="email-auth-subcard">
                  <span className="email-auth-subcard-title">DMARC Policy (RFC 7489)</span>
                  <div className="email-auth-subcard-val" style={{ color: emailAuth.dmarc?.policy === 'reject' ? 'var(--sev-safe)' : (emailAuth.dmarc?.policy === 'quarantine' ? 'var(--sev-medium)' : 'var(--sev-critical)') }}>
                    p={emailAuth.dmarc?.policy || 'none'}
                    <span style={{ fontSize: '11px', fontWeight: 500, color: 'var(--text-muted)' }}>
                      ({emailAuth.dmarc?.spoofing_protected ? 'Spoofing Blocked' : 'Vulnerable to Spoofing'})
                    </span>
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    Reports (rua): {emailAuth.dmarc?.rua?.length > 0 ? 'Configured' : 'Missing'} &nbsp;|&nbsp; Enforcement: {emailAuth.dmarc?.pct || 100}%
                  </div>
                </div>

                {/* SPF Subcard */}
                <div className="email-auth-subcard">
                  <span className="email-auth-subcard-title">SPF Policy (RFC 7208)</span>
                  <div className="email-auth-subcard-val" style={{ color: emailAuth.spf?.qualifier === '-all' ? 'var(--sev-safe)' : (emailAuth.spf?.qualifier === '~all' ? 'var(--sev-safe)' : 'var(--sev-high)') }}>
                    {emailAuth.spf?.qualifier || 'No qualifier'} ({emailAuth.spf?.policy || 'none'})
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    Lookups: {emailAuth.spf?.lookup_count || 0}/10 &nbsp;|&nbsp; Includes: {emailAuth.spf?.includes?.length || 0}
                  </div>
                </div>

                {/* DKIM Subcard */}
                <div className="email-auth-subcard">
                  <span className="email-auth-subcard-title">DKIM Selectors (RFC 6376)</span>
                  <div className="email-auth-subcard-val" style={{ color: emailAuth.dkim?.selectors_found > 0 ? 'var(--sev-safe)' : 'var(--text-muted)' }}>
                    {emailAuth.dkim?.selectors_found > 0 ? `${emailAuth.dkim.selectors_found} Selector(s) Discovered` : 'No Standard Selectors'}
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    Probed: {emailAuth.dkim?.selectors_probed || 0} known provider keys
                  </div>
                </div>

                {/* BIMI Subcard */}
                <div className="email-auth-subcard">
                  <span className="email-auth-subcard-title">BIMI Brand Indicator</span>
                  <div className="email-auth-subcard-val" style={{ color: emailAuth.bimi?.present ? 'var(--sev-safe)' : 'var(--text-muted)' }}>
                    {emailAuth.bimi?.present ? 'Active Brand Logo' : 'Not Configured'}
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    VMC Cert: {emailAuth.bimi?.vmc_cert ? 'Present' : 'None'}
                  </div>
                </div>
              </div>
            </div>
          )}
          {/* Interactive KPI Cards */}
          <div className="stats-grid-interactive">
            <div
              className={`stat-kpi-card kpi-card-sessions ${kpiFilter === 'ALL' ? 'selected-filter' : ''}`}
              onClick={() => setKpiFilter('ALL')}
              title="Click to reset filters and view all sessions"
            >
              <div className="kpi-header">
                <span className="kpi-label">Total Sessions</span>
                <svg className="kpi-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                  <polyline points="22,6 12,13 2,6" />
                </svg>
              </div>
              <div className="kpi-value-row">
                <span className="kpi-value">{overall.total_sessions}</span>
                <span className="kpi-badge badge-streams">STREAMS</span>
              </div>
              <div className="kpi-subtext">Click to view all sessions</div>
            </div>

            <div
              className={`stat-kpi-card kpi-card-encrypted ${kpiFilter === 'ENCRYPTED' ? 'selected-filter' : ''}`}
              onClick={() => setKpiFilter(prev => prev === 'ENCRYPTED' ? 'ALL' : 'ENCRYPTED')}
              title="Click to filter encrypted sessions"
            >
              <div className="kpi-header">
                <span className="kpi-label">Encrypted</span>
                <svg className="kpi-icon" style={{ color: 'var(--sev-safe)' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <div className="kpi-value-row">
                <span className="kpi-value" style={{ color: 'var(--sev-safe)' }}>{overall.encrypted_sessions}</span>
                <span className="kpi-badge badge-encrypted">
                  {overall.total_sessions ? Math.round((overall.encrypted_sessions / overall.total_sessions) * 100) : 0}%
                </span>
              </div>
              <div className="kpi-subtext">TLS / STARTTLS secured</div>
            </div>

            <div
              className={`stat-kpi-card kpi-card-plaintext ${kpiFilter === 'PLAINTEXT' ? 'selected-filter' : ''}`}
              onClick={() => setKpiFilter(prev => prev === 'PLAINTEXT' ? 'ALL' : 'PLAINTEXT')}
              title="Click to filter plaintext sessions"
            >
              <div className="kpi-header">
                <span className="kpi-label">Plaintext Exposure</span>
                <svg className="kpi-icon" style={{ color: 'var(--sev-critical)' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 9.9-1" />
                </svg>
              </div>
              <div className="kpi-value-row">
                <span className="kpi-value" style={{ color: overall.plaintext_sessions > 0 ? 'var(--sev-critical)' : 'var(--text-primary)' }}>
                  {overall.plaintext_sessions}
                </span>
                {overall.plaintext_sessions > 0 && (
                  <span className="kpi-badge badge-alert">
                    ALERT
                  </span>
                )}
              </div>
              <div className="kpi-subtext">Unencrypted email traffic</div>
            </div>

            <div className="stat-kpi-card kpi-card-posture posture-score-kpi">
              <div className="kpi-header">
                <span className="kpi-label">Posture Score</span>
                <span className="kpi-badge badge-grade" style={{ background: overallRating?.color + '22', color: overallRating?.color }}>
                  Grade {overallRating?.grade}
                </span>
              </div>
              <div className="kpi-value-row">
                <span className="kpi-value score-number" style={{ color: overallRating?.color }}>
                  {overall.avg_posture_score}
                </span>
                <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>/ 100</span>
              </div>
              <div className="kpi-subtext" style={{ color: overallRating?.color }}>
                {overallRating?.label}
              </div>
            </div>

            <div
              className={`stat-kpi-card kpi-card-anomalies ${kpiFilter === 'ANOMALIES' ? 'selected-filter' : ''}`}
              onClick={() => setKpiFilter(prev => prev === 'ANOMALIES' ? 'ALL' : 'ANOMALIES')}
              title="Click to filter ML anomalies"
            >
              <div className="kpi-header">
                <span className="kpi-label">ML Anomalies</span>
                <svg className="kpi-icon" style={{ color: 'var(--sev-high)' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
              </div>
              <div className="kpi-value-row">
                <span className="kpi-value" style={{ color: overall.anomalies > 0 ? 'var(--sev-high)' : 'var(--text-primary)' }}>
                  {overall.anomalies}
                </span>
                <span className="kpi-badge badge-ml">
                  ISOLATION FOREST
                </span>
              </div>
              <div className="kpi-subtext">Unusual handshake patterns</div>
            </div>
          </div>

          {/* Visual Analytics Charts: 4-Grid Multi-Dimensional Visualizations */}
          <div className="charts-section-grid-4">
            {/* Chart 1: Findings by Severity Donut */}
            <div className="chart-card">
              <div className="chart-card-header">
                <span className="chart-card-title">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" /><path d="M12 2a10 10 0 0 1 10 10h-10z" />
                  </svg>
                  Findings by Severity
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{Object.values(overall.severity_counts).reduce((a, b) => a + b, 0)} Total</span>
              </div>
              <ResponsiveContainer width="100%" height={210}>
                <PieChart>
                  <Pie
                    data={sevPieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={74}
                    paddingAngle={3}
                  >
                    {sevPieData.map((d) => (
                      <Cell key={d.name} fill={SEV_COLORS[d.rawKey] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload
                      return (
                        <div className="custom-recharts-tooltip">
                          <p style={{ color: SEV_COLORS[data.rawKey] }}><b>{data.name} Severity</b></p>
                          <p>Count: <span>{data.value}</span> findings</p>
                        </div>
                      )
                    }
                    return null
                  }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', flexWrap: 'wrap', marginTop: '6px' }}>
                {sevPieData.map(d => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: SEV_COLORS[d.rawKey] }}></span>
                    <span>{d.name}: {d.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Chart 2: Sessions by Protocol */}
            <div className="chart-card">
              <div className="chart-card-header">
                <span className="chart-card-title">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
                  </svg>
                  Sessions by Protocol
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Traffic Flow</span>
              </div>
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={protoBarData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.08)" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis allowDecimals={false} stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload
                      return (
                        <div className="custom-recharts-tooltip">
                          <p style={{ color: PROTOCOL_COLORS[data.name] || '#f97316' }}><b>{data.name} Protocol</b></p>
                          <p>Sessions: <span>{data.sessions}</span></p>
                        </div>
                      )
                    }
                    return null
                  }} />
                  <Bar dataKey="sessions" radius={[6, 6, 0, 0]}>
                    {protoBarData.map((d) => (
                      <Cell key={`proto-cell-${d.name}`} fill={PROTOCOL_COLORS[d.name] || '#f97316'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '6px' }}>
                {protoBarData.map(d => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '2px', backgroundColor: PROTOCOL_COLORS[d.name] || '#ff924c' }}></span>
                    <span>{d.name}: {d.sessions}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Chart 3: Posture Curve (AreaChart) across streams */}
            <div className="chart-card">
              <div className="chart-card-header">
                <span className="chart-card-title">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                  </svg>
                  Stream Posture Curve
                </span>
                <span style={{ fontSize: '11px', color: 'var(--accent-orange)' }}>Health Wave</span>
              </div>
              <ResponsiveContainer width="100%" height={210}>
                <AreaChart data={streamScoreData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scoreAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38a856" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#38a856" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.08)" vertical={false} />
                  <XAxis dataKey="index" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload
                      return (
                        <div className="custom-recharts-tooltip">
                          <p style={{ color: '#ff924c' }}><b>{data.name} ({data.protocol})</b></p>
                          <p>Posture Score: <b style={{ color: data.score < 50 ? '#ff595e' : data.score < 75 ? '#ffca3a' : '#38a856' }}>{data.score}/100</b></p>
                          <p>Findings: <span>{data.findings}</span></p>
                        </div>
                      )
                    }
                    return null
                  }} />
                  <Area type="monotone" dataKey="score" stroke="#38a856" strokeWidth={2.5} fillOpacity={1} fill="url(#scoreAreaGrad)" />
                </AreaChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', marginTop: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                  <span style={{ width: '12px', height: '3px', borderRadius: '2px', background: 'var(--primary)' }}></span>
                  Session Cryptographic Health (0-100)
                </span>
              </div>
            </div>

            {/* Chart 4: Encryption Status Breakdown Donut */}
            <div className="chart-card">
              <div className="chart-card-header">
                <span className="chart-card-title">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                  Encryption Breakdown
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Security Ratio</span>
              </div>
              <ResponsiveContainer width="100%" height={210}>
                <PieChart>
                  <Pie
                    data={encryptionBreakdownData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={74}
                    paddingAngle={4}
                  >
                    {encryptionBreakdownData.map((d) => (
                      <Cell key={d.name} fill={d.color} />
                    ))}
                  </Pie>
                  <Tooltip content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload
                      return (
                        <div className="custom-recharts-tooltip">
                          <p style={{ color: data.color }}><b>{data.name}</b></p>
                          <p>Count: <span>{data.value}</span> streams</p>
                        </div>
                      )
                    }
                    return null
                  }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap', marginTop: '6px' }}>
                {encryptionBreakdownData.map(d => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: d.color }}></span>
                    <span>{d.name}: {d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Forensic Filter & Search Toolbar */}
          <div className="forensic-toolbar">
            <div className="search-input-wrapper">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <input
                type="text"
                placeholder="Search IP, port, protocol, cipher, cert, finding..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button onClick={() => setSearchQuery('')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>✕</button>
              )}
            </div>

            {/* Protocol Chips */}
            <div className="filter-chips-group">
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginRight: '2px' }}>PROTO:</span>
              {['ALL', 'SMTP', 'IMAP', 'POP3'].map(p => (
                <button
                  key={p}
                  className={`chip-btn ${protocolFilter === p ? 'active' : ''}`}
                  onClick={() => setProtocolFilter(p)}
                >
                  {p}
                </button>
              ))}
            </div>

            {/* Risk Chips */}
            <div className="filter-chips-group">
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginRight: '2px' }}>RISK:</span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(r => (
                <button
                  key={r}
                  className={`chip-btn ${riskFilter === r ? 'active' : ''}`}
                  onClick={() => setRiskFilter(r)}
                  style={riskFilter === r && r !== 'ALL' ? { color: SEV_COLORS[r.toLowerCase()], borderColor: SEV_COLORS[r.toLowerCase()] } : {}}
                >
                  {r}
                </button>
              ))}
            </div>

            {/* Sort & Actions */}
            <div className="toolbar-controls-right">
              <select
                className="sort-select"
                value={sortOption}
                onChange={(e) => setSortOption(e.target.value)}
              >
                <option value="score_asc">Posture: Lowest First (Priority)</option>
                <option value="score_desc">Posture: Highest First</option>
                <option value="findings_desc">Findings: Most First</option>
                <option value="protocol">Protocol (A-Z)</option>
              </select>

              <div className="export-actions-group">
                <a className="export-btn" href={exportUrl('json')} download title="Export structured JSON report">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                  JSON
                </a>
                <a className="export-btn" href={exportUrl('html')} download title="Export standalone interactive HTML report">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                  HTML
                </a>
                <a className="export-btn" href={exportUrl('pdf')} download title="Export executive PDF report">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                  PDF
                </a>
                <a className="export-btn" href={exportUrl('csv')} download title="Export CSV for spreadsheet analysis">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                  CSV
                </a>
                <button
                  className="export-btn"
                  style={{ background: 'rgba(15, 118, 110, 0.15)', color: '#0f766e', borderColor: '#0f766e', cursor: 'pointer' }}
                  onClick={() => downloadPlaybookPdf()}
                  title="Export Automated Remediation Playbook (PDF)"
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                  Playbook (PDF)
                </button>
              </div>
            </div>
          </div>

          {/* Forensic Sessions Accordion List */}
          <div className="session-list-header">
            <div className="session-list-title">
              <span>Forensic Stream Inspection</span>
              <span style={{ fontSize: '13px', fontWeight: '400', color: 'var(--text-muted)' }}>
                Showing {filteredSessions.length} of {sessions.length} sessions
              </span>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="chip-btn" onClick={expandAllSessions}>Expand All</button>
              <button className="chip-btn" onClick={collapseAllSessions}>Collapse All</button>
            </div>
          </div>

          <div className="sessions-container">
            {filteredSessions.map((s) => {
              const detail = detailCache[s.session_id]
              const isExpanded = expandedSessions.has(s.session_id)
              const riskCls = `sev-${s.risk_label || 'low'}`
              const sessionScoreRating = getPostureRating(s.posture_score)

              return (
                <div key={s.session_id} className={`session-card-modern ${riskCls}`}>
                  <div className="session-card-summary" onClick={() => toggleSession(s.session_id)}>
                    <div className="session-left-meta">
                      <span className={`protocol-tag proto-${(s.protocol || 'unknown').toLowerCase()}`}>
                        {s.protocol || 'UNKNOWN'}
                      </span>

                      <div className="network-flow-text">
                        <span className="ip-chip client">{s.client_ip}:{s.client_port}</span>
                        <span className="flow-arrow">➔</span>
                        <span className="ip-chip server">{s.server_ip}:{s.server_port}</span>
                      </div>

                      <button
                        className="copy-mini-btn"
                        title="Copy connection stream IPs"
                        onClick={(e) => {
                          e.stopPropagation()
                          copyToClipboard(`${s.client_ip}:${s.client_port} -> ${s.server_ip}:${s.server_port}`, `stream-${s.session_id}`)
                        }}
                      >
                        {copiedKey === `stream-${s.session_id}` ? (
                          <span style={{ color: 'var(--sev-safe)' }}>✓ Copied</span>
                        ) : (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                          </svg>
                        )}
                      </button>
                    </div>

                    <div className="session-right-meta">
                      {s.encrypted ? (
                        <span className="status-badge-compact encrypted">
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                          TLS
                        </span>
                      ) : (
                        <span className="status-badge-compact plaintext">
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 9.9-1" /></svg>
                          Plaintext
                        </span>
                      )}

                      {s.starttls && (
                        <span className="status-badge-compact starttls">
                          STARTTLS {s.starttls_stripped ? '⚠️ STRIPPED' : '✓'}
                        </span>
                      )}

                      {detail?.pqc && (
                        <span
                          className={`status-badge-compact ${detail.pqc.pqc_status === 'QUANTUM_RESISTANT' ? 'encrypted' : 'plaintext'}`}
                          title={`Quantum Status: ${detail.pqc.pqc_status} (Score: ${detail.pqc.quantum_vulnerability_score}/100)`}
                        >
                          ⚛️ {detail.pqc.pqc_status === 'QUANTUM_RESISTANT' ? 'PQC Safe' : 'HNDL Risk'}
                        </span>
                      )}

                      {detail?.attribution && (
                        <span
                          className="status-badge-compact"
                          style={{
                            background: detail.attribution.is_threat ? 'var(--sev-critical-bg)' : 'rgba(56, 168, 86, 0.12)',
                            color: detail.attribution.is_threat ? 'var(--sev-critical)' : 'var(--primary)',
                            border: `1px solid ${detail.attribution.is_threat ? 'var(--sev-critical-border)' : 'var(--border-color)'}`
                          }}
                          title={`Client: ${detail.attribution.client_name} (${detail.attribution.client_category})`}
                        >
                          {detail.attribution.is_threat ? '⚠️ ' : '👤 '}{detail.attribution.client_name.split(' ')[0]}
                        </span>
                      )}

                      <span
                        className="risk-level-badge"
                        style={{
                          background: (SEV_COLORS[s.risk_label] || '#64748b') + '20',
                          color: SEV_COLORS[s.risk_label] || '#64748b',
                          border: `1px solid ${SEV_COLORS[s.risk_label] || '#64748b'}40`
                        }}
                      >
                        {s.risk_label} risk
                      </span>


                      <PostureRing score={s.posture_score} size={42} strokeWidth={4} />

                      <span className="chip-btn" style={{ padding: '3px 8px', fontSize: '11px' }}>
                        {s.finding_count} {s.finding_count === 1 ? 'finding' : 'findings'}
                      </span>

                      <svg className={`expand-chevron ${isExpanded ? 'expanded' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>

                  {/* Expanded Session Forensic Deep-Dive */}
                  {isExpanded && (
                    <div className="session-detail-body">
                      {!detail ? (
                        <div className="loading-card" style={{ padding: '16px' }}>
                          <div className="spinner"></div>
                          <span>Loading cryptographic handshake &amp; certificate forensics…</span>
                        </div>
                      ) : (
                        <>
                          <div className="forensic-sections-grid">
                            {/* Handshake & Crypto Specs */}
                            <div className="forensic-box">
                              <div className="forensic-box-title">
                                <span>TLS Handshake Forensics</span>
                                {detail.tls && (
                                  <button
                                    className="copy-mini-btn"
                                    onClick={() => copyToClipboard(JSON.stringify(detail.tls, null, 2), `tls-${s.session_id}`)}
                                  >
                                    {copiedKey === `tls-${s.session_id}` ? '✓ Copied' : 'Copy TLS Specs'}
                                  </button>
                                )}
                              </div>

                              {detail.tls ? (
                                <>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Negotiated Version</span>
                                    <span className="prop-val" style={{ color: detail.tls.version?.includes('1.3') ? 'var(--sev-safe)' : detail.tls.version?.includes('1.2') ? 'var(--sev-low)' : 'var(--sev-critical)' }}>
                                      {detail.tls.version || 'None'}
                                    </span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Cipher Suite</span>
                                    <span className="prop-val" title={detail.tls.cipher_suite}>
                                      {detail.tls.cipher_suite || 'None'}
                                    </span>
                                  </div>
                                  {detail.tls.key_exchange && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">Key Exchange</span>
                                      <span className="prop-val">{detail.tls.key_exchange}</span>
                                    </div>
                                  )}
                                  {detail.tls.server_name && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">Server Name (SNI)</span>
                                      <span className="prop-val">{detail.tls.server_name}</span>
                                    </div>
                                  )}
                                  {detail.tls.ja4 && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">JA4 (Client)</span>
                                      <span className="prop-val" style={{ fontSize: '11px', fontFamily: 'monospace' }}>
                                        {detail.tls.ja4}
                                        <button
                                          className="copy-mini-btn"
                                          onClick={() => copyToClipboard(detail.tls.ja4, `ja4-${s.session_id}`)}
                                        >
                                          {copiedKey === `ja4-${s.session_id}` ? '✓' : 'Copy'}
                                        </button>
                                      </span>
                                    </div>
                                  )}
                                  {detail.tls.ja4s && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">JA4S (Server)</span>
                                      <span className="prop-val" style={{ fontSize: '11px', fontFamily: 'monospace' }}>
                                        {detail.tls.ja4s}
                                        <button
                                          className="copy-mini-btn"
                                          onClick={() => copyToClipboard(detail.tls.ja4s, `ja4s-${s.session_id}`)}
                                        >
                                          {copiedKey === `ja4s-${s.session_id}` ? '✓' : 'Copy'}
                                        </button>
                                      </span>
                                    </div>
                                  )}
                                  {detail.tls.ja3 && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">JA3 Fingerprint</span>
                                      <span className="prop-val" style={{ fontSize: '11px' }}>
                                        {detail.tls.ja3.substring(0, 16)}…
                                        <button
                                          className="copy-mini-btn"
                                          onClick={() => copyToClipboard(detail.tls.ja3, `ja3-${s.session_id}`)}
                                        >
                                          {copiedKey === `ja3-${s.session_id}` ? '✓' : 'Copy'}
                                        </button>
                                      </span>
                                    </div>
                                  )}
                                </>
                              ) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', padding: '8px 0' }}>
                                  No TLS handshake observed on this stream. Communication transpired in cleartext.
                                </div>
                              )}
                            </div>

                            {/* X.509 Certificate Profile */}
                            <div className="forensic-box">
                              <div className="forensic-box-title">
                                <span>X.509 Certificate Profile</span>
                                {detail.certificate && (
                                  <span style={{ fontSize: '11px', color: detail.certificate.trusted ? 'var(--sev-safe)' : 'var(--sev-critical)' }}>
                                    {detail.certificate.trusted ? '● TRUSTED' : detail.certificate.self_signed ? '● SELF-SIGNED' : '● UNTRUSTED'}
                                  </span>
                                )}
                              </div>

                              {detail.certificate ? (
                                <>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Subject CN</span>
                                    <span className="prop-val">{detail.certificate.subject || '—'}</span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Issuer CA</span>
                                    <span className="prop-val">{detail.certificate.issuer || '—'}</span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Public Key</span>
                                    <span className="prop-val">
                                      {detail.certificate.public_key_algorithm} {detail.certificate.key_size ? `${detail.certificate.key_size}-bit` : ''}
                                    </span>
                                  </div>
                                  {detail.certificate.ja4x && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">JA4X (Cert FP)</span>
                                      <span className="prop-val" style={{ fontSize: '11px', fontFamily: 'monospace' }}>
                                        {detail.certificate.ja4x}
                                        <button
                                          className="copy-mini-btn"
                                          onClick={() => copyToClipboard(detail.certificate.ja4x, `ja4x-${s.session_id}`)}
                                        >
                                          {copiedKey === `ja4x-${s.session_id}` ? '✓' : 'Copy'}
                                        </button>
                                      </span>
                                    </div>
                                  )}
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Validity Status</span>
                                    <span className="prop-val" style={{ color: detail.certificate.expired ? 'var(--sev-critical)' : 'var(--sev-safe)' }}>
                                      {detail.certificate.expired
                                        ? 'EXPIRED'
                                        : detail.certificate.days_to_expiry !== null
                                          ? `Expires in ${detail.certificate.days_to_expiry} days`
                                          : 'Valid'}
                                    </span>
                                  </div>
                                  {/* Certificate Chain Visualizer */}
                                  <div style={{ marginTop: '10px', borderTop: '1px dashed var(--border-color)', paddingTop: '10px' }}>
                                    <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>Certificate Trust Chain</div>
                                    <CertChainVisualizer certificate={detail.certificate} />
                                  </div>
                                </>
                              ) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', padding: '8px 0' }}>
                                  No server certificate exchanged during this connection.
                                </div>
                              )}
                            </div>

                            {/* Stream Metadata & Telemetry */}
                            <div className="forensic-box">
                              <div className="forensic-box-title">
                                <span>Stream Telemetry</span>
                                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ID: {s.session_id.substring(0, 8)}</span>
                              </div>
                              <div className="forensic-property-row">
                                <span className="prop-key">Packets Transferred</span>
                                <span className="prop-val">{detail.packets || '—'} pkts</span>
                              </div>
                              <div className="forensic-property-row">
                                <span className="prop-key">Client ➔ Server</span>
                                <span className="prop-val">{formatBytes(detail.bytes_c2s)}</span>
                              </div>
                              <div className="forensic-property-row">
                                <span className="prop-key">Server ➔ Client</span>
                                <span className="prop-val">{formatBytes(detail.bytes_s2c)}</span>
                              </div>
                              <div className="forensic-property-row">
                                <span className="prop-key">ML Anomaly Flag</span>
                                <span className="prop-val" style={{ color: detail.ml_anomaly ? 'var(--sev-high)' : 'var(--sev-safe)' }}>
                                  {detail.ml_anomaly ? '⚠️ Unusual Pattern' : '✓ Normal Profile'}
                                </span>
                              </div>
                            </div>

                            {/* Downgrade Protection (MTA-STS & DANE) */}
                            <div className="forensic-box">
                              <div className="forensic-box-title">
                                <span>Downgrade Protection (RFC 8461/7672)</span>
                                {detail.dns_security && (
                                  <span style={{
                                    fontSize: '11px',
                                    fontWeight: 600,
                                    color: detail.dns_security.mta_sts_mode === 'enforce' || detail.dns_security.dane_valid
                                      ? 'var(--sev-safe)'
                                      : detail.dns_security.mta_sts_mode === 'testing'
                                        ? 'var(--sev-low)'
                                        : 'var(--sev-medium)'
                                  }}>
                                    {detail.dns_security.mta_sts_mode === 'enforce'
                                      ? '● MTA-STS ENFORCE'
                                      : detail.dns_security.dane_valid
                                        ? '● DANE VALIDATED'
                                        : detail.dns_security.mta_sts_mode === 'testing'
                                          ? '● MTA-STS TESTING'
                                          : '● NO ACTIVE POLICY'}
                                  </span>
                                )}
                              </div>

                              {detail.dns_security ? (
                                <>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Mail Domain</span>
                                    <span className="prop-val" style={{ fontFamily: 'monospace' }}>
                                      {detail.dns_security.domain || detail.dns_security.hostname || '—'}
                                    </span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">MTA-STS Mode</span>
                                    <span className="prop-val" style={{
                                      color: detail.dns_security.mta_sts_mode === 'enforce'
                                        ? 'var(--sev-safe)'
                                        : detail.dns_security.mta_sts_mode === 'testing'
                                          ? 'var(--sev-low)'
                                          : 'var(--text-muted)'
                                    }}>
                                      {detail.dns_security.mta_sts_mode
                                        ? `Mode: ${detail.dns_security.mta_sts_mode.toUpperCase()}`
                                        : detail.dns_security.mta_sts_record
                                          ? 'Configured'
                                          : 'Not Published'}
                                    </span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">DANE TLSA Status</span>
                                    <span className="prop-val" style={{
                                      color: detail.dns_security.dane_match_status === 'MATCH'
                                        ? 'var(--sev-safe)'
                                        : detail.dns_security.dane_match_status === 'MISMATCH'
                                          ? 'var(--sev-critical)'
                                          : 'var(--text-muted)'
                                    }}>
                                      {detail.dns_security.dane_match_status === 'MATCH'
                                        ? '✓ Validated against Leaf Cert'
                                        : detail.dns_security.dane_match_status === 'MISMATCH'
                                          ? '⚠️ TLSA Mismatch'
                                          : detail.dns_security.dane_tlsa_records?.length > 0
                                            ? `${detail.dns_security.dane_tlsa_records.length} Record(s)`
                                            : 'Not Published'}
                                    </span>
                                  </div>
                                  {(detail.dns_security.recommended_mta_sts_dns || detail.dns_security.recommended_mta_sts_policy) && (
                                    <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px dashed var(--border-color)' }}>
                                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--accent-primary)', marginBottom: '4px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <span>Advisory Policy Snippet</span>
                                        {detail.dns_security.recommended_mta_sts_dns && (
                                          <button
                                            className="copy-mini-btn"
                                            onClick={() => copyToClipboard(detail.dns_security.recommended_mta_sts_dns, `dns-rec-${s.session_id}`)}
                                          >
                                            {copiedKey === `dns-rec-${s.session_id}` ? '✓ Copied' : 'Copy DNS Record'}
                                          </button>
                                        )}
                                      </div>
                                      {detail.dns_security.recommended_mta_sts_dns && (
                                        <div style={{ fontSize: '10px', fontFamily: 'monospace', color: 'var(--text-secondary)', background: 'var(--bg-app)', padding: '4px 6px', borderRadius: '4px', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                                          {detail.dns_security.recommended_mta_sts_dns}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </>
                              ) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', padding: '8px 0' }}>
                                  No destination mail domain resolved for DNS advisory evaluation.
                                </div>
                              )}
                            </div>

                            {/* Post-Quantum Cryptography (PQC) Readiness */}
                            <div className="forensic-box">
                              <div className="forensic-box-title">
                                <span>⚛️ Post-Quantum Readiness (FIPS 203)</span>
                                {detail.pqc && (
                                  <span style={{
                                    fontSize: '11px',
                                    fontWeight: 600,
                                    color: detail.pqc.pqc_status === 'QUANTUM_RESISTANT' ? 'var(--sev-safe)' : detail.pqc.pqc_status === 'TRANSITIONAL' ? 'var(--sev-low)' : 'var(--sev-critical)'
                                  }}>
                                    ● {detail.pqc.pqc_status.replace(/_/g, ' ')}
                                  </span>
                                )}
                              </div>

                              {detail.pqc ? (
                                <>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Quantum KEM</span>
                                    <span className="prop-val" style={{ color: detail.pqc.quantum_safe_kem ? 'var(--sev-safe)' : 'var(--sev-high)' }}>
                                      {detail.pqc.kem_algorithm || 'None (Classical ECDHE)'}
                                    </span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">HNDL Risk Profile</span>
                                    <span className="prop-val" style={{ color: detail.pqc.hndl_risk === 'LOW' ? 'var(--sev-safe)' : detail.pqc.hndl_risk === 'CRITICAL' ? 'var(--sev-critical)' : 'var(--sev-medium)' }}>
                                      {detail.pqc.hndl_risk} (Harvest Now Decrypt Later)
                                    </span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Quantum Exposure</span>
                                    <span className="prop-val">
                                      <b>{detail.pqc.quantum_vulnerability_score}</b>/100
                                    </span>
                                  </div>
                                  {detail.pqc.standard_compliance && detail.pqc.standard_compliance.length > 0 && (
                                    <div className="forensic-property-row">
                                      <span className="prop-key">Standards</span>
                                      <span className="prop-val" style={{ fontSize: '11px' }}>
                                        {detail.pqc.standard_compliance.join(', ')}
                                      </span>
                                    </div>
                                  )}
                                </>
                              ) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', padding: '8px 0' }}>
                                  PQC metrics unavailable for this stream.
                                </div>
                              )}
                            </div>

                            {/* Threat Actor & Client Attribution via JA4 */}
                            <div className="forensic-box">
                              <div className="forensic-box-title">
                                <span>🎯 JA4 Client &amp; Threat Attribution</span>
                                {detail.attribution && (
                                  <span style={{
                                    fontSize: '11px',
                                    fontWeight: 600,
                                    color: detail.attribution.is_threat ? 'var(--sev-critical)' : 'var(--sev-safe)'
                                  }}>
                                    ● {detail.attribution.confidence.toUpperCase()} CONFIDENCE
                                  </span>
                                )}
                              </div>

                              {detail.attribution ? (
                                <>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Identified Client</span>
                                    <span className="prop-val" style={{ fontWeight: 600 }}>
                                      {detail.attribution.client_name}
                                    </span>
                                  </div>
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Category</span>
                                    <span className="prop-val">
                                      {detail.attribution.client_category.replace(/_/g, ' ').toUpperCase()}
                                    </span>
                                  </div>
                                  {detail.attribution.masquerading_detected && (
                                    <div style={{ margin: '8px 0', padding: '8px', background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical-border)', borderRadius: '4px', color: 'var(--sev-critical)', fontSize: '11px' }}>
                                      <b>🚨 Masquerading Alert:</b> {detail.attribution.masquerading_details}
                                    </div>
                                  )}
                                  <div className="forensic-property-row">
                                    <span className="prop-key">Automation</span>
                                    <span className="prop-val" style={{ color: detail.attribution.is_automation ? 'var(--sev-medium)' : 'var(--sev-safe)' }}>
                                      {detail.attribution.is_automation ? 'Automated / Script' : 'Interactive User'}
                                    </span>
                                  </div>
                                </>
                              ) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', padding: '8px 0' }}>
                                  Client attribution unavailable.
                                </div>
                              )}
                            </div>
                          </div>

                          {/* 1-Click Hardening Config Generator Trigger */}
                          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '16px', gap: '8px' }}>
                            <button
                              className="chip-btn"
                              style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', background: 'var(--bg-surface)', border: '1px solid var(--primary)', color: 'var(--primary)', padding: '7px 14px', fontWeight: 600 }}
                              onClick={() => openHardeningModal(s.session_id)}
                              title="Generate copy-pasteable configurations for Postfix, Dovecot, and Exim"
                            >
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                              1-Click Server Hardening (Postfix / Dovecot / Exim)
                            </button>
                          </div>

                          {/* Actionable Findings & Mitigations */}
                          <div className="session-findings-container">
                            <div className="findings-header">

                              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                              </svg>
                              <span>Cryptographic Vulnerability Findings ({detail.findings.length})</span>
                            </div>

                            {detail.findings.length === 0 ? (
                              <div className="no-findings-msg">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>
                                <span>No security weaknesses detected — stream meets modern cryptographic standards.</span>
                              </div>
                            ) : (
                              detail.findings.map((f, idx) => (
                                <div key={f.id + idx} className="finding-item-card">
                                  <div className="finding-title-row">
                                    <span
                                      className="finding-sev-pill"
                                      style={{
                                        background: (SEV_COLORS[f.severity] || '#64748b') + '22',
                                        color: SEV_COLORS[f.severity] || '#64748b',
                                        border: `1px solid ${SEV_COLORS[f.severity] || '#64748b'}50`
                                      }}
                                    >
                                      {f.severity}
                                    </span>
                                    <span className="finding-title-text">{f.title}</span>
                                    {f.category && (
                                      <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                                        [{f.category}]
                                      </span>
                                    )}
                                  </div>
                                  <div className="finding-desc-text">{f.description}</div>
                                  {f.recommendation && (
                                    <div className="finding-rec-box">
                                      <b>Remediation:</b> {f.recommendation}
                                    </div>
                                  )}
                                </div>
                              ))
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )
            })}

            {filteredSessions.length === 0 && (
              <div className="panel-card" style={{ textAlign: 'center', padding: '40px' }}>
                <div style={{ color: 'var(--text-muted)', marginBottom: '8px' }}>No sessions matched your filter criteria.</div>
                <button className="btn-secondary" onClick={() => { setSearchQuery(''); setProtocolFilter('ALL'); setRiskFilter('ALL'); setKpiFilter('ALL'); }}>
                  Reset Filters
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {/* ==========================================================================
          COMPLIANCE MATRIX TAB
         ========================================================================== */}
      {activeTab === 'compliance' && (
        <div className="compliance-container">
          {complianceLoading && (
            <div className="loading-card">
              <div className="spinner"></div>
              <span>Auditing PCAP sessions against regulatory frameworks (PCI-DSS 4.0, NIST 800-52r2, HIPAA)…</span>
            </div>
          )}

          {!compliance && !complianceLoading && !jobId && (
            <div className="panel-card" style={{ textAlign: 'center', padding: '40px' }}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ color: 'var(--text-muted)', margin: '0 auto 12px' }}>
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" />
              </svg>
              <div style={{ fontSize: '15px', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '6px' }}>No Capture Data Available</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px' }}>Please analyze a PCAP file or load the demo sample first to generate the regulatory compliance audit matrix.</div>
              <button className="btn-primary" onClick={doLoadDemo} disabled={loading}>
                ⚡ Load Demo PCAP Now
              </button>
            </div>
          )}

          {compliance && !complianceLoading && (
            <>
              {/* Framework Verdict Cards */}
              <div className="compliance-cards-grid">
                {compliance.frameworks.map((fw) => {
                  const totalTested = (fw.passed || 0) + (fw.failed || 0)
                  const passPct = totalTested > 0 ? Math.round(((fw.passed || 0) / totalTested) * 100) : 100
                  return (
                    <div key={fw.framework} className="compliance-verdict-card">
                      <div className="fw-card-top">
                        <div className="fw-title">{fw.framework}</div>
                        <div className="verdict-text" style={{ color: VERDICT_COLORS[fw.verdict] || '#64748b' }}>
                          {fw.verdict}
                        </div>
                      </div>

                      <div className="fw-meter-wrapper">
                        <div className="fw-meter-label">
                          <span>Readiness Ratio</span>
                          <span style={{ fontWeight: '700', color: fw.verdict === 'PASS' ? '#10b981' : fw.verdict === 'CONDITIONAL' ? '#f59e0b' : '#ef4444' }}>{passPct}%</span>
                        </div>
                        <div className="fw-meter-track">
                          <div
                            className="fw-meter-fill"
                            style={{
                              width: `${passPct}%`,
                              background: fw.verdict === 'PASS'
                                ? '#38a856'
                                : fw.verdict === 'CONDITIONAL'
                                  ? '#ffca3a'
                                  : '#ff595e'
                            }}
                          />
                        </div>
                      </div>

                      <div className="compliance-stats-row">
                        <span style={{ color: 'var(--sev-safe)' }}>✓ {fw.passed} Passed</span>
                        <span style={{ color: 'var(--sev-critical)' }}>✗ {fw.failed} Failed</span>
                        <span style={{ color: 'var(--text-muted)' }}>— {fw.na} N/A</span>
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Interactive Controls Table */}
              <div className="compliance-table-card">
                <div className="table-toolbar">
                  <div className="search-input-wrapper" style={{ maxWidth: '320px' }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
                    <input
                      type="text"
                      placeholder="Filter control ID or name..."
                      value={complianceSearch}
                      onChange={(e) => setComplianceSearch(e.target.value)}
                    />
                  </div>

                  <div className="filter-chips-group">
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>STATUS:</span>
                    {['ALL', 'PASS', 'FAIL', 'N/A'].map(st => (
                      <button
                        key={st}
                        className={`chip-btn ${complianceStatusFilter === st ? 'active' : ''}`}
                        onClick={() => setComplianceStatusFilter(st)}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="table-responsive">
                  <table className="matrix-table">
                    <thead>
                      <tr>
                        <th style={{ width: '80px' }}>Control ID</th>
                        <th>Mandated Control Requirement</th>
                        <th style={{ textAlign: 'center' }}>PCI-DSS 4.0</th>
                        <th style={{ textAlign: 'center' }}>NIST 800-52r2</th>
                        <th style={{ textAlign: 'center' }}>HIPAA Security Rule</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredControls.map((ctrl) => (
                        <tr key={ctrl.control_id}>
                          <td>
                            <span className="ctrl-id-badge">{ctrl.control_id}</span>
                          </td>
                          <td style={{ fontWeight: '500' }}>{ctrl.control_name}</td>
                          {['PCI-DSS 4.0', 'NIST 800-52r2', 'HIPAA'].map((fw) => {
                            const fwd = ctrl.frameworks[fw] || { status: 'N/A', citation: '' }
                            const st = fwd.status
                            const icon = st === 'PASS' ? '✓' : st === 'FAIL' ? '✗' : '—'
                            return (
                              <td key={fw} style={{ textAlign: 'center' }}>
                                <span
                                  className="status-chip-table"
                                  style={{
                                    background: (STATUS_COLORS[st] || '#64748b') + '15',
                                    color: STATUS_COLORS[st] || '#64748b',
                                    border: `1px solid ${STATUS_COLORS[st] || '#64748b'}40`
                                  }}
                                >
                                  {icon} {st}
                                </span>
                                {fwd.citation && (
                                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '3px' }}>
                                    {fwd.citation}
                                  </div>
                                )}
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ==========================================================================
          LIVE SNIFFER TAB (Real-Time WebSocket Streaming)
         ========================================================================== */}
      {activeTab === 'live' && (
        <div>
          <div className="panel-card" style={{ marginBottom: '20px' }}>
            <div className="panel-card-title">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="2" /><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
                </svg>
                <span>Real-Time Network Interface Sniffer &amp; WebSocket Stream</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '3px 9px',
                  borderRadius: '12px',
                  background: wsConnected ? 'rgba(56, 168, 86, 0.15)' : 'rgba(255, 146, 76, 0.15)',
                  color: wsConnected ? 'var(--sev-safe)' : 'var(--sev-high)',
                  border: `1px solid ${wsConnected ? 'rgba(56, 168, 86, 0.3)' : 'rgba(255, 146, 76, 0.3)'}`
                }}>
                  {wsConnected ? '● WS STREAM CONNECTED' : '○ WS CONNECTING…'}
                </span>

                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '3px 9px',
                  borderRadius: '12px',
                  background: liveEngine === 'pyshark' ? 'rgba(14, 165, 233, 0.15)' : (liveEngine === 'scapy' ? 'rgba(168, 85, 247, 0.15)' : 'rgba(234, 179, 8, 0.15)'),
                  color: liveEngine === 'pyshark' ? '#0ea5e9' : (liveEngine === 'scapy' ? '#a855f7' : '#eab308'),
                  border: '1px solid currentColor',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px'
                }}>
                  {liveEngine === 'pyshark' ? '⚡ PYSHARK WIRE' : (liveEngine === 'scapy' ? '🐍 SCAPY SNIFFER' : (simulationMode ? '📦 PCAP REPLAY' : '🧪 ACTIVE STREAM ENGINE'))}
                </span>

                {liveCapturing && (
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '3px 9px',
                    borderRadius: '12px',
                    background: 'var(--sev-critical-bg)',
                    color: 'var(--sev-critical)',
                    border: '1px solid var(--sev-critical-border)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}>
                    <span className="live-pulse-dot"></span>
                    REC: {captureRemaining}s
                  </span>
                )}
              </div>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
              Sniff live packets across local network interfaces or simulate mail traffic streams, reassembling TCP flows in flight and assessing email TLS cryptographic posture via WebSocket in real time.
            </p>

            {/* Active Notice / OS Permission Tip */}
            {liveNotice && (
              <div style={{
                background: 'rgba(234, 179, 8, 0.1)',
                border: '1px solid rgba(234, 179, 8, 0.3)',
                borderRadius: '8px',
                padding: '10px 14px',
                color: '#facc15',
                fontSize: '12px',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '15px' }}>ℹ️</span>
                  <span>{liveNotice}</span>
                </div>
                <button
                  onClick={() => setLiveNotice(null)}
                  style={{ background: 'none', border: 'none', color: '#facc15', cursor: 'pointer', fontWeight: 700 }}
                >
                  ✕
                </button>
              </div>
            )}

            {/* Controls Bar */}
            <div className="live-controls-bar">
              {/* Mode Toggle */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label className="form-label" style={{ fontSize: '11px', textTransform: 'uppercase' }}>Capture Source:</label>
                <div className="mode-toggle-group">
                  <button
                    className={`mode-toggle-btn ${!simulationMode ? 'active' : ''}`}
                    onClick={() => setSimulationMode(false)}
                    disabled={liveCapturing}
                  >
                    Hardware Interface (Live)
                  </button>
                  <button
                    className={`mode-toggle-btn ${simulationMode ? 'active' : ''}`}
                    onClick={() => setSimulationMode(true)}
                    disabled={liveCapturing}
                  >
                    Simulation Mode (Sample PCAP)
                  </button>
                </div>
              </div>

              {/* Interface or Simulation Selector */}
              {!simulationMode ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', minWidth: '240px' }}>
                  <label className="form-label" style={{ fontSize: '11px', textTransform: 'uppercase' }}>Network Adapter:</label>
                  <select
                    id="network-adapter-select"
                    className="custom-select"
                    value={selectedInterface}
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    disabled={liveCapturing}
                    style={{ padding: '6px 12px', fontSize: '12.5px', minWidth: '260px' }}
                  >
                    {interfaces.map(i => (
                      <option key={i.name} value={i.name}>
                        {i.description || i.name} {i.ip ? `(${i.ip})` : ''}
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxWidth: '300px' }}>
                  <label className="form-label" style={{ fontSize: '11px', textTransform: 'uppercase' }}>Simulation Dataset:</label>
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)', background: 'var(--bg-app)', padding: '6px 10px', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                    📦 Replaying realistic SMTP/IMAP/POP3 email streams from sample PCAP
                  </span>
                </div>
              )}

              {/* Protocol Filter */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', minWidth: '180px' }}>
                <label className="form-label" style={{ fontSize: '11px', textTransform: 'uppercase' }}>Protocol Filter:</label>
                <select
                  id="live-protocol-filter"
                  className="custom-select"
                  value={liveProtocolFilter}
                  onChange={(e) => setLiveProtocolFilter(e.target.value)}
                  disabled={liveCapturing}
                  style={{ padding: '6px 12px', fontSize: '12.5px' }}
                >
                  <option value="all">All Mail (25, 465, 587, 143, 993, 110, 995)</option>
                  <option value="smtp">SMTP Only (25, 465, 587)</option>
                  <option value="imap">IMAP Only (143, 993)</option>
                  <option value="pop3">POP3 Only (110, 995)</option>
                </select>
              </div>

              {/* Duration Slider */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', width: '150px' }}>
                <label className="form-label" style={{ fontSize: '11px', textTransform: 'uppercase' }}>
                  Duration: <b>{liveDuration}s</b>
                </label>
                <input
                  type="range"
                  min="5"
                  max="60"
                  value={liveDuration}
                  onChange={(e) => setLiveDuration(Number(e.target.value))}
                  className="range-slider"
                  disabled={liveCapturing}
                />
              </div>

              {/* Start / Stop Button */}
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                {liveCapturing ? (
                  <button
                    className="btn-danger"
                    onClick={stopLiveSniffing}
                    style={{ background: 'var(--sev-critical)', color: '#fff', border: 'none', padding: '9px 18px', borderRadius: '6px', fontWeight: '700', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
                  >
                    <span className="live-pulse-dot" style={{ background: '#fff' }}></span>
                    Stop Sniffing ({captureRemaining}s)
                  </button>
                ) : (
                  <button
                    className="btn-primary"
                    onClick={startLiveSniffing}
                    disabled={!wsConnected || (!simulationMode && !selectedInterface)}
                    style={{ padding: '9px 20px', display: 'flex', alignItems: 'center', gap: '8px' }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3" /></svg>
                    Start Real-Time Sniffing
                  </button>
                )}
              </div>
            </div>

            {/* Metrics Strip */}
            <div className="live-metrics-strip">
              <div className="live-metric-card">
                <span className="live-metric-label">Packets Streamed</span>
                <span className="live-metric-val">{liveStats.packets || 0}</span>
              </div>
              <div className="live-metric-card">
                <span className="live-metric-label">Payload Transferred</span>
                <span className="live-metric-val">{formatBytes(liveStats.bytes || 0)}</span>
              </div>
              <div className="live-metric-card">
                <span className="live-metric-label">Reassembled Streams</span>
                <span className="live-metric-val">{liveSessions.length}</span>
              </div>
              <div className="live-metric-card">
                <span className="live-metric-label">Capture Elapsed</span>
                <span className="live-metric-val">{liveStats.elapsed || 0}s / {liveDuration}s</span>
              </div>
            </div>

            {/* Streaming Visualizer Grid: Terminal + Discovered Sessions */}
            <div className="live-streaming-grid">
              {/* Packet Wire Stream Console */}
              <div className="live-terminal-container">
                <div className="live-terminal-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ color: '#4ade80' }}>⚡</span>
                    <span>REAL-TIME PACKET WIRE STREAM ({livePackets.length})</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer', fontSize: '11px', color: '#9ca3af' }}>
                      <input
                        type="checkbox"
                        checked={autoScroll}
                        onChange={(e) => setAutoScroll(e.target.checked)}
                      />
                      Auto-scroll
                    </label>
                    <button
                      className="copy-mini-btn"
                      onClick={() => setLivePackets([])}
                      style={{ background: '#1f2937', color: '#9ca3af', border: '1px solid #374151' }}
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <div className="live-terminal-body" ref={terminalBodyRef}>
                  {livePackets.length === 0 ? (
                    <div style={{ padding: '30px', textAlign: 'center', color: '#6b7280' }}>
                      {liveCapturing
                        ? 'Sniffing wire... Waiting for incoming email traffic packets on interface.'
                        : 'Capture is idle. Click "Start Real-Time Sniffing" to stream live packet forensics.'}
                    </div>
                  ) : (
                    livePackets.map((p, idx) => (
                      <div key={idx} className="live-packet-row">
                        <span style={{ color: '#6b7280' }}>#{p.packet_num || idx + 1}</span>
                        <span style={{ color: '#9ca3af' }}>
                          {new Date(p.ts * 1000).toISOString().substr(14, 9)}
                        </span>
                        <span>
                          <span className={`live-proto-badge ${p.protocol || 'TCP'}`}>
                            {p.protocol || 'TCP'}
                          </span>
                        </span>
                        <span style={{ color: '#60a5fa', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={`${p.src} ➔ ${p.dst}`}>
                          {p.src} ➔ {p.dst}
                        </span>
                        <span style={{ color: '#fbbf24' }}>
                          {p.bytes}B
                        </span>
                        <span style={{ color: '#e5e7eb', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.summary}>
                          {p.summary || '—'}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Reassembled Live Sessions Feed */}
              <div className="live-sessions-feed">
                <div className="live-sessions-header">
                  <span>DISCOVERED EMAIL STREAMS ({liveSessions.length})</span>
                  {liveCapturing && <span className="live-pulse-dot"></span>}
                </div>

                <div className="live-sessions-list">
                  {liveSessions.length === 0 ? (
                    <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12.5px' }}>
                      No full TCP email sessions reassembled yet. As handshakes transpire, analyzed streams appear here in real time.
                    </div>
                  ) : (
                    liveSessions.map((s) => (
                      <div key={s.session_id} className="live-session-item-card">
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span className="proto-badge" style={{ fontSize: '10px', padding: '2px 6px' }}>{s.protocol?.toUpperCase()}</span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700 }}>{s.session_id.substring(0, 8)}</span>
                          </div>
                          <span
                            className="risk-level-badge"
                            style={{
                              background: (SEV_COLORS[s.risk_label] || '#64748b') + '20',
                              color: SEV_COLORS[s.risk_label] || '#64748b',
                              border: `1px solid ${SEV_COLORS[s.risk_label] || '#64748b'}40`,
                              fontSize: '10.5px',
                              padding: '2px 6px'
                            }}
                          >
                            {s.risk_label}
                          </span>
                        </div>

                        <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                          {s.client_ip}:{s.client_port} ➔ {s.server_ip}:{s.server_port}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', paddingTop: '4px', borderTop: '1px solid var(--border-color)' }}>
                          <span style={{ color: s.encrypted ? 'var(--sev-safe)' : 'var(--sev-critical)', fontWeight: 600 }}>
                            {s.encrypted ? '✓ Encrypted (TLS)' : '⚠️ Plaintext Stream'}
                          </span>
                          <span style={{ fontWeight: 700 }}>
                            Posture: {s.posture_score ?? '—'}/100
                          </span>
                          <span style={{ color: 'var(--text-muted)' }}>
                            {s.finding_count || 0} findings
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Completed Job Handoff CTA */}
            {liveCompletedJob && (
              <div className="live-completed-cta">
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--primary-hover)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>🎉 Live Capture Analysis Ready!</span>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      (Job ID: {liveCompletedJob.job_id})
                    </span>
                  </div>
                  <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '3px' }}>
                    Reassembled and evaluated <b>{liveCompletedJob.session_count} email streams</b> across {liveStats.packets} packets with automated posture scoring.
                  </div>
                </div>

                <button
                  className="btn-primary"
                  onClick={openLiveAnalysis}
                  style={{ padding: '10px 20px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <span>Open Full SOC Forensic Analysis &amp; Reports</span>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6" /></svg>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==========================================================================
          ML STUDIO TAB
         ========================================================================== */}
      {activeTab === 'ml' && (
        <div className="panel-card">
          <div className="panel-card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
            </svg>
            <span>Machine Learning Model Studio &amp; Telemetry</span>
          </div>

          {mlStatus ? (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '20px' }}>
                <div className="forensic-box">
                  <div className="forensic-box-title">Risk Classifier (Random Forest)</div>
                  <div style={{ fontSize: '18px', fontWeight: '700', color: mlStatus.risk_model_ready ? 'var(--sev-safe)' : 'var(--sev-critical)' }}>
                    {mlStatus.risk_model_ready ? '✓ Model Loaded & Active' : '✗ Model Not Initialized'}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Multi-class classification (Low, Medium, High, Critical)
                  </div>
                </div>

                <div className="forensic-box">
                  <div className="forensic-box-title">Anomaly Detector (Isolation Forest)</div>
                  <div style={{ fontSize: '18px', fontWeight: '700', color: mlStatus.anomaly_model_ready ? 'var(--sev-safe)' : 'var(--sev-critical)' }}>
                    {mlStatus.anomaly_model_ready ? '✓ Model Loaded & Active' : '✗ Model Not Initialized'}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Unsupervised anomaly detection on TLS handshake distributions
                  </div>
                </div>

                <div className="forensic-box">
                  <div className="forensic-box-title">Scoring Fusion Balance</div>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                    Rule-Engine Weight: <b style={{ color: 'var(--accent-blue)' }}>{mlStatus.config?.posture?.rule_weight ?? 0.6}</b> <br />
                    ML Inference Weight: <b style={{ color: 'var(--accent-blue)' }}>{mlStatus.config?.posture?.ml_weight ?? 0.4}</b>
                  </div>
                  {mlStatus.metadata && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px' }}>
                      Last trained: {new Date(mlStatus.metadata.trained_at).toLocaleString()} · {mlStatus.metadata.classifier_sample_count} samples · source: {mlStatus.metadata.source}
                    </div>
                  )}
                </div>
              </div>

              {mlStatus.feature_names && mlStatus.feature_names.length > 0 && (
                <div className="forensic-box" style={{ marginBottom: '20px' }}>
                  <div className="forensic-box-title" style={{ marginBottom: '8px' }}>
                    Model Input Features ({mlStatus.feature_names.length} dimensions)
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {mlStatus.feature_names.map(f => (
                      <span key={f} className="chip-btn" style={{ fontSize: '11px', cursor: 'default' }}>
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Enterprise Baseline Retraining Control Panel */}
              <div className="forensic-box" style={{ marginBottom: '24px', background: 'var(--panel-bg)', border: '1px solid var(--border-color)' }}>
                <div className="forensic-box-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
                    </svg>
                    <span>Enterprise Baseline Retraining &amp; Model Calibration</span>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Continuous Machine Learning Model Tuning
                  </span>
                </div>

                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                  Calibrate the Isolation Forest anomaly baseline and Random Forest risk classifier on your organization's real observed mail traffic patterns, SQLite audit history, custom CSV exports, or high-variance benchmark vectors.
                </p>

                {/* Source Selection Cards */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px', marginBottom: '16px' }}>
                  <div
                    onClick={() => setTrainSource('synthetic')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `1.5px solid ${trainSource === 'synthetic' ? 'var(--accent-blue)' : 'var(--border-color)'}`,
                      background: trainSource === 'synthetic' ? 'rgba(14, 165, 233, 0.08)' : 'var(--bg-app)',
                      cursor: 'pointer',
                      transition: 'all 0.2s'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '12.5px', color: trainSource === 'synthetic' ? 'var(--accent-blue)' : 'var(--text-primary)' }}>
                      <span>🌐</span>
                      <span>Synthetic Benchmark</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Balanced multi-class cryptographic distribution with full 17 feature dimensions.
                    </div>
                  </div>

                  <div
                    onClick={() => setTrainSource('active_sessions')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `1.5px solid ${trainSource === 'active_sessions' ? 'var(--accent-blue)' : 'var(--border-color)'}`,
                      background: trainSource === 'active_sessions' ? 'rgba(14, 165, 233, 0.08)' : 'var(--bg-app)',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      opacity: sessions.length > 0 ? 1 : 0.6
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '12.5px', color: trainSource === 'active_sessions' ? 'var(--accent-blue)' : 'var(--text-primary)' }}>
                      <span>🛡️</span>
                      <span>Current Inspected Traffic</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Retrain on {sessions.length} sessions currently in memory from recent scan.
                    </div>
                  </div>

                  <div
                    onClick={() => setTrainSource('history')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `1.5px solid ${trainSource === 'history' ? 'var(--accent-blue)' : 'var(--border-color)'}`,
                      background: trainSource === 'history' ? 'rgba(14, 165, 233, 0.08)' : 'var(--bg-app)',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      opacity: historyScans.length > 0 ? 1 : 0.6
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '12.5px', color: trainSource === 'history' ? 'var(--accent-blue)' : 'var(--text-primary)' }}>
                      <span>🗄️</span>
                      <span>Historical Archive</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Aggregate all past sessions persisted in SQLite database ({historyScans.length} scans).
                    </div>
                  </div>

                  <div
                    onClick={() => setTrainSource('csv')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `1.5px solid ${trainSource === 'csv' ? 'var(--accent-blue)' : 'var(--border-color)'}`,
                      background: trainSource === 'csv' ? 'rgba(14, 165, 233, 0.08)' : 'var(--bg-app)',
                      cursor: 'pointer',
                      transition: 'all 0.2s'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '12.5px', color: trainSource === 'csv' ? 'var(--accent-blue)' : 'var(--text-primary)' }}>
                      <span>📁</span>
                      <span>Upload Custom CSV</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Import custom enterprise network capture feature matrix.
                    </div>
                  </div>
                </div>

                {/* CSV File Input */}
                {trainSource === 'csv' && (
                  <div style={{ marginBottom: '16px', background: 'var(--bg-app)', padding: '12px', borderRadius: '6px', border: '1px dashed var(--border-color)' }}>
                    <label style={{ fontSize: '11.5px', fontWeight: 600, display: 'block', marginBottom: '6px' }}>Select Baseline CSV File:</label>
                    <input
                      type="file"
                      accept=".csv"
                      onChange={(e) => setTrainCsvFile(e.target.files[0] || null)}
                      style={{ fontSize: '12px' }}
                    />
                    {trainCsvFile && (
                      <span style={{ fontSize: '11px', color: 'var(--sev-safe)', marginLeft: '10px' }}>
                        ✓ {trainCsvFile.name} ({(trainCsvFile.size / 1024).toFixed(1)} KB)
                      </span>
                    )}
                  </div>
                )}

                {/* Training Hyperparameters */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '20px', alignItems: 'center', marginBottom: '18px' }}>
                  <div>
                    <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                      Samples Per Class: <b>{trainNPerClass}</b>
                    </label>
                    <input
                      type="range"
                      min="100"
                      max="2000"
                      step="50"
                      value={trainNPerClass}
                      onChange={(e) => setTrainNPerClass(Number(e.target.value))}
                      disabled={mlTraining}
                      style={{ width: '150px' }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                      Anomaly Baseline Size: <b>{trainBaselineN}</b>
                    </label>
                    <input
                      type="range"
                      min="300"
                      max="5000"
                      step="100"
                      value={trainBaselineN}
                      onChange={(e) => setTrainBaselineN(Number(e.target.value))}
                      disabled={mlTraining}
                      style={{ width: '150px' }}
                    />
                  </div>
                </div>

                {/* Action Buttons */}
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  <button
                    className="btn-primary"
                    onClick={trainMl}
                    disabled={mlTraining || (trainSource === 'active_sessions' && sessions.length === 0) || (trainSource === 'history' && historyScans.length === 0) || (trainSource === 'csv' && !trainCsvFile)}
                    style={{ padding: '9px 18px', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700 }}
                  >
                    {mlTraining ? (
                      <>
                        <span className="live-pulse-dot"></span>
                        <span>Retraining ML Pipeline…</span>
                      </>
                    ) : (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3" /></svg>
                        <span>Retrain On Baseline ({trainSource.replace('_', ' ').toUpperCase()})</span>
                      </>
                    )}
                  </button>

                  <button className="btn-secondary" onClick={evaluateMl} disabled={mlEvaluating}>
                    {mlEvaluating ? 'Evaluating Metrics…' : 'Run Model Evaluation Benchmark'}
                  </button>
                </div>

                {/* Training Result Feedback Banner */}
                {trainResult && (
                  <div style={{
                    marginTop: '16px',
                    padding: '14px',
                    borderRadius: '8px',
                    background: 'rgba(56, 168, 86, 0.1)',
                    border: '1px solid rgba(56, 168, 86, 0.3)',
                    color: '#e5e7eb'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, color: 'var(--sev-safe)' }}>
                        <span>✓</span>
                        <span>Models Retrained &amp; Persisted Successfully!</span>
                      </div>
                      <button
                        onClick={evaluateMl}
                        className="btn-primary"
                        style={{ fontSize: '11px', padding: '4px 10px', background: 'var(--sev-safe)', color: '#000', fontWeight: 700 }}
                      >
                        Evaluate New Weights
                      </button>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      <span>Source: <b style={{ color: '#fff' }}>{trainResult.source || 'Synthetic'}</b></span>
                      <span>Classifier Pool: <b style={{ color: '#fff' }}>{trainResult.classifier} vectors</b></span>
                      <span>Anomaly Baseline: <b style={{ color: '#fff' }}>{trainResult.baseline} vectors</b></span>
                      {trainResult.class_distribution && (
                        <span>
                          Distribution: Low={trainResult.class_distribution['0'] || 0} | Med={trainResult.class_distribution['1'] || 0} | High={trainResult.class_distribution['2'] || 0} | Crit={trainResult.class_distribution['3'] || 0}
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {mlEval && (
                <div className="forensic-box" style={{ marginTop: '20px' }}>
                  <div className="forensic-box-title">Model Evaluation Benchmark</div>
                  <div style={{ fontSize: '22px', fontWeight: '800', color: 'var(--accent-blue)', margin: '8px 0 16px' }}>
                    Overall Test Accuracy: {(mlEval.accuracy * 100).toFixed(2)}%
                  </div>

                  <div style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px' }}>Confusion Matrix:</div>
                  <div className="table-responsive" style={{ marginBottom: '16px' }}>
                    <table className="matrix-table" style={{ width: 'auto' }}>
                      <thead>
                        <tr>
                          <th>Actual / Pred</th>
                          <th>Low</th>
                          <th>Medium</th>
                          <th>High</th>
                          <th>Critical</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mlEval.confusion_matrix.map((row, i) => (
                          <tr key={i}>
                            <td><b>{['Low', 'Medium', 'High', 'Critical'][i]}</b></td>
                            {row.map((cell, j) => (
                              <td key={j} style={{ textAlign: 'center', fontWeight: cell > 0 ? '700' : '400', background: i === j ? 'rgba(14, 165, 233, 0.1)' : 'transparent' }}>
                                {cell}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px' }}>Detailed Classification Metrics:</div>
                  <pre style={{ background: 'var(--bg-app)', padding: '14px', borderRadius: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#000000', overflowX: 'auto' }}>
                    {JSON.stringify(mlEval.classification_report, null, 2)}
                  </pre>

                  {typeof mlEval.anomaly_baseline_flag_rate === 'number' && (
                    <div className="forensic-box" style={{ marginTop: '16px' }}>
                      <div className="forensic-box-title">Anomaly Detector Evaluation</div>
                      <div style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '8px 0' }}>
                        Flag rate on clean baseline traffic: <b style={{ color: 'var(--accent-blue)' }}>{((mlEval.anomaly_baseline_flag_rate || 0) * 100).toFixed(1)}%</b> (lower is better)
                      </div>
                      <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                        Flag rate on critical/broken-crypto traffic: <b style={{ color: 'var(--accent-blue)' }}>{((mlEval.anomaly_critical_flag_rate || 0) * 100).toFixed(1)}%</b> (higher is better — shows real detection power)
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : mlStatusError ? (
            <div className="forensic-box" style={{ borderColor: 'var(--sev-critical)' }}>
              <div className="forensic-box-title" style={{ color: 'var(--sev-critical)' }}>Failed to load ML subsystem</div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '8px 0 12px' }}>{mlStatusError}</div>
              <button className="btn-secondary" onClick={loadMlStatus}>Retry</button>
            </div>
          ) : (
            <div className="loading-card" style={{ padding: '20px' }}>
              <div className="spinner"></div>
              <span>Connecting to ML subsystem…</span>
            </div>
          )}
        </div>
      )}

      {/* ==========================================================================
          SYSTEM DIAGNOSTICS TAB
         ========================================================================== */}
      {activeTab === 'diagnostics' && (
        <div className="panel-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
            <div className="panel-card-title" style={{ margin: 0 }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
              </svg>
              <span>Subsystem Health &amp; Dependencies</span>
            </div>
            <button className="btn-secondary" onClick={loadDiagnostics} disabled={diagnosticsLoading}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
              Refresh
            </button>
          </div>

          {diagnostics ? (
            <div className="diagnostics-grid">
              {[
                { label: 'Process Privilege Level', value: diagnostics.elevated_privileges ? `Elevated Root (UID ${diagnostics.process_uid ?? 0})` : `Standard User (${diagnostics.process_user || 'non-root'})`, ok: diagnostics.elevated_privileges },
                { label: 'Hardware Packet Capture (BPF)', value: diagnostics.raw_socket_capable ? 'Enabled (Full Raw Wire Access)' : 'Restricted (Run backend via sudo)', ok: diagnostics.raw_socket_capable },
                { label: 'Python Runtime', value: diagnostics.python_version.split(' ')[0], ok: true },
                { label: 'Host Platform', value: diagnostics.os_platform, ok: true },
                { label: 'TShark Sniffer Binary', value: diagnostics.tshark_available ? 'Available' : 'Missing (Live sniff limited)', ok: diagnostics.tshark_available },
                { label: 'PyShark Python Bridge', value: diagnostics.pyshark_installed ? 'Installed' : 'Not Installed', ok: diagnostics.pyshark_installed },
                { label: 'Certifi Root Certificates', value: `${diagnostics.certifi_roots_count} trusted roots`, ok: diagnostics.certifi_roots_count > 100 },
                { label: 'ReportLab PDF Exporter', value: diagnostics.reportlab_version ? `v${diagnostics.reportlab_version}` : 'Not Installed', ok: !!diagnostics.reportlab_version },
                { label: 'Scapy Packet Engine', value: diagnostics.scapy_version ? `v${diagnostics.scapy_version}` : 'Not Installed', ok: !!diagnostics.scapy_version },
                { label: 'ML Risk & Anomaly Engine', value: diagnostics.ml_models_active ? 'Active' : 'Offline', ok: diagnostics.ml_models_active },
              ].map(d => (
                <div key={d.label} className={`diagnostic-item-card ${d.ok ? 'ok' : 'failed'}`}>
                  <div>
                    <div className="diag-label">{d.label}</div>
                    <div className="diag-val" style={{ color: d.ok ? 'var(--text-primary)' : 'var(--sev-critical)' }}>
                      {d.value}
                    </div>
                  </div>
                  <span style={{ fontSize: '18px', color: d.ok ? 'var(--sev-safe)' : 'var(--sev-critical)' }}>
                    {d.ok ? '✓' : '✗'}
                  </span>
                </div>
              ))}
            </div>
          ) : diagnosticsError ? (
            <div className="forensic-box" style={{ borderColor: 'var(--sev-critical)' }}>
              <div className="forensic-box-title" style={{ color: 'var(--sev-critical)' }}>Failed to load diagnostics subsystem</div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '8px 0 12px' }}>{diagnosticsError}</div>
              <button className="btn-secondary" onClick={loadDiagnostics}>Retry</button>
            </div>
          ) : (
            <div className="loading-card">
              <div className="spinner"></div>
              <span>Querying system diagnostics…</span>
            </div>
          )}
        </div>
      )}

      {/* ==========================================================================
          TRENDS & HISTORY TAB
         ========================================================================== */}
      {activeTab === 'history' && (
        <div className="history-view-container">
          {/* Summary Stat Cards */}
          <div className="history-stats-grid">
            <div className="history-stat-card">
              <span className="exec-metric-label">Total Scans Conducted</span>
              <span style={{ fontSize: '24px', fontWeight: 800, color: 'var(--primary)' }}>
                {historyTrends?.total_scans || historyScans.length}
              </span>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Persistent in SQLite database</span>
            </div>

            <div className="history-stat-card">
              <span className="exec-metric-label">Overall Average Score</span>
              <span style={{ fontSize: '24px', fontWeight: 800, color: '#1982c4' }}>
                {historyTrends?.overall_avg_score || '0.0'}/100
              </span>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Across all historical evaluations</span>
            </div>

            <div className="history-stat-card">
              <span className="exec-metric-label">Critical Flaws Detected</span>
              <span style={{ fontSize: '24px', fontWeight: 800, color: '#ff595e' }}>
                {historyTrends?.total_critical_detected || 0}
              </span>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Plaintext &amp; downgrade flaws</span>
            </div>

            <div className="history-stat-card">
              <span className="exec-metric-label">Database Storage</span>
              <span style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '6px' }}>
                output/history.db
              </span>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Persistent across restarts</span>
            </div>
          </div>

          {/* Time-Series Trend Chart */}
          <div className="history-chart-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Cryptographic Security Posture Progression
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Chronological progression of Posture Scores and encryption health across audits
                </div>
              </div>
              <button className="btn-secondary" onClick={() => { loadHistory(); loadTrends(); }} disabled={historyLoading}>
                Refresh
              </button>
            </div>

            {historyTrends?.points?.length > 1 ? (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={historyTrends.points} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="var(--primary)" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                  <XAxis dataKey="date_label" stroke="var(--text-muted)" fontSize={11} />
                  <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const d = payload[0].payload
                      return (
                        <div className="custom-recharts-tooltip">
                          <p style={{ fontWeight: 700, color: 'var(--primary)' }}>{d.target} ({d.scan_type.toUpperCase()})</p>
                          <p>Posture Score: <b>{d.posture_score}/100</b></p>
                          <p>Encrypted Ratio: <b>{d.encrypted_ratio}%</b></p>
                          <p>Critical Flaws: <span style={{ color: '#ff595e' }}>{d.critical_findings}</span></p>
                        </div>
                      )
                    }
                    return null
                  }} />
                  <Area type="monotone" dataKey="posture_score" stroke="var(--primary)" strokeWidth={2.5} fillOpacity={1} fill="url(#scoreGradient)" name="Posture Score" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                Run at least two scans (PCAP upload, live capture, or domain probe) to populate the progression trend line.
              </div>
            )}
          </div>

          {/* Historical Scans Table */}
          <div className="history-table-card">
            <div className="history-table-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Assessment History ({historyScans.length})
                </div>
                {historyScans.length >= 2 && (
                  <button
                    className={`compare-toggle-btn ${compareMode ? 'active' : ''}`}
                    onClick={() => { setCompareMode(!compareMode); setCompareSelections(new Set()); }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M16 3h5v5M8 3H3v5M3 16v5h5M21 16v5h-5M12 3v18M3 12h18" /></svg>
                    {compareMode ? 'Cancel Compare' : 'Compare Mode'}
                  </button>
                )}
                {compareMode && compareSelections.size === 2 && (
                  <button
                    className="compare-launch-btn"
                    onClick={() => setCompareModalOpen(true)}
                  >
                    Compare Selected ({compareSelections.size})
                  </button>
                )}
                {compareMode && compareSelections.size > 0 && compareSelections.size < 2 && (
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Select 1 more scan to compare</span>
                )}
              </div>
              {historyScans.length > 0 && (
                <button
                  className="history-action-btn delete"
                  onClick={clearAllHistory}
                >
                  Clear All History
                </button>
              )}
            </div>

            {historyScans.length > 0 ? (
              <div style={{ overflowX: 'auto' }}>
                <table className="history-table">
                  <thead>
                    <tr>
                      {compareMode && <th style={{ width: '40px' }}></th>}
                      <th>Target</th>
                      <th>Type</th>
                      <th>Date</th>
                      <th>Sessions</th>
                      <th>Score</th>
                      <th>Verdict</th>
                      <th>Flaws (Crit / High / Med)</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyScans.map((s) => (
                      <tr key={s.id}>
                        {compareMode && (
                          <td>
                            <input
                              type="checkbox"
                              className="compare-checkbox"
                              checked={compareSelections.has(s.id)}
                              onChange={() => {
                                const next = new Set(compareSelections)
                                if (next.has(s.id)) {
                                  next.delete(s.id)
                                } else if (next.size < 2) {
                                  next.add(s.id)
                                }
                                setCompareSelections(next)
                              }}
                              disabled={!compareSelections.has(s.id) && compareSelections.size >= 2}
                            />
                          </td>
                        )}
                        <td>
                          <b>{s.target_name}</b>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{s.id}</div>
                        </td>
                        <td>
                          <span className={`scan-type-badge ${s.scan_type}`}>
                            {s.scan_type}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          {s.timestamp?.replace('T', ' ')?.slice(0, 16)}
                        </td>
                        <td>{s.session_count}</td>
                        <td>
                          <span className="score-badge-pill" style={{
                            color: s.avg_posture_score >= 80 ? 'var(--sev-safe)' : (s.avg_posture_score >= 50 ? 'var(--sev-medium)' : 'var(--sev-critical)'),
                            fontWeight: 800,
                          }}>
                            {s.avg_posture_score}/100
                          </span>
                        </td>
                        <td>
                          <span className={`status-badge-compact ${s.compliance_verdict === 'COMPLIANT' ? 'encrypted' : 'plaintext'}`}>
                            {s.compliance_verdict}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '4px' }}>
                            <span style={{ color: '#ff595e', fontWeight: 700 }}>{s.critical_findings}C</span>
                            <span>/</span>
                            <span style={{ color: '#ff924c', fontWeight: 700 }}>{s.high_findings}H</span>
                            <span>/</span>
                            <span style={{ color: '#ffca3a', fontWeight: 700 }}>{s.medium_findings}M</span>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '6px' }}>
                            <button
                              className="history-action-btn"
                              title="Rehydrate and open in Analysis dashboard"
                              onClick={() => rehydrateHistoryScan(s.id)}
                            >
                              Open
                            </button>
                            <button
                              className="history-action-btn"
                              title="Download Remediation Playbook PDF"
                              onClick={() => downloadPlaybookPdf(s.id)}
                            >
                              Playbook
                            </button>
                            <button
                              className="history-action-btn delete"
                              title="Delete from history"
                              onClick={() => deleteHistoryScan(s.id)}
                            >
                              ✕
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                No historical scans recorded yet. Upload a PCAP or run a Live Domain Probe to record assessments.
              </div>
            )}
          </div>
        </div>
      )}


      {hardeningModalOpen && (
        <div className="modal-backdrop" onClick={() => setHardeningModalOpen(false)}>
          <div className="modal-card" style={{ maxWidth: '820px', width: '90%' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                <h2 style={{ fontSize: '18px', margin: 0 }}>1-Click Server Hardening Generator</h2>
              </div>
              <button className="copy-mini-btn" style={{ fontSize: '16px', padding: '4px 8px' }} onClick={() => setHardeningModalOpen(false)}>✕</button>
            </div>

            {hardeningLoading ? (
              <div className="loading-card" style={{ padding: '32px' }}>
                <div className="spinner"></div>
                <span>Generating custom cryptographically-hardened server configurations…</span>
              </div>
            ) : hardeningData ? (
              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                  {hardeningData.summary}
                </p>

                {/* Server Daemon Tabs */}
                <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', marginBottom: '16px' }}>
                  {Object.keys(hardeningData.snippets || {}).map(daemonKey => {
                    const snip = hardeningData.snippets[daemonKey]
                    return (
                      <button
                        key={daemonKey}
                        className={`chip-btn ${activeHardeningTab === daemonKey ? 'active' : ''}`}
                        style={{
                          borderRadius: '4px 4px 0 0',
                          borderBottom: activeHardeningTab === daemonKey ? '2px solid var(--primary)' : 'none',
                          fontWeight: activeHardeningTab === daemonKey ? '700' : '500',
                          background: activeHardeningTab === daemonKey ? 'var(--bg-surface)' : 'transparent',
                          padding: '8px 16px',
                        }}
                        onClick={() => setActiveHardeningTab(daemonKey)}
                      >
                        {snip.daemon}
                      </button>
                    )
                  })}
                </div>

                {hardeningData.snippets[activeHardeningTab] && (() => {
                  const activeSnip = hardeningData.snippets[activeHardeningTab]
                  return (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <div>
                          <span style={{ fontSize: '13px', fontWeight: 600 }}>Target File: </span>
                          <code style={{ fontSize: '12px', background: 'var(--bg-app)', padding: '3px 6px', borderRadius: '4px' }}>
                            {activeSnip.target_file}
                          </code>
                        </div>
                        <button
                          className="btn-primary"
                          style={{ padding: '6px 14px', fontSize: '12px' }}
                          onClick={() => copyToClipboard(activeSnip.config_text, `hardening-${activeHardeningTab}`)}
                        >
                          {copiedKey === `hardening-${activeHardeningTab}` ? '✓ Copied Configuration!' : 'Copy Config Snippet'}
                        </button>
                      </div>

                      <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                        {activeSnip.explanation}
                      </div>

                      {/* Remediated Findings Badges */}
                      {activeSnip.remediated_findings && activeSnip.remediated_findings.length > 0 && (
                        <div style={{ marginBottom: '12px' }}>
                          <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--sev-safe)', marginBottom: '4px' }}>
                            Remediates Vulnerabilities &amp; Conformance Gaps:
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {activeSnip.remediated_findings.map((item, idx) => (
                              <span key={idx} style={{ fontSize: '11px', background: 'rgba(56, 168, 86, 0.12)', color: 'var(--sev-safe)', padding: '2px 8px', borderRadius: '12px', border: '1px solid rgba(56, 168, 86, 0.25)' }}>
                                ✓ {item}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Code Block */}
                      <pre style={{
                        background: '#1a1f18',
                        color: '#d6f0d1',
                        padding: '12px 16px',
                        borderRadius: '6px',
                        fontSize: '11.5px',
                        fontFamily: 'var(--font-mono)',
                        overflowX: 'auto',
                        maxHeight: '260px',
                        lineHeight: 1.5,
                      }}>
                        {activeSnip.config_text}
                      </pre>

                      {/* Reload command */}
                      {activeSnip.reload_command && (
                        <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-app)', padding: '8px 12px', borderRadius: '4px' }}>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                            Apply Changes Command: <code style={{ color: 'var(--primary)', fontWeight: 600 }}>{activeSnip.reload_command}</code>
                          </span>
                          <button
                            className="copy-mini-btn"
                            onClick={() => copyToClipboard(activeSnip.reload_command, `reload-${activeHardeningTab}`)}
                          >
                            {copiedKey === `reload-${activeHardeningTab}` ? '✓ Copied' : 'Copy Command'}
                          </button>
                        </div>
                      )}
                    </div>
                  )
                })()}

                {/* One-Click Hardening Script Download */}
                <div className="hardening-script-download-row">
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)', marginRight: '8px' }}>
                    Download automated hardening script:
                  </span>
                  <button
                    className="hardening-script-btn linux"
                    onClick={() => downloadHardeningScript('linux')}
                    title="Download Bash script (.sh) for Postfix/Dovecot/Exim hardening on Linux"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                    Hardening Script (.sh)
                  </button>
                  <button
                    className="hardening-script-btn windows"
                    onClick={() => downloadHardeningScript('windows')}
                    title="Download PowerShell script (.ps1) for Windows Server hardening"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                    Hardening Script (.ps1)
                  </button>
                </div>

                {/* Remediation Playbook PDF Action inside Modal */}
                <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Export complete multi-daemon remediation playbook with pre-flight backups &amp; verification commands:
                  </span>
                  <button
                    className="btn-primary"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '8px 16px', fontSize: '12.5px' }}
                    onClick={() => downloadPlaybookPdf()}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                    Download Full Playbook (PDF)
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* SIEM / Slack / Discord Webhook Alerting Modal */}
      {webhookModalOpen && (
        <div className="modal-backdrop" onClick={() => setWebhookModalOpen(false)}>
          <div className="modal-card" style={{ maxWidth: '680px', width: '90%' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" /></svg>
                <h2 style={{ fontSize: '18px', margin: 0 }}>SIEM, Slack &amp; Discord Webhook Alerts</h2>
              </div>
              <button className="copy-mini-btn" style={{ fontSize: '16px', padding: '4px 8px' }} onClick={() => setWebhookModalOpen(false)}>✕</button>
            </div>

            <div className="modal-body" style={{ padding: '16px 20px' }}>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                Automatically dispatch cryptographically-rich security alerts whenever critical vulnerabilities (STARTTLS stripping, plaintext credentials, revoked certificates, or JA4 client masquerading) are discovered.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
                <div>
                  <label style={{ fontSize: '12px', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Target Channel / Provider</label>
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={webhookProvider}
                    onChange={e => setWebhookProvider(e.target.value)}
                  >
                    <option value="slack">Slack (Block Kit interactive alert)</option>
                    <option value="discord">Discord (Rich Embeds with colorization)</option>
                    <option value="siem">Generic SIEM / Splunk HEC (JSON format)</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '12px', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Minimum Severity Trigger</label>
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={webhookMinSev}
                    onChange={e => setWebhookMinSev(e.target.value)}
                  >
                    <option value="critical">Critical Findings Only</option>
                    <option value="high">High &amp; Critical Findings (Recommended)</option>
                    <option value="medium">Medium, High &amp; Critical Findings</option>
                  </select>
                </div>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Webhook Ingestion Endpoint URL</label>
                <input
                  type="text"
                  placeholder={webhookProvider === 'discord' ? 'https://discord.com/api/webhooks/...' : webhookProvider === 'slack' ? 'https://hooks.slack.com/services/...' : 'https://siem.corp.internal:8088/services/collector'}
                  value={webhookUrl}
                  onChange={e => setWebhookUrl(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '4px',
                    border: '1px solid var(--border-color)',
                    fontSize: '12.5px',
                    fontFamily: 'var(--font-mono)',
                    background: 'var(--bg-app)',
                  }}
                />
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Leave URL blank to execute an offline simulation test and inspect the generated payload.
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginBottom: '16px' }}>
                <button
                  className="btn-primary"
                  onClick={doTestWebhook}
                  disabled={webhookTesting}
                  style={{ padding: '7px 18px', fontSize: '12.5px' }}
                >
                  {webhookTesting ? 'Testing Dispatch…' : webhookUrl ? 'Dispatch Live Webhook Test' : 'Simulate Alert Payload'}
                </button>
              </div>

              {webhookTestResult && (
                <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 600 }}>
                      Status: <b style={{ color: webhookTestResult.dispatched ? 'var(--sev-safe)' : 'var(--sev-critical)' }}>
                        {webhookTestResult.dispatched ? '✓ Successfully Dispatched' : '✗ Dispatch Error / Inactive'}
                      </b> {webhookTestResult.mode === 'dry_run' && <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}> (Simulation Mode)</span>}
                    </span>
                    <span style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                      Findings Included: {webhookTestResult.findings_count}
                    </span>
                  </div>

                  {webhookTestResult.error && (
                    <div style={{ color: 'var(--sev-critical)', fontSize: '12px', marginBottom: '8px' }}>
                      Error: {webhookTestResult.error}
                    </div>
                  )}

                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>Payload Preview:</div>
                  <pre style={{
                    background: '#1a1f18',
                    color: '#d6f0d1',
                    padding: '10px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    maxHeight: '160px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}>
                    {JSON.stringify(webhookTestResult.payload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Comparison Modal */}
      {compareModalOpen && (
        <ComparisonView
          scans={historyScans.filter(s => compareSelections.has(s.id))}
          onClose={() => setCompareModalOpen(false)}
        />
      )}

      {/* Footer */}
      <footer className="app-footer">

        <span>SecureMailScope Forensic Architecture</span>
        <span>•</span>
        <span>Passive TLS Posture Assessment</span>
        <span>•</span>
        <span>Compliance Matrix: PCI-DSS 4.0 / NIST 800-52r2 / HIPAA</span>
      </footer>
    </div>
  )
}
