import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Search,
  FileCheck,
  Activity,
  Cpu,
  Wrench,
  Network,
  TrendingUp,
  Gauge,
  Atom,
  Lock,
  Unlock,
  Check,
  ArrowRight,
  ChevronRight,
  Server,
  Layers,
  Terminal as TerminalIcon,
  AlertTriangle,
  Radio,
  ExternalLink,
  RefreshCw,
  Sparkles,
  Sun,
  Moon
} from 'lucide-react'
import './landing.css'
import AsciiPixelEnvelope from './AsciiPixelEnvelope.jsx'
import HowItWorksCircuit from './HowItWorksCircuit.jsx'

export default function LandingPage({ onLaunchApp, theme: propTheme, toggleTheme: propToggleTheme }) {
  const [internalTheme, setInternalTheme] = useState(() => {
    return localStorage.getItem('sms_landing_theme') || 'light'
  })

  const theme = propTheme !== undefined ? propTheme : internalTheme
  const toggleTheme = () => {
    if (propToggleTheme) {
      propToggleTheme()
    } else {
      const nextTheme = theme === 'light' ? 'dark' : 'light'
      setInternalTheme(nextTheme)
      localStorage.setItem('sms_landing_theme', nextTheme)
    }
  }

  const [drawerOpen, setDrawerOpen] = useState(false)
  const [pqcScenario, setPqcScenario] = useState('pqc') // 'classical' | 'pqc'
  const [activeBlip, setActiveBlip] = useState(null)
  const [waveActive, setWaveActive] = useState(true)
  const [tilt, setTilt] = useState({ x: 0, y: 0 })

  const handleMouseMove = (e) => {
    const card = e.currentTarget.getBoundingClientRect()
    const x = e.clientX - card.left - card.width / 2
    const y = e.clientY - card.top - card.height / 2
    setTilt({
      x: -(y / card.height) * 14,
      y: (x / card.width) * 14
    })
  }

  const handleMouseLeave = () => {
    setTilt({ x: 0, y: 0 })
    setActiveBlip(null)
  }

  const scrollToSection = (id) => {
    setDrawerOpen(false)
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' })
    }
  }

  // Animation variants (Clean & diverse)
  const heroReveal = {
    hidden: { opacity: 0, y: 20, filter: 'blur(6px)' },
    visible: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] } }
  }

  const cardStagger = {
    hidden: { opacity: 0, y: 16 },
    visible: (i) => ({
      opacity: 1,
      y: 0,
      transition: { delay: i * 0.06, duration: 0.5, ease: [0.16, 1, 0.3, 1] }
    })
  }

  return (
    <div className={`landing-page-root ${theme === 'light' ? 'theme-light' : 'theme-dark'}`}>
      {/* Cyber Mecha Chassis Framing Backdrop (From Reference Image, Theme-Integrated) */}
      <div className="lp-tactical-mecha-backdrop" aria-hidden="true">
        <div className="lp-mecha-canvas-bg" />
        <div className="lp-mecha-flank-left" />
        <div className="lp-mecha-flank-right" />
        <div className="lp-mecha-full-mobile" />
        <div className="lp-mecha-vignette-layer" />
        <div className="lp-mecha-grid-layer" />
      </div>

      {/* ===================================================================
          1. Header & Navigation
          =================================================================== */}
      <header className="lp-header">
        <div className="lp-container lp-header-inner">
          <div className="lp-brand-lockup" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            <div className="lp-brand-logo-icon">
              <Shield size={16} strokeWidth={2.2} />
            </div>
            <span className="lp-brand-text">SecureMailScope</span>
          </div>

          <nav className="lp-nav-links">
            <span className="lp-nav-link" onClick={() => scrollToSection('problem')}>Problem</span>
            <span className="lp-nav-link" onClick={() => scrollToSection('how-it-works')}>How It Works</span>
            <span className="lp-nav-link" onClick={() => scrollToSection('pqc')}>Quantum Threat</span>
            <span className="lp-nav-link" onClick={() => scrollToSection('modules')}>Modules</span>
            <span className="lp-nav-link" onClick={() => scrollToSection('compliance')}>Compliance</span>
          </nav>

          <div className="lp-header-actions">
            {/* Theme Toggle Button (Light / Dark) */}
            <button
              className="lp-theme-toggle-btn"
              onClick={toggleTheme}
              title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
              aria-label="Toggle Theme Mode"
            >
              {theme === 'light' ? <Moon size={14} /> : <Sun size={14} />}
              <span>{theme === 'light' ? 'DARK' : 'LIGHT'}</span>
            </button>

            <button
              className="lp-btn-primary lp-btn-chamfer"
              onClick={onLaunchApp}
              title="Launch SecureMailScope Console"
            >
              <span>Launch Cockpit</span>
              <ArrowRight size={15} />
            </button>

            <button
              className="lp-menu-btn"
              onClick={() => setDrawerOpen(true)}
              aria-label="Toggle Navigation"
            >
              <Layers size={18} />
            </button>
          </div>
        </div>
      </header>

      {/* ===================================================================
          2. Hero Section (Clean, Minimalist, Clear Value)
          =================================================================== */}
      <section className="lp-hero-section" id="problem">
        <div className="lp-container">
          <div className="lp-hero-grid">
            {/* Left Column: Clear Value Proposition */}
            <motion.div initial="hidden" animate="visible" variants={heroReveal}>
              <div className="lp-badge-tag">
                <Radio size={14} />
                <span>Enterprise Email Cryptographic Forensics</span>
              </div>

              <h1 className="lp-hero-title">
                Is your email encryption <span>actually protecting</span> your enterprise?
              </h1>

              <p className="lp-hero-desc">
                Most companies assume email is safe because TLS is enabled. In reality, mail servers frequently suffer hidden misconfigurations attackers actively exploit: <strong>STARTTLS stripping attacks</strong>, obsolete <strong>TLS 1.0/1.1 protocols</strong>, weak <strong>CBC ciphers</strong>, and <strong>zero forward secrecy</strong>.
              </p>

              {/* Layman Clarity Box */}
              <div className="lp-layman-box">
                <ShieldAlert size={20} style={{ color: 'var(--lp-accent-chartreuse)', flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <strong style={{ color: 'var(--lp-text-primary)', display: 'block', marginBottom: '2px' }}>In Plain English:</strong>
                  Standard email acts like a postcard. Even when encrypted, adversaries can force it into cleartext mid-transit or capture it today to decrypt later with quantum computing. SecureMailScope audits your servers in seconds without installing anything.
                </div>
              </div>

              <div className="lp-hero-actions">
                <button className="lp-btn-secondary" onClick={() => scrollToSection('how-it-works')}>
                  <span>See How It Works</span>
                  <ChevronRight size={15} />
                </button>
              </div>
            </motion.div>

            {/* Right Column: 3D ASCII/Pixel-Art Rotating Mail Envelope Hero CTA */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
              style={{ width: '100%', display: 'flex', justifyContent: 'center' }}
            >
              <AsciiPixelEnvelope onLaunchApp={onLaunchApp} theme={theme} />
            </motion.div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          3. Compliance & Standards Strip
          =================================================================== */}
      <section className="lp-standards-section" id="compliance">
        <div className="lp-container">
          <div className="lp-standards-grid">
            <div className="lp-standards-title">
              <ShieldCheck size={16} style={{ color: 'var(--lp-accent-chartreuse)' }} />
              <span>Aligned With Global Standards</span>
            </div>

            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <span className="lp-standard-item">
                <Check size={13} style={{ color: 'var(--lp-accent-chartreuse)' }} />
                PCI-DSS 4.0 (Req 4.2.1)
              </span>
              <span className="lp-standard-item">
                <Check size={13} style={{ color: 'var(--lp-accent-chartreuse)' }} />
                NIST SP 800-52 Rev. 2
              </span>
              <span className="lp-standard-item">
                <Check size={13} style={{ color: 'var(--lp-accent-chartreuse)' }} />
                HIPAA §164.312(e)(1)
              </span>
              <span className="lp-standard-item">
                <Check size={13} style={{ color: 'var(--lp-accent-chartreuse)' }} />
                IETF RFC 8461 (MTA-STS)
              </span>
              <span className="lp-standard-item">
                <Check size={13} style={{ color: 'var(--lp-accent-chartreuse)' }} />
                NIST FIPS 203 (ML-KEM)
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          4. How It Works Section (Process Pipeline)
          =================================================================== */}
      <section className="lp-section" id="how-it-works">
        <div className="lp-container">
          <div className="lp-section-header center">
            <div className="lp-pretitle">
              <Cpu size={14} />
              <span>Assessment Architecture</span>
            </div>
            <h2 className="lp-title">How <span>SecureMailScope</span> Works</h2>
            <p className="lp-desc">
              Whether analyzing passive network captures (PCAP) or actively probing public mail records, the platform reconstructs every cryptographic detail to generate a verified 0-100 posture score.
            </p>
          </div>

          <HowItWorksCircuit onLaunchApp={onLaunchApp} />
        </div>
      </section>

      {/* ===================================================================
          5. Animated "How PQC Works" Interactive Component
          =================================================================== */}
      <section className="lp-section lp-section-alt" id="pqc">
        <div className="lp-container">
          <div className="lp-section-header center">
            <div className="lp-pretitle">
              <Atom size={14} />
              <span>Post-Quantum Cryptography Readiness</span>
            </div>
            <h2 className="lp-title">Understanding the <span>Quantum Threat</span> to Email</h2>
            <p className="lp-desc">
              Adversaries are executing <strong>Harvest-Now, Decrypt-Later (HNDL)</strong> attacks: storing encrypted corporate emails today to decrypt them once quantum computers arrive.
            </p>
          </div>

          <div className="lp-card-xotc lp-pqc-visualizer-card">
            <div className="lp-card-xotc-inner">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div className="lp-card-tab">[ NIST FIPS 203: POST-QUANTUM CRYPTOGRAPHY ]</div>
                <div className="lp-dot-matrix" aria-hidden="true">
                  {[...Array(35)].map((_, i) => (
                    <span key={i} className="lp-dot" />
                  ))}
                </div>
              </div>

              <div className="lp-pqc-grid">
                {/* Left Column: Clear Explanation */}
                <div>
                  <h3 style={{ fontFamily: 'var(--lp-font-heading)', fontSize: '24px', fontWeight: '700', color: 'var(--lp-text-primary)', marginBottom: '12px' }}>
                    Dual-Layer Hybrid Key Exchange
                  </h3>

                <p style={{ fontSize: '14.5px', color: 'var(--lp-text-secondary)', lineHeight: '1.6', marginBottom: '16px' }}>
                  SecureMailScope tests whether mail transfer sessions negotiate NIST-approved post-quantum algorithms like <strong>X25519MLKEM768 (Group 0x6399)</strong>.
                </p>

                <div className="lp-layman-box" style={{ marginBottom: '20px' }}>
                  <ShieldCheck size={18} style={{ color: 'var(--lp-accent-chartreuse)', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong>How It Protects You:</strong>
                    Instead of a single classical lock (RSA or ECDHE) which quantum computers easily break with Shor’s algorithm, hybrid PQC wraps your data in two independent locks. Both must be broken to read the message.
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
                  <div className="lp-pqc-layer-pill">
                    <div style={{ fontSize: '10.5px', color: 'var(--lp-text-muted)', fontFamily: 'var(--lp-font-mono)' }}>CLASSICAL LAYER</div>
                    <div className="lp-pqc-node">
                      <div className="lp-pqc-node-icon classical">
                        <Lock size={16} />
                      </div>
                      <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--lp-text-primary)' }}>X25519 (ECDHE)</div>
                      <div className="lp-pqc-node-sub">Classical ECDH (Fast, Elliptic)</div>
                    </div>
                  </div>

                  <div className="lp-pqc-layer-pill">
                    <div style={{ fontSize: '10.5px', color: 'var(--lp-text-muted)', fontFamily: 'var(--lp-font-mono)' }}>QUANTUM LATTICE LAYER</div>
                    <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--lp-accent-chartreuse)' }}>ML-KEM-768 (Kyber)</div>
                  </div>
                </div>
              </div>

              {/* Right Column: Interactive Animated Diagram */}
              <div className="lp-pqc-diagram-wrap">
                <div className="lp-pqc-tabs">
                  <button
                    className={`lp-pqc-tab-btn ${pqcScenario === 'classical' ? 'active' : ''}`}
                    onClick={() => setPqcScenario('classical')}
                  >
                    <Unlock size={13} />
                    <span>Legacy Classical TLS (Vulnerable)</span>
                  </button>

                  <button
                    className={`lp-pqc-tab-btn ${pqcScenario === 'pqc' ? 'active' : ''}`}
                    onClick={() => setPqcScenario('pqc')}
                  >
                    <Shield size={13} />
                    <span>Hybrid PQC (Quantum Safe)</span>
                  </button>
                </div>

                {/* Animated Diagram Nodes */}
                <div className="lp-pqc-flow-row">
                  <div className="lp-pqc-node-box">
                    <div className="lp-pqc-node-label">SENDER</div>
                    <div className="lp-pqc-node-title">Mail Client</div>
                  </div>

                  <div className="lp-pqc-arrow-path">
                    <div className="lp-pqc-arrow-pulse" />
                  </div>

                  <div className="lp-pqc-node-box highlight">
                    <div className="lp-pqc-node-label">KEY EXCHANGE</div>
                    <div className="lp-pqc-node-title" style={{ color: pqcScenario === 'classical' ? 'var(--lp-accent-coral)' : 'var(--lp-accent-chartreuse)' }}>
                      {pqcScenario === 'classical' ? 'Standard ECDHE' : 'X25519 + ML-KEM'}
                    </div>
                  </div>

                  <div className="lp-pqc-arrow-path">
                    <div className="lp-pqc-arrow-pulse" />
                  </div>

                  <div className="lp-pqc-node-box">
                    <div className="lp-pqc-node-label">RECEIVER</div>
                    <div className="lp-pqc-node-title">Destination MX</div>
                  </div>
                </div>

                {/* Adversary Simulation Banner */}
                <div style={{
                  background: pqcScenario === 'classical' ? 'rgba(255, 89, 94, 0.1)' : 'rgba(204, 255, 0, 0.08)',
                  border: `1px solid ${pqcScenario === 'classical' ? 'rgba(255, 89, 94, 0.3)' : 'rgba(204, 255, 0, 0.25)'}`,
                  padding: '14px',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px'
                }}>
                  {pqcScenario === 'classical' ? (
                    <>
                      <AlertTriangle size={22} style={{ color: 'var(--lp-accent-coral)', flexShrink: 0 }} />
                      <div style={{ fontSize: '12.5px', color: '#fca5a5' }}>
                        <strong>HIGH QUANTUM RISK:</strong> Adversary captures encrypted email on the wire. Future quantum computer solves discrete log in seconds, exposing full message contents.
                      </div>
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={22} style={{ color: 'var(--lp-accent-chartreuse)', flexShrink: 0 }} />
                      <div style={{ fontSize: '12.5px', color: 'var(--lp-text-primary)' }}>
                        <strong>QUANTUM RESISTANT (GRADE A):</strong> NIST FIPS 203 lattice math cannot be broken by Shor’s algorithm. Recorded email remains confidential indefinitely.
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          6. Product Capabilities Showcase (9 Tab Cards)
          =================================================================== */}
      <section className="lp-section" id="modules">
        <div className="lp-container">
          <div className="lp-section-header center">
            <div className="lp-pretitle">
              <Server size={14} />
              <span>Comprehensive Security Toolset</span>
            </div>
            <h2 className="lp-title"><span>9 Forensic Modules</span> in One Dashboard</h2>
            <p className="lp-desc">
              From automated regulatory audits to machine learning anomaly detection, every tab in SecureMailScope solves a concrete enterprise mail challenge.
            </p>
          </div>

          <div className="lp-features-grid">
            {[
              {
                icon: Search,
                tag: 'CORE INSPECTION',
                title: 'Analysis & Forensics',
                desc: 'Deep per-session TLS, certificate, and protocol inspection from PCAP uploads or live remote MX domain probes.',
                usecase: 'Pinpoints exactly what failed on the wire, which ciphers were negotiated, and where plaintext credentials leaked.'
              },
              {
                icon: FileCheck,
                tag: 'AUDIT AUTOMATION',
                title: 'Compliance Matrix',
                desc: 'Automated cross-regulatory mapping against PCI-DSS 4.0, NIST SP 800-52r2, and HIPAA Security Rule §164.312(e)(1).',
                usecase: 'Instantly answers auditors with PASS/FAIL determinations and exact regulatory clause citations.'
              },
              {
                icon: Activity,
                tag: 'REAL-TIME CAPTURE',
                title: 'Live Sniffer',
                what: 'Continuous loopback and wire packet capture with live terminal streaming and protocol classification.',
                usecase: 'Catches active cryptographic downgrades and cleartext relay attempts as they hit your mail gateway.'
              },
              {
                icon: Cpu,
                tag: 'AI ANOMALY DETECTION',
                title: 'ML Studio',
                desc: 'Dual-model machine learning architecture combining unsupervised Isolation Forests with supervised Random Forest risk scoring.',
                usecase: 'Identifies zero-day handshake anomalies and subtle behavioral deviations that static rules miss.'
              },
              {
                icon: Wrench,
                tag: 'INSTANT HARDENING',
                title: 'Remediate',
                desc: 'Converts cryptographic findings into concrete, copy-paste configuration scripts for Postfix, Dovecot, and Exim.',
                usecase: 'Generates ready-to-run .sh and .ps1 hardening commands plus DNS record snippets to fix issues in minutes.'
              },
              {
                icon: ShieldAlert,
                tag: 'RED TEAM SIMULATION',
                title: 'MITM Cryptographic Simulator',
                desc: 'Executes genuine cryptographic Man-in-the-Middle proxies to simulate downgrade and stripping attacks.',
                usecase: 'Validates whether mail servers strictly reject tampered cipher suites and stripped STARTTLS attempts.'
              },
              {
                icon: TrendingUp,
                tag: 'POSTURE TRACKING',
                title: 'Trends & History',
                desc: 'Persistent SQLite database tracking posture scores, finding velocity, and security grades across scans.',
                usecase: 'Provides CISOs and security managers with measurable proof of posture improvement over time.'
              },
              {
                icon: Gauge,
                tag: 'RUNTIME HEALTH',
                title: 'System Diagnostics',
                desc: 'Monitors raw socket permissions, BPF devices, and capture engine integrity in real time.',
                usecase: 'Ensures the forensic inspection pipeline operates without permission or socket degradation.'
              },
              {
                icon: Atom,
                tag: 'QUANTUM DEFENSE',
                title: 'PQC Readiness Radar',
                desc: 'Assesses Harvest-Now-Decrypt-Later exposure and verifies NIST FIPS 203 ML-KEM/Kyber hybrid key exchanges.',
                usecase: 'Guarantees that high-value email archives cannot be retroactively cracked by future quantum adversaries.'
              }
            ].map((mod, idx) => {
              const IconComp = mod.icon
              return (
                <motion.div
                  key={idx}
                  className="lp-card-xotc"
                  custom={idx}
                  initial="hidden"
                  whileInView="visible"
                  viewport={{ once: true, margin: '-30px' }}
                  variants={cardStagger}
                >
                  <div className="lp-card-xotc-inner">
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                        <div className="lp-card-tab">[ {mod.tag} ]</div>
                        <div className="lp-dot-matrix" aria-hidden="true">
                          {[...Array(20)].map((_, i) => (
                            <span key={i} className="lp-dot" />
                          ))}
                        </div>
                      </div>

                      <div className="lp-icon-box-xotc">
                        <IconComp size={22} strokeWidth={1.8} />
                      </div>

                      <h3 className="lp-card-heading">{mod.title}</h3>
                      <p className="lp-card-desc">{mod.desc}</p>
                    </div>

                    <div className="lp-card-usecase" style={{ marginTop: '16px' }}>
                      <strong>Why You'd Use It:</strong>
                      {mod.usecase}
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>
      </section>



      {/* ===================================================================
          10. Slide-Out Drawer Navigation (Photo 3 Match)
          =================================================================== */}
      <AnimatePresence>
        {drawerOpen && (
          <motion.div
            className="lp-drawer-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setDrawerOpen(false)}
          >
            <motion.div
              className="lp-drawer-panel"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
              onClick={(e) => e.stopPropagation()}
            >
              <div>
                {/* Header matching Photo 3 */}
                <div className="lp-drawer-tab-header">
                  <div className="lp-card-tab">[ NAVIGATION ]</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <button
                      className="lp-btn-primary lp-btn-chamfer"
                      style={{ padding: '6px 14px', fontSize: '11px' }}
                      onClick={() => {
                        setDrawerOpen(false)
                        onLaunchApp()
                      }}
                    >
                      <TerminalIcon size={12} />
                      <span>Console</span>
                    </button>
                    <button className="lp-menu-btn" onClick={() => setDrawerOpen(false)}>✕</button>
                  </div>
                </div>

                {/* Photo 3 Menu Links */}
                <div className="lp-drawer-links">
                  <span className="lp-drawer-link" onClick={() => scrollToSection('problem')}>HOME</span>
                  <span className="lp-drawer-link" onClick={() => scrollToSection('how-it-works')}>PROCESS</span>
                  <span className="lp-drawer-link" onClick={() => scrollToSection('pqc')}>QUANTUM</span>
                  <span className="lp-drawer-link" onClick={() => scrollToSection('modules')}>MODULES</span>
                  <span className="lp-drawer-link" onClick={() => scrollToSection('compliance')}>COMPLIANCE</span>
                </div>
              </div>

              {/* Photo 3 Button States Demonstration */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div className="lp-btn-state-wrap">
                  <button
                    className="lp-btn-primary lp-btn-chamfer"
                    style={{ width: '100%' }}
                    onClick={() => {
                      setDrawerOpen(false)
                      onLaunchApp()
                    }}
                  >
                    <span>GET EARLY ACCESS</span>
                  </button>
                  <span className="lp-btn-sublabel">NORMAL</span>
                </div>

                <div className="lp-btn-state-wrap">
                  <button
                    className="lp-btn-primary lp-btn-chamfer"
                    style={{ width: '100%' }}
                    onClick={() => {
                      setDrawerOpen(false)
                      onLaunchApp()
                    }}
                  >
                    <Check size={16} strokeWidth={2} />
                    <span>ENGINE READY!</span>
                  </button>
                  <span className="lp-btn-sublabel">FORENSIC SUITE CONNECTED</span>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ===================================================================
          11. Footer
          =================================================================== */}
      <footer className="lp-footer">
        <div className="lp-container lp-footer-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span>© {new Date().getFullYear()} SecureMailScope</span>
            <span>·</span>
            <span>AI-Assisted Cryptographic Security Posture Assessment</span>
          </div>

          <div style={{ display: 'flex', gap: '16px' }}>
            <span>RFC 3207</span>
            <span>RFC 8461 (MTA-STS)</span>
            <span>NIST FIPS 203</span>
            <span>PCI-DSS 4.0</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
