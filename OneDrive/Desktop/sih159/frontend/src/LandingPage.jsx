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
  const [activeSim, setActiveSim] = useState('insecure') // 'insecure' | 'hardened'
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

          {/* Top Row: 4 Feature Cards with Icon Boxes (Photo 2) */}
          <div className="lp-circuit-feature-cards">
            {[
              {
                icon: RefreshCw,
                tag: 'NON-INVASIVE WIRE ANALYSIS',
                desc: 'Audit & assess mail traffic with zero agents, zero downtime, and zero packet modification.',
                notchClass: 'lp-feature-notch-bl'
              },
              {
                icon: Sparkles,
                tag: 'PASSIVE PCAP REASSEMBLY',
                desc: 'Reconstruct live TCP streams to immediately expose cleartext leaks, STARTTLS stripping, and rogue relays.',
                notchClass: ''
              },
              {
                icon: Atom,
                tag: 'NIST FIPS 203 PQC RADAR',
                desc: 'Inspect hybrid ML-KEM-768 key exchanges to eliminate Harvest-Now-Decrypt-Later quantum threats.',
                notchClass: ''
              },
              {
                icon: ShieldAlert,
                tag: 'ACTIVE EXPLOIT & MITM SHIELDS',
                desc: 'Never get caught by protocol downgrade attacks, cipher tampering, or forged TLS handshake certificates.',
                notchClass: 'lp-feature-notch-r'
              }
            ].map((card, idx) => {
              const IconComponent = card.icon
              return (
                <motion.div
                  key={idx}
                  className={`lp-card-xotc ${card.notchClass}`}
                  initial={{ opacity: 0, y: 24 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: '-40px' }}
                  transition={{ duration: 0.5, delay: idx * 0.12, ease: [0.16, 1, 0.3, 1] }}
                >
                  <div className="lp-card-xotc-inner">
                    <div>
                      <div className="lp-icon-box-xotc">
                        <IconComponent size={22} strokeWidth={1.8} />
                      </div>
                      <p style={{ fontSize: '13.5px', color: 'var(--lp-text-secondary)', lineHeight: '1.55', margin: 0, fontWeight: '500' }}>
                        {card.desc}
                      </p>
                    </div>

                    <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontFamily: 'var(--lp-font-mono)', fontSize: '10px', color: 'var(--lp-accent-chartreuse)', letterSpacing: '0.06em' }}>
                        {card.tag}
                      </span>
                      <div className="lp-dot-matrix" aria-hidden="true">
                        {[...Array(15)].map((_, i) => (
                          <span key={i} className="lp-dot" />
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>

          {/* Middle Tactical Banner (Photo 2) */}
          <motion.div
            className="lp-circuit-banner"
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <strong>SecureMailScope solves these issues.</strong> Audit and harden enterprise mail transport off-market with zero risk of cleartext stripping, handshake downgrade, or quantum exposure.
          </motion.div>

          {/* Serpentine 3-Row Circuit Track with SVG & Sequential Flow-State Nodes (Photo 2) */}
          <div className="lp-circuit-container">
            {/* SVG Connecting S-Curve Circuit Track */}
            <svg
              className="lp-circuit-svg"
              viewBox="0 0 1000 420"
              fill="none"
              preserveAspectRatio="none"
            >
              {/* Background Guide Line */}
              <path
                d="M 0 40 L 840 40 C 920 40 940 70 940 120 C 940 170 920 195 840 195 L 160 195 C 80 195 60 225 60 275 C 60 325 80 350 160 350 L 760 350"
                className="lp-circuit-bg-path"
              />
              {/* Animated Glowing Flow-State Path */}
              <motion.path
                d="M 0 40 L 840 40 C 920 40 940 70 940 120 C 940 170 920 195 840 195 L 160 195 C 80 195 60 225 60 275 C 60 325 80 350 160 350 L 760 350"
                className="lp-circuit-active-path"
                initial={{ pathLength: 0 }}
                whileInView={{ pathLength: 1 }}
                viewport={{ once: true, margin: '-40px' }}
                transition={{ duration: 2.6, ease: 'easeInOut' }}
              />
            </svg>

            <div className="lp-circuit-rows-wrap">
              {/* Row 1: Left to Right (Nodes 1, 2, 3) */}
              <div className="lp-circuit-row">
                {[
                  { id: 1, title: 'Concept', subtitle: 'RFC 3207 / 8461 Architecture', state: 'completed' },
                  { id: 2, title: 'Testnet working', subtitle: 'Passive Stream Engine', state: 'completed' },
                  { id: 3, title: 'Front-end integration', subtitle: 'Cryptographic Forensics UI', state: 'completed' }
                ].map((node, i) => (
                  <motion.div
                    key={node.id}
                    className="lp-circuit-node"
                    initial={{ opacity: 0, scale: 0.7, y: 15 }}
                    whileInView={{ opacity: 1, scale: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.45, delay: 0.2 + i * 0.35, ease: [0.16, 1, 0.3, 1] }}
                  >
                    <div className={`lp-node-circle ${node.state}`}>
                      <Check size={18} strokeWidth={2} />
                    </div>
                    <div className="lp-node-title">{node.title}</div>
                    <div className="lp-node-subtitle">{node.subtitle}</div>
                  </motion.div>
                ))}
              </div>

              {/* Row 2: Right to Left (Nodes 4, 5, 6 - reverse order) */}
              <div className="lp-circuit-row row-reverse">
                {[
                  {
                    id: 4,
                    title: 'Branding',
                    subtitle: 'Forensic Visual Pipeline',
                    state: 'active',
                    isVehicleSlot: true
                  },
                  { id: 5, title: 'New Platform UI', subtitle: 'AI Anomaly Studio', state: 'pending' },
                  { id: 6, title: 'Early Access', subtitle: 'Enterprise Security SOC', state: 'pending' }
                ].map((node, i) => (
                  <motion.div
                    key={node.id}
                    className="lp-circuit-node"
                    initial={{ opacity: 0, scale: 0.7, y: 15 }}
                    whileInView={{ opacity: 1, scale: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.45, delay: 1.2 + i * 0.35, ease: [0.16, 1, 0.3, 1] }}
                  >
                    {node.isVehicleSlot && (
                      <div className="lp-vehicle-slot">
                        <span className="lp-vehicle-slot-pulse" />
                        <span className="lp-vehicle-slot-text">[ ACTIVE PROGRESS POINT ]</span>
                      </div>
                    )}
                    <div className={`lp-node-circle ${node.state}`}>
                      {node.state === 'active' ? (
                        <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#000000' }} />
                      ) : (
                        <span className="lp-node-dot" />
                      )}
                    </div>
                    <div className="lp-node-title">{node.title}</div>
                    <div className="lp-node-subtitle">{node.subtitle}</div>
                  </motion.div>
                ))}
              </div>

              {/* Row 3: Left to Right (Nodes 7, 8) */}
              <div className="lp-circuit-row">
                {[
                  { id: 7, title: 'Mainnet launch', subtitle: 'FIPS 203 Production', state: 'pending' },
                  { id: 8, title: 'Launchpad', subtitle: 'Global Compliance Registry', state: 'pending' }
                ].map((node, i) => (
                  <motion.div
                    key={node.id}
                    className="lp-circuit-node"
                    initial={{ opacity: 0, scale: 0.7, y: 15 }}
                    whileInView={{ opacity: 1, scale: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.45, delay: 2.1 + i * 0.35, ease: [0.16, 1, 0.3, 1] }}
                  >
                    <div className={`lp-node-circle ${node.state}`}>
                      <span className="lp-node-dot" />
                    </div>
                    <div className="lp-node-title">{node.title}</div>
                    <div className="lp-node-subtitle">{node.subtitle}</div>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
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
          7. Interactive Forensic Preview Terminal
          =================================================================== */}
      <section className="lp-section" id="terminal">
        <div className="lp-container">
          <div className="lp-section-header center">
            <div className="lp-pretitle">
              <TerminalIcon size={14} />
              <span>Interactive Posture Preview</span>
            </div>
            <h2 className="lp-title">See an Audit in <span>Action</span></h2>
            <p className="lp-desc">
              Compare a misconfigured legacy mail gateway against a hardened server configured to modern NIST and PQC standards.
            </p>
          </div>

          <div className="lp-card-xotc lp-terminal-card">
            <div className="lp-card-xotc-inner" style={{ padding: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px 8px 20px' }}>
                <div className="lp-card-tab">[ FORENSIC PROBE SIMULATOR ]</div>
                <div className="lp-dot-matrix" aria-hidden="true">
                  {[...Array(25)].map((_, i) => (
                    <span key={i} className="lp-dot" />
                  ))}
                </div>
              </div>

              <div className="lp-terminal-bar">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: 'var(--lp-accent-chartreuse)' }} />
                  <span style={{ fontFamily: 'var(--lp-font-mono)', fontSize: '12px', color: 'var(--lp-text-primary)' }}>
                    FORENSIC PROBE TELEMETRY — {activeSim === 'insecure' ? 'mail.legacy-bank.example' : 'mx1.hardened-pqc.gov'}
                  </span>
                </div>
                <span className="lp-status-pill">PORT 25 (SMTP)</span>
              </div>

            <div className="lp-terminal-body">
              {/* Left Column: Simulation Controls */}
              <div>
                <div style={{ fontFamily: 'var(--lp-font-mono)', fontSize: '11px', color: 'var(--lp-text-muted)', marginBottom: '10px' }}>
                  SELECT SCENARIO:
                </div>

                <div className="lp-sim-switch-group">
                  <button
                    className={`lp-sim-btn ${activeSim === 'insecure' ? 'active' : ''}`}
                    onClick={() => setActiveSim('insecure')}
                  >
                    <AlertTriangle size={14} />
                    <span>Misconfigured Gateway</span>
                  </button>

                  <button
                    className={`lp-sim-btn ${activeSim === 'hardened' ? 'active' : ''}`}
                    onClick={() => setActiveSim('hardened')}
                  >
                    <ShieldCheck size={14} />
                    <span>Hardened PQC Server</span>
                  </button>
                </div>

                <div className="lp-sim-result-box">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontFamily: 'var(--lp-font-mono)', fontSize: '11px', color: 'var(--lp-text-muted)' }}>POSTURE SCORE</span>
                    <span style={{
                      fontFamily: 'var(--lp-font-heading)',
                      fontSize: '24px',
                      fontWeight: '700',
                      color: activeSim === 'insecure' ? 'var(--lp-accent-coral)' : 'var(--lp-accent-chartreuse)'
                    }}>
                      {activeSim === 'insecure' ? '18 / 100 [GRADE F]' : '98 / 100 [GRADE A+]'}
                    </span>
                  </div>

                  <p style={{ fontSize: '13px', color: 'var(--lp-text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    {activeSim === 'insecure'
                      ? 'CRITICAL DEFECTS: STARTTLS stripped mid-session. Plaintext credentials transmitted. Obsolete CBC cipher suites accepted. Zero post-quantum protection.'
                      : 'SECURE: TLS 1.3 enforced. Hybrid X25519MLKEM768 post-quantum key exchange active. MTA-STS enforced. DMARC policy set to reject.'
                    }
                  </p>
                </div>

                <button className="lp-btn-primary lp-btn-chamfer" style={{ width: '100%' }} onClick={onLaunchApp}>
                  <span>Audit Your Domain in Console</span>
                  <ArrowRight size={15} />
                </button>
              </div>

              {/* Right Column: Handshake Parameters */}
              <div>
                <div style={{ fontFamily: 'var(--lp-font-mono)', fontSize: '11px', color: 'var(--lp-text-muted)', marginBottom: '10px' }}>
                  CRYPTOGRAPHIC HANDSHAKE AUDIT:
                </div>

                <div className="lp-data-grid">
                  <div className="lp-data-tile">
                    <div className="lp-data-label">TLS VERSION</div>
                    <div className={`lp-data-value ${activeSim === 'insecure' ? 'danger' : 'safe'}`}>
                      {activeSim === 'insecure' ? 'N/A (No TLS Handshake)' : 'TLSv1.3'}
                    </div>
                  </div>

                  <div className="lp-data-tile">
                    <div className="lp-data-label">CIPHER SUITE</div>
                    <div className={`lp-data-value ${activeSim === 'insecure' ? 'danger' : 'safe'}`} style={{ fontSize: '11px' }}>
                      {activeSim === 'insecure' ? 'N/A (Plaintext Session)' : 'TLS_AES_256_GCM_SHA384'}
                    </div>
                  </div>

                  <div className="lp-data-tile">
                    <div className="lp-data-label">KEY EXCHANGE</div>
                    <div className={`lp-data-value ${activeSim === 'insecure' ? 'danger' : 'safe'}`}>
                      {activeSim === 'insecure' ? 'None (Cleartext)' : 'ECDHE + PQC (Hybrid)'}
                    </div>
                  </div>

                  <div className="lp-data-tile">
                    <div className="lp-data-label">PQC NAMED GROUP</div>
                    <div className={`lp-data-value ${activeSim === 'insecure' ? 'danger' : 'safe'}`}>
                      {activeSim === 'insecure' ? 'None (Vulnerable)' : 'X25519MLKEM768 (0x6399)'}
                    </div>
                  </div>

                  <div className="lp-data-tile">
                    <div className="lp-data-label">MTA-STS DOWNGRADE SHIELD</div>
                    <div className={`lp-data-value ${activeSim === 'insecure' ? 'danger' : 'safe'}`}>
                      {activeSim === 'insecure' ? 'Missing' : 'Enforce (RFC 8461)'}
                    </div>
                  </div>

                  <div className="lp-data-tile">
                    <div className="lp-data-label">DMARC POLICY</div>
                    <div className={`lp-data-value ${activeSim === 'insecure' ? 'danger' : 'safe'}`}>
                      {activeSim === 'insecure' ? 'p=none (Spoofable)' : 'p=reject (Protected)'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          8. Trust & Regulatory Cards
          =================================================================== */}
      <section className="lp-section">
        <div className="lp-container">
          <div className="lp-section-header center">
            <div className="lp-pretitle">
              <ShieldCheck size={14} />
              <span>Audit Readiness</span>
            </div>
            <h2 className="lp-title">Built for <span>Compliance Teams</span></h2>
            <p className="lp-desc">
              Pass security audits with verifiable proof that your email transmission channels comply with international mandates.
            </p>
          </div>

          <div className="lp-trust-grid">
            <div className="lp-card-xotc lp-trust-card">
              <div className="lp-card-xotc-inner">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div className="lp-card-tab">[ MANDATE: PCI-DSS 4.0 ]</div>
                  <div className="lp-dot-matrix" aria-hidden="true">
                    {[...Array(15)].map((_, i) => (
                      <span key={i} className="lp-dot" />
                    ))}
                  </div>
                </div>
                <h3 className="lp-trust-title">PCI-DSS 4.0 (Req 4.2.1)</h3>
                <p className="lp-trust-desc">
                  Mandates strong cryptography during the transmission of cardholder data across open networks. Prohibits obsolete TLS 1.0/1.1 and insecure ciphers.
                </p>
                <ul className="lp-trust-list">
                  <li>Verifies mandatory TLS encryption</li>
                  <li>Flags deprecated CBC and 3DES ciphers</li>
                  <li>Generates audit evidence reports</li>
                </ul>
              </div>
            </div>

            <div className="lp-card-xotc lp-trust-card">
              <div className="lp-card-xotc-inner">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div className="lp-card-tab">[ STANDARD: NIST SP 800-52 ]</div>
                  <div className="lp-dot-matrix" aria-hidden="true">
                    {[...Array(15)].map((_, i) => (
                      <span key={i} className="lp-dot" />
                    ))}
                  </div>
                </div>
                <h3 className="lp-trust-title">NIST SP 800-52 Rev. 2</h3>
                <p className="lp-trust-desc">
                  Federal guidelines for TLS configurations across government agencies and contractors. Requires ephemeral forward secrecy and strict certificate trust paths.
                </p>
                <ul className="lp-trust-list">
                  <li>Inspects ECDHE forward secrecy</li>
                  <li>Validates SHA-256+ signature hashes</li>
                  <li>Prepares infrastructure for NIST FIPS 203 PQC</li>
                </ul>
              </div>
            </div>

            <div className="lp-card-xotc lp-trust-card">
              <div className="lp-card-xotc-inner">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div className="lp-card-tab">[ STATUTE: HIPAA §164.312 ]</div>
                  <div className="lp-dot-matrix" aria-hidden="true">
                    {[...Array(15)].map((_, i) => (
                      <span key={i} className="lp-dot" />
                    ))}
                  </div>
                </div>
                <h3 className="lp-trust-title">HIPAA §164.312(e)(1)</h3>
                <p className="lp-trust-desc">
                  Federal transmission security standard governing electronic protected health information (ePHI). Unencrypted email creates immediate breach liability.
                </p>
                <ul className="lp-trust-list">
                  <li>Eliminates cleartext mail exchange risks</li>
                  <li>Verifies MTA-STS downgrade prevention</li>
                  <li>Ensures mutual server authentication</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          9. Final Call to Action
          =================================================================== */}
      <section className="lp-section" style={{ paddingBottom: '110px' }}>
        <div className="lp-container">
          <div className="lp-card-xotc lp-final-cta-card">
            <div className="lp-card-xotc-inner" style={{ padding: '48px 32px', textAlign: 'center', alignItems: 'center' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', marginBottom: '24px' }}>
                <div className="lp-card-tab">[ ENTERPRISE AUDIT DISPATCH ]</div>
                <div className="lp-dot-matrix" aria-hidden="true">
                  {[...Array(25)].map((_, i) => (
                    <span key={i} className="lp-dot" />
                  ))}
                </div>
              </div>

              <h2 className="lp-final-cta-title">
                Assess your email security posture <span>in seconds</span>.
              </h2>

              <p className="lp-final-cta-desc">
                Inspect PCAP network traffic or run a zero-touch probe on your domain's live MX records. Completely non-disruptive, with zero agents required.
              </p>

              <button
                className="lp-btn-primary lp-btn-chamfer"
                style={{ fontSize: '14px', padding: '14px 38px' }}
                onClick={onLaunchApp}
              >
                <span>Initialize Cockpit</span>
                <ArrowRight size={17} />
              </button>

              <div className="lp-guarantee-row">
                <span>✓ Passive Wire Forensics</span>
                <span>·</span>
                <span>✓ Active Live MX Probing</span>
                <span>·</span>
                <span>✓ NIST FIPS 203 Quantum Defense</span>
                <span>·</span>
                <span>✓ Ready-to-Run Fixes</span>
              </div>
            </div>
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
