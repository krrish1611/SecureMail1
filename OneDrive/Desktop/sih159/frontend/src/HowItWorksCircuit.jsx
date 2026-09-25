import React, { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Cpu,
  Database,
  Mail,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  Lock,
  Server,
  Radio,
  Layers,
  Activity,
  TrendingUp,
  Gauge,
  FileCheck,
  AlertTriangle,
  Wrench,
  Terminal as TerminalIcon,
  Check,
  Boxes,
  Settings,
  ArrowRight,
  Zap,
  Atom
} from 'lucide-react'

// 3 Real Pipeline Stages of SecureMailScope
const PIPELINE_STAGES = [
  {
    id: 0,
    tabLabel: '1. WIRE INGESTION',
    themeTag: '1. WIRE INGESTION',
    hubTitle: 'SECUREMAIL\nAI ENGINE',
    hubEyebrow: 'ZERO-TOUCH WIRE CAPTURE',
    hubSubcopy: 'Passively reassembles raw network packets into ordered TCP streams and SMTP dialogues without private keys.',
    flowInput: 'Raw Network Wire & PCAPs',
    flowOutput: 'Session Forensics & Dialogues',
    ticket: {
      eyebrow: 'SECUREMAILSCOPE TELEMETRY',
      headline: 'Wire Reassembled',
      code: 'INSPECT SESSIONS'
    },
    leftCards: [
      {
        id: 'c1',
        title: 'LIVE WIRE & PCAP',
        sub: 'PASSIVE PACKET SNIFFING',
        icons: ['radio', 'server']
      },
      {
        id: 'c2',
        title: 'TCP REASSEMBLY',
        sub: 'RFC 793 STREAM ENGINE',
        icons: ['layers', 'cpu']
      },
      {
        id: 'c3',
        title: 'MAIL PROTOCOL PARSER',
        sub: 'SMTP, IMAP, POP3 COMMANDS',
        icons: ['mail', 'terminal']
      }
    ]
  },
  {
    id: 1,
    tabLabel: '2. CRYPTOGRAPHIC AUDIT',
    themeTag: '2. TLS & CIPHER AUDIT',
    hubTitle: 'SECUREMAIL\nAI ENGINE',
    hubEyebrow: 'MITM & DOWNGRADE DEFENSE',
    hubSubcopy: 'Audits STARTTLS stripping, obsolete CBC ciphers, and validates NIST FIPS 203 quantum-resistant hybrid exchanges.',
    flowInput: 'TLS Handshakes & Ciphers',
    flowOutput: 'Cipher Radar & Quantum Rating',
    ticket: {
      eyebrow: 'SECUREMAILSCOPE TELEMETRY',
      headline: 'STRIPTLS Protected',
      code: 'VIEW CIPHER RADAR'
    },
    leftCards: [
      {
        id: 'c1',
        title: 'STRIPTLS DEFENSE',
        sub: 'RFC 8461 MTA-STS & DANE',
        icons: ['shieldAlert', 'lock']
      },
      {
        id: 'c2',
        title: 'CIPHER SUITE AUDIT',
        sub: 'TLS 1.3 / FORWARD SECRECY',
        icons: ['lock', 'shieldCheck']
      },
      {
        id: 'c3',
        title: 'POST-QUANTUM AUDIT',
        sub: 'NIST FIPS 203 ML-KEM',
        icons: ['atom', 'zap']
      }
    ]
  },
  {
    id: 2,
    tabLabel: '3. AI SCORING & REMEDY',
    themeTag: '3. AI POSTURE & REMEDY',
    hubTitle: 'SECUREMAIL\nAI ENGINE',
    hubEyebrow: 'ZERO-DAY THREAT & HARDENING',
    hubSubcopy: 'Dual-model AI computes real-time 0-100 posture grades and auto-generates Postfix, Exim & M365 hardening playbooks.',
    flowInput: '14 Cryptographic Features',
    flowOutput: 'Compliance & Fix Playbooks',
    ticket: {
      eyebrow: 'SECUREMAILSCOPE VERDICT',
      headline: 'Score: 98/100 (A+)',
      code: 'LAUNCH COCKPIT'
    },
    leftCards: [
      {
        id: 'c1',
        title: 'ISOLATION FOREST',
        sub: 'UNSUPERVISED ANOMALY ML',
        icons: ['activity', 'cpu']
      },
      {
        id: 'c2',
        title: 'RANDOM FOREST SCORER',
        sub: '0-100 POSTURE VERDICT',
        icons: ['trendingUp', 'gauge']
      },
      {
        id: 'c3',
        title: 'HARDENING PLAYBOOKS',
        sub: 'AUTOMATED FIX SCRIPTS',
        icons: ['wrench', 'fileCheck']
      }
    ]
  }
]

// 3 Dynamic Right Expansion Cartridge Bays matching SecureMailScope outputs:
const RIGHT_CARTRIDGES = [
  {
    id: 0,
    title: 'SESSION FORENSICS',
    sub: 'data slot 01 • Reassembled Wire Streams',
    badgeText: 'WIRE CAPTURE',
    icons: ['layers', 'database', 'cpu']
  },
  {
    id: 1,
    title: 'CIPHER & PQC RADAR',
    sub: 'data slot 02 • STRIPTLS & Quantum Defense',
    badgeText: 'CRYPTO AUDIT',
    icons: ['lock', 'shieldCheck', 'atom']
  },
  {
    id: 2,
    title: 'COMPLIANCE VAULT',
    sub: 'data slot 03 • PCI-DSS & Auto-Remediation',
    badgeText: 'INSTANT FIXES',
    icons: ['fileCheck', 'wrench', 'check']
  }
]

const leftCardMotionVariants = {
  initial: () => ({
    x: -80,
    z: 50,
    scale: 1.05,
    rotateY: -8,
    rotateX: 2,
    opacity: 0,
    filter: 'drop-shadow(0px 20px 25px rgba(0, 0, 0, 0.5))'
  }),
  animate: (idx) => {
    const isMiddle = idx === 1;
    return {
      x: 0,
      z: 0,
      scale: 1,
      rotateY: 0,
      rotateX: 0,
      opacity: 1,
      filter: 'drop-shadow(0px 0px 0px rgba(0, 0, 0, 0))',
      transition: {
        duration: 0.46,
        delay: isMiddle ? 0.04 : 0.18,
        ease: [0.22, 1, 0.36, 1]
      }
    };
  },
  exit: (idx) => {
    const isMiddle = idx === 1;
    return {
      // 1. Float forward (z: 52, scale: 1.05, rotateY: -8), x STAYS at 0!
      // 2. Card design DOES NOT disappear! Opacity remains 1 as it floats and slides.
      // 3. Middle slides out first (starts at 0.40s), top & bottom follow (starts at 0.56s)
      x: isMiddle ? [0, 0, -130] : [0, 0, -130],
      z: [0, 52, 52],
      scale: [1, 1.05, 1.05],
      rotateY: [0, -8, -8],
      rotateX: [0, 2, 2],
      opacity: [1, 1, 1, 0],
      filter: [
        'drop-shadow(0px 0px 0px rgba(0, 0, 0, 0))',
        'drop-shadow(0px 22px 28px rgba(0, 0, 0, 0.55))',
        'drop-shadow(0px 22px 28px rgba(0, 0, 0, 0.55))',
        'drop-shadow(0px 22px 28px rgba(0, 0, 0, 0.55))'
      ],
      transition: {
        duration: isMiddle ? 0.74 : 0.90,
        times: isMiddle ? [0, 0.40, 0.82, 1] : [0, 0.56, 0.88, 1],
        ease: 'easeInOut'
      }
    };
  }
};

const rightCardMotionVariants = {
  initial: () => ({
    x: 80,
    z: 50,
    scale: 1.05,
    rotateY: 8,
    rotateX: 2,
    opacity: 0,
    filter: 'drop-shadow(0px 20px 25px rgba(0, 0, 0, 0.5))'
  }),
  animate: () => ({
    x: 0,
    z: 0,
    scale: 1,
    rotateY: 0,
    rotateX: 0,
    opacity: 1,
    filter: 'drop-shadow(0px 0px 0px rgba(0, 0, 0, 0))',
    transition: {
      duration: 0.44,
      ease: [0.22, 1, 0.36, 1]
    }
  }),
  exit: () => ({
    // Floats forward first while connection disconnects (lights/text off), then slides out right!
    x: [0, 0, 130],
    z: [0, 52, 52],
    scale: [1, 1.05, 1.05],
    rotateY: [0, 8, 8],
    rotateX: [0, 2, 2],
    opacity: [1, 1, 1, 0],
    filter: [
      'drop-shadow(0px 0px 0px rgba(0, 0, 0, 0))',
      'drop-shadow(0px 22px 28px rgba(0, 0, 0, 0.55))',
      'drop-shadow(0px 22px 28px rgba(0, 0, 0, 0.55))',
      'drop-shadow(0px 22px 28px rgba(0, 0, 0, 0.55))'
    ],
    transition: {
      duration: 0.88,
      times: [0, 0.48, 0.85, 1],
      ease: 'easeInOut'
    }
  })
};

const ledMotionVariants = {
  initial: { opacity: 0.25, backgroundColor: '#20242c', boxShadow: 'none' },
  animate: {
    opacity: 1,
    backgroundColor: 'var(--sl-accent-orange)',
    boxShadow: 'var(--sl-led-shadow)',
    transition: { duration: 0.28, delay: 0.16 }
  },
  exit: {
    // Light is OFF (unlit dark diode, no glow, doesn't disappear)
    opacity: 0.25,
    backgroundColor: '#1a1e26',
    boxShadow: '0 0 0px transparent',
    transition: { duration: 0.18, ease: 'easeOut' }
  }
};

const textPowerVariants = {
  initial: { opacity: 0.15 },
  animate: {
    opacity: 1,
    transition: { duration: 0.28, delay: 0.16 }
  },
  exit: {
    // Text is OFF (dim unlit LCD text, doesn't disappear)
    opacity: 0.14,
    transition: { duration: 0.18, ease: 'easeOut' }
  }
};

export default function HowItWorksCircuit({ onLaunchApp }) {
  const [activeStateIdx, setActiveStateIdx] = useState(0)
  const [displayedRightIdx, setDisplayedRightIdx] = useState(0)
  const [isPaused, setIsPaused] = useState(false)
  const [isSignalsStopped, setIsSignalsStopped] = useState(false)
  const [isTransitioning, setIsTransitioning] = useState(false)

  const isTransitioningRef = useRef(false)
  const activeStateIdxRef = useRef(0)
  const transitionTimersRef = useRef([])

  useEffect(() => {
    isTransitioningRef.current = isTransitioning
  }, [isTransitioning])

  useEffect(() => {
    activeStateIdxRef.current = activeStateIdx
  }, [activeStateIdx])

  const clearTimers = () => {
    transitionTimersRef.current.forEach(clearTimeout)
    transitionTimersRef.current = []
  }

  useEffect(() => {
    return () => clearTimers()
  }, [])

  // Synchronized Stage Coordinator:
  // 1. t = 0: All signals STOP completely (opacity: 0, hidden). Old cards float & slide out (middle first on left).
  // 2. t = 950ms: Left AnimatePresence mounts new left cards, which slide in & settle.
  // 3. t = 1600ms: AFTER left cards have arrived & settled, the right card mounts and enters from the right!
  // 4. t = 2150ms: Right card has docked behind front bar, signals & dots resume flowing!
  const changeStage = useCallback((targetIdx) => {
    if (targetIdx === activeStateIdxRef.current || isTransitioningRef.current) return
    setIsTransitioning(true)
    isTransitioningRef.current = true
    setIsSignalsStopped(true)
    setActiveStateIdx(targetIdx)
    setDisplayedRightIdx(null) // triggers old right card departure

    clearTimers()

    // At 1600ms: Left cards have arrived and settled -> now mount Right card!
    const tRight = setTimeout(() => {
      setDisplayedRightIdx(targetIdx)

      // At 2150ms: Right card has landed and docked -> resume signals and unlock
      const tResume = setTimeout(() => {
        setIsSignalsStopped(false)
        setIsTransitioning(false)
        isTransitioningRef.current = false
      }, 550)
      transitionTimersRef.current.push(tResume)
    }, 1600)
    transitionTimersRef.current.push(tRight)
  }, [])

  // Auto-play state carousel every ~5.8s
  useEffect(() => {
    if (isPaused) return
    const timer = setInterval(() => {
      if (isTransitioningRef.current) return
      const nextIdx = (activeStateIdxRef.current + 1) % PIPELINE_STAGES.length
      changeStage(nextIdx)
    }, 5800)
    return () => clearInterval(timer)
  }, [isPaused, changeStage])

  const currentState = PIPELINE_STAGES[activeStateIdx]

  const handlePrev = (e) => {
    e?.stopPropagation()
    if (isTransitioningRef.current) return
    const prevIdx = (activeStateIdxRef.current - 1 + PIPELINE_STAGES.length) % PIPELINE_STAGES.length
    changeStage(prevIdx)
  }

  const handleNext = (e) => {
    e?.stopPropagation()
    if (isTransitioningRef.current) return
    const nextIdx = (activeStateIdxRef.current + 1) % PIPELINE_STAGES.length
    changeStage(nextIdx)
  }

  const renderCardBadgeIcon = (type) => {
    switch (type) {
      case 'atom':
        return <Atom size={11} strokeWidth={2.2} />
      case 'radio':
        return <Radio size={11} strokeWidth={2.2} />
      case 'server':
        return <Server size={11} strokeWidth={2.2} />
      case 'layers':
        return <Layers size={11} strokeWidth={2.2} />
      case 'cpu':
        return <Cpu size={11} strokeWidth={2.2} />
      case 'mail':
        return <Mail size={11} strokeWidth={2.2} />
      case 'database':
        return <Database size={11} strokeWidth={2.2} />
      case 'shield':
        return <Shield size={11} strokeWidth={2.2} />
      case 'shieldAlert':
        return <ShieldAlert size={11} strokeWidth={2.2} />
      case 'shieldCheck':
        return <ShieldCheck size={11} strokeWidth={2.2} />
      case 'alertTriangle':
        return <AlertTriangle size={11} strokeWidth={2.2} />
      case 'lock':
        return <Lock size={11} strokeWidth={2.2} />
      case 'fileCheck':
        return <FileCheck size={11} strokeWidth={2.2} />
      case 'activity':
        return <Activity size={11} strokeWidth={2.2} />
      case 'trendingUp':
        return <TrendingUp size={11} strokeWidth={2.2} />
      case 'gauge':
        return <Gauge size={11} strokeWidth={2.2} />
      case 'wrench':
        return <Wrench size={11} strokeWidth={2.2} />
      case 'terminal':
        return <TerminalIcon size={11} strokeWidth={2.2} />
      case 'boxes':
        return <Boxes size={11} strokeWidth={2.2} />
      case 'settings':
        return <Settings size={11} strokeWidth={2.2} />
      case 'check':
        return <Check size={11} strokeWidth={2.2} />
      case 'zap':
      default:
        return <Zap size={11} strokeWidth={2.2} />
    }
  }

  return (
    <div
      className="lp-superlinked-root"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      {/* ===================================================================
          AUTHENTIC INDUSTRIAL MOTHERBOARD / PCB CANVAS
          3-Column Cryptographic Forensics Pipeline:
          - Left: 3 Data Source Inputs (Packets -> Streams -> Protocols)
          - Center: SecureMail AI Engine + Real-Time Telemetry Ticket
          - Right: 3 Expansion Cartridge Bays (Sessions -> Radar -> Compliance)
          =================================================================== */}
      <div className="lp-superlinked-pcb">
        {/* Motherboard Relief Chassis & Hardware Details Layer */}
        <div className="lp-pcb-chassis-layer" aria-hidden="true">
          {/* Sculpted CNC Milled Background Contour Ridges */}
          <div className="lp-pcb-cnc-ridge ridge-diagonal-left" />
          <div className="lp-pcb-cnc-ridge ridge-diagonal-center" />
          <div className="lp-pcb-cnc-ridge ridge-curved-dispenser" />

          {/* Top Board Silkscreen Code */}
          <div className="lp-top-pcb-marking">
            <span>SECUREMAILSCOPE-CORE</span>
            <span>v2.4.1 FORENSIC ENGINE</span>
          </div>

          {/* Top-Left Angled Beveled Chassis Vent Plate */}
          <div className="lp-top-left-vent-plate">
            <span className="vent-slot-angled" />
            <span className="vent-slot-angled" />
            <span className="vent-slot-angled" />
            <span className="vent-plate-screw" />
          </div>

          {/* Left 2x3 Grid of Sunken Square IC Heatsink Sockets */}
          <div className="lp-left-ic-socket-grid">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="lp-recessed-socket">
                <div className="lp-socket-fins">
                  <span className="fin-line" />
                  <span className="fin-line" />
                  <span className="fin-line" />
                  <span className="fin-line" />
                  <span className="fin-line" />
                </div>
              </div>
            ))}
          </div>

          {/* Bottom-Left Hardware: DIP-8 IC Chips & Silkscreen Code Specs */}
          <div className="lp-bottom-left-hardware">
            <div className="lp-pcb-dip-chips">
              <div className="lp-dip-chip">
                <div className="lp-chip-pins top-pins">
                  <span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" />
                </div>
                <div className="lp-chip-body">
                  <span className="lp-chip-notch" />
                  <span className="lp-chip-print">SMS-CORE</span>
                </div>
                <div className="lp-chip-pins bottom-pins">
                  <span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" />
                </div>
              </div>

              <div className="lp-dip-chip">
                <div className="lp-chip-pins top-pins">
                  <span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" />
                </div>
                <div className="lp-chip-body">
                  <span className="lp-chip-notch" />
                  <span className="lp-chip-print">TLS-1.3</span>
                </div>
                <div className="lp-chip-pins bottom-pins">
                  <span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" /><span className="chip-pin" />
                </div>
              </div>
            </div>

            {/* Micro Silkscreen Specification Print */}
            <div className="lp-pcb-silkscreen-block">
              <span className="silk-row">SMS-CORE FORENSIC ENGINE v2.4</span>
              <span className="silk-row">RFC 8461 MTA-STS &bull; RFC 7672 DANE</span>
              <span className="silk-row">NIST FIPS 203 ML-KEM &bull; TLS 1.3</span>
              <span className="silk-row">PCI-DSS 4.0 REQ 4.2 &bull; HIPAA 164.312</span>
            </div>
          </div>

          {/* Top-Center Hardware: 3 Sensor Ports + Coordinate Silkscreen */}
          <div className="lp-top-sensor-cluster">
            <div className="lp-sensor-coord">
              <span>00321</span>
              <span>00:11</span>
            </div>
            <div className="lp-sensor-ports-row">
              <div className="lp-sensor-port-unit">
                <span className="sensor-arrow">▼</span>
                <span className="sensor-label">R.01</span>
                <div className="sensor-socket">
                  <span className="sensor-core" />
                </div>
              </div>
              <div className="lp-sensor-port-unit">
                <span className="sensor-arrow">▼</span>
                <span className="sensor-label">R.02</span>
                <div className="sensor-socket">
                  <span className="sensor-core" />
                </div>
              </div>
              <div className="lp-sensor-port-unit">
                <span className="sensor-arrow">▼</span>
                <span className="sensor-label">R.03</span>
                <div className="sensor-socket">
                  <span className="sensor-core" />
                </div>
              </div>
            </div>
          </div>

          {/* Top-Right Screw Rivets & Barcode Motif */}
          <div className="lp-pcb-hardware-accents">
            <div className="lp-screw-rivets">
              <div className="lp-screw-socket"><span className="lp-screw-slot" /></div>
              <div className="lp-screw-socket"><span className="lp-screw-slot" /></div>
              <div className="lp-screw-socket"><span className="lp-screw-slot" /></div>
            </div>
            <div className="lp-top-barcode">
              <span className="b-bar b-1" />
              <span className="b-bar b-2" />
              <span className="b-bar b-1" />
              <span className="b-bar b-3" />
              <span className="b-bar b-2" />
              <span className="b-bar b-1" />
            </div>
          </div>

          {/* Chamfered Mounting Backplate behind the 3 Right Slots */}
          <div className="lp-right-mounting-plate">
            {/* Top-Left 45° Chamfer Screw Rivet */}
            <div className="chamfer-screw-wrapper">
              <div className="lp-screw-socket"><span className="lp-screw-slot" /></div>
            </div>

            {/* Embossed Structural Bosses above and between slots */}
            <div className="dock-boss boss-top">
              <span className="boss-notch left" />
              <span className="boss-rivet" />
              <span className="boss-notch right" />
            </div>
            <div className="dock-bay-emboss bay-0" />

            <div className="dock-boss boss-mid-1">
              <span className="boss-notch left" />
              <span className="boss-rivet" />
              <span className="boss-notch right" />
            </div>
            <div className="dock-bay-emboss bay-1" />

            <div className="dock-boss boss-mid-2">
              <span className="boss-notch left" />
              <span className="boss-rivet" />
              <span className="boss-notch right" />
            </div>
            <div className="dock-bay-emboss bay-2" />

            {/* Right Margin Laser Perforation Dot Matrix */}
            <div className="lp-laser-dot-matrix">
              {[...Array(48)].map((_, i) => (
                <span key={i} className="laser-dot" />
              ))}
            </div>

            {/* Bottom Test Points & SMD Pad */}
            <div className="dock-test-points">
              <span className="test-pad-circle" />
              <span className="test-pad-circle" />
              <span className="test-pad-circle" />
              <span className="test-pad-rect" />
            </div>
          </div>

          {/* Bottom-Right SMD Power Regulators & Test Points */}
          <div className="lp-bottom-right-hardware">
            <div className="lp-sub-dip-chips">
              <div className="lp-mini-smd-chip">
                <span className="smd-pin" /><span className="smd-pin" /><span className="smd-pin" />
                <div className="smd-chip-core" />
              </div>
              <div className="lp-mini-smd-chip">
                <span className="smd-pin" /><span className="smd-pin" /><span className="smd-pin" />
                <div className="smd-chip-core" />
              </div>
              <div className="lp-mini-smd-chip">
                <span className="smd-pin" /><span className="smd-pin" /><span className="smd-pin" />
                <div className="smd-chip-core" />
              </div>
            </div>
            <div className="lp-sub-vertical-vias">
              <span className="v-via" />
              <span className="v-via" />
              <span className="v-via" />
            </div>
            {/* Bottom PCB Edge Connector Bus Fingers */}
            <div className="lp-bottom-edge-fingers">
              {[...Array(12)].map((_, i) => (
                <span key={i} className="edge-finger" />
              ))}
            </div>
          </div>
        </div>

        {/* ===================================================================
            MAIN 3-COLUMN INTERACTIVE HARDWARE ARENA WITH DYNAMIC CONDUITS
            =================================================================== */}
        <div className="lp-pcb-stage-wrapper">
          {/* -------------------------------------------------------------
              COLUMN 1: Left Stacked Data Input Cards (Raw Traffic & PCAP)
              ------------------------------------------------------------- */}
          <div className="lp-pcb-col-left">
            <AnimatePresence mode="wait">
              <motion.div
                key={`left-cards-stage-${activeStateIdx}`}
                className="lp-cards-stack-wrapper"
                initial={{ opacity: 1 }}
                animate={{ opacity: 1 }}
                exit={{
                  opacity: 1,
                  transition: { duration: 0.95 }
                }}
              >
                {currentState.leftCards.map((card, idx) => (
                  <motion.div
                    key={`${activeStateIdx}-${card.id}`}
                    custom={idx}
                    variants={leftCardMotionVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    className={`lp-source-card lp-source-card-${idx} ${activeStateIdx === idx ? 'card-active' : ''}`}
                    onClick={() => changeStage(idx)}
                  >
                    <div className="lp-source-card-top">
                      <div className="lp-card-icon-pill">
                        <span className="lp-pill-icon">{renderCardBadgeIcon(card.icons[0])}</span>
                        <span className="lp-pill-icon">{renderCardBadgeIcon(card.icons[1])}</span>
                      </div>
                      {/* Status LED: powers off to dark diode when disconnecting */}
                      <div className="lp-source-card-status">
                        <motion.span
                          variants={ledMotionVariants}
                          className={`lp-orange-status-led ${activeStateIdx === idx ? 'pulsing' : 'dim'}`}
                        />
                      </div>
                    </div>

                    {/* Card Body with schematic micro lines - stays visible */}
                    <div className="lp-source-card-body">
                      <div className="lp-schematic-lines">
                        <span className="lp-line-row row-full" />
                        <span className="lp-line-row row-75" />
                        <span className="lp-line-row row-50" />
                      </div>
                    </div>

                    {/* Card Footer: Text powers off to unlit phosphor screen */}
                    <div className="lp-source-card-footer">
                      <motion.div variants={textPowerVariants} className="lp-source-label-wrap">
                        <span className="lp-source-card-title">{card.title}</span>
                        <span className="lp-source-card-metric">{card.sub}</span>
                      </motion.div>
                    </div>
                  </motion.div>
                ))}
              </motion.div>
            </AnimatePresence>
          </div>

          {/* -------------------------------------------------------------
              LEFT CONDUIT: Dynamic 45° Bus Traces with Ladder Rungs
              Orange pulse flows from the ACTIVE CARD into Center Computer!
              ------------------------------------------------------------- */}
          <div className={`lp-pcb-conduit-left ${isSignalsStopped ? 'signals-stopped' : ''}`} aria-hidden="true">
            <svg className="lp-conduit-svg" viewBox="0 0 120 380" fill="none" preserveAspectRatio="none">
              <defs>
                <filter id="milledShadowLeft" x="-10%" y="-10%" width="120%" height="120%">
                  <feDropShadow dx="0" dy="1" stdDeviation="1" floodColor="#000000" floodOpacity="0.2" />
                </filter>
                {/* Smooth Fade Gradient along Left Conduit: Entry fade-in (0-25%), bright core (25-70%), exit fade-out (70-100%) */}
                <linearGradient id="lp-flow-fade-left" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="120" y2="0">
                  <stop offset="0%" className="lp-grad-stop-orange" stopOpacity="0.05" />
                  <stop offset="22%" className="lp-grad-stop-orange" stopOpacity="0.9" />
                  <stop offset="60%" className="lp-grad-stop-orange" stopOpacity="1" />
                  <stop offset="85%" className="lp-grad-stop-orange" stopOpacity="0.45" />
                  <stop offset="100%" className="lp-grad-stop-orange" stopOpacity="0.05" />
                </linearGradient>
                <linearGradient id="lp-bed-fade-left" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="120" y2="0">
                  <stop offset="0%" className="lp-grad-stop-orange" stopOpacity="0.04" />
                  <stop offset="25%" className="lp-grad-stop-orange" stopOpacity="0.22" />
                  <stop offset="60%" className="lp-grad-stop-orange" stopOpacity="0.25" />
                  <stop offset="85%" className="lp-grad-stop-orange" stopOpacity="0.1" />
                  <stop offset="100%" className="lp-grad-stop-orange" stopOpacity="0.02" />
                </linearGradient>
              </defs>

              {/* Milled Recessed Channel Backgrounds (3 separate unmerged channels) */}
              <path d="M 0 58 L 24 58 L 88 154 L 120 154" className="lp-milled-channel" />
              <path d="M 0 190 L 120 190" className="lp-milled-channel" />
              <path d="M 0 322 L 24 322 L 88 226 L 120 226" className="lp-milled-channel" />

              {/* Ladder Rungs Crossbars across tracks */}
              <path d="M 0 58 L 24 58 L 88 154 L 120 154" className="lp-ladder-rungs" />
              <path d="M 0 190 L 120 190" className="lp-ladder-rungs" />
              <path d="M 0 322 L 24 322 L 88 226 L 120 226" className="lp-ladder-rungs" />

              {/* Permanent etched grey double-rail tracks */}
              {/* Card 0 to Center (top channel) */}
              <path d="M 0 53.5 L 22 53.5 L 86 149.5 L 120 149.5" className="lp-rail-track" />
              <path d="M 0 62.5 L 26 62.5 L 90 158.5 L 120 158.5" className="lp-rail-track" />

              {/* Card 1 to Center (middle channel) */}
              <path d="M 0 185.5 L 120 185.5" className="lp-rail-track" />
              <path d="M 0 194.5 L 120 194.5" className="lp-rail-track" />

              {/* Card 2 to Center (bottom channel) */}
              <path d="M 0 317.5 L 26 317.5 L 90 221.5 L 120 221.5" className="lp-rail-track" />
              <path d="M 0 326.5 L 22 326.5 L 86 230.5 L 120 230.5" className="lp-rail-track" />

              {/* Solder Via Pads */}
              <circle cx="24" cy="58" r="3.5" className="lp-via-pad" />
              <circle cx="24" cy="322" r="3.5" className="lp-via-pad" />
              <circle cx="104" cy="154" r="4" className="lp-via-pad" />
              <circle cx="104" cy="154" r="1.5" fill="#11141a" />
              <circle cx="104" cy="190" r="4" className="lp-via-pad" />
              <circle cx="104" cy="190" r="1.5" fill="#11141a" />
              <circle cx="104" cy="226" r="4" className="lp-via-pad" />
              <circle cx="104" cy="226" r="1.5" fill="#11141a" />

              {/* LEFT CONDUIT: Multiple lines active simultaneously with smooth fade */}
              {/* Branch 0 (Top Card) */}
              <path
                d="M 0 58 L 24 58 L 88 154 L 120 154"
                stroke="url(#lp-flow-fade-left)"
                className={`lp-flow-dots ${activeStateIdx === 0 ? 'is-active' : 'is-faded'}`}
              />
              <g className={`lp-trace-flow-group ${activeStateIdx !== 0 ? 'is-active' : 'is-faded'}`}>
                <path d="M 0 58 L 24 58 L 88 154 L 120 154" stroke="url(#lp-bed-fade-left)" className="lp-flow-channel-bed" />
                <path d="M 0 58 L 24 58 L 88 154 L 120 154" stroke="url(#lp-flow-fade-left)" className="lp-flow-signal-tail" />
                <path d="M 0 58 L 24 58 L 88 154 L 120 154" stroke="url(#lp-flow-fade-left)" className="lp-flow-signal-packet" />
              </g>

              {/* Branch 1 (Middle Card) */}
              <path
                d="M 0 190 L 120 190"
                stroke="url(#lp-flow-fade-left)"
                className={`lp-flow-dots ${activeStateIdx === 1 ? 'is-active' : 'is-faded'}`}
              />
              <g className={`lp-trace-flow-group ${activeStateIdx !== 1 ? 'is-active' : 'is-faded'}`}>
                <path d="M 0 190 L 120 190" stroke="url(#lp-bed-fade-left)" className="lp-flow-channel-bed" />
                <path d="M 0 190 L 120 190" stroke="url(#lp-flow-fade-left)" className="lp-flow-signal-tail" />
                <path d="M 0 190 L 120 190" stroke="url(#lp-flow-fade-left)" className="lp-flow-signal-packet" />
              </g>

              {/* Branch 2 (Bottom Card) */}
              <path
                d="M 0 322 L 24 322 L 88 226 L 120 226"
                stroke="url(#lp-flow-fade-left)"
                className={`lp-flow-dots ${activeStateIdx === 2 ? 'is-active' : 'is-faded'}`}
              />
              <g className={`lp-trace-flow-group ${activeStateIdx !== 2 ? 'is-active' : 'is-faded'}`}>
                <path d="M 0 322 L 24 322 L 88 226 L 120 226" stroke="url(#lp-bed-fade-left)" className="lp-flow-channel-bed" />
                <path d="M 0 322 L 24 322 L 88 226 L 120 226" stroke="url(#lp-flow-fade-left)" className="lp-flow-signal-tail" />
                <path d="M 0 322 L 24 322 L 88 226 L 120 226" stroke="url(#lp-flow-fade-left)" className="lp-flow-signal-packet" />
              </g>
            </svg>
          </div>

          {/* -------------------------------------------------------------
              COLUMN 2: Center "SecureMail AI Engine" + Real-Time Telemetry Ticket
              ------------------------------------------------------------- */}
          <div className="lp-pcb-col-center">
            {/* Top Cooling Hardware: 5 micro ticks + 5 Stamped Cooling Slots */}
            <div className="lp-center-cooling-header" aria-hidden="true">
              <div className="lp-micro-ticks-group">
                <span className="micro-tick" />
                <span className="micro-tick" />
                <span className="micro-tick" />
                <span className="micro-tick" />
                <span className="micro-tick" />
              </div>
              <div className="lp-center-cooling-vents">
                <span className="vent-slot" />
                <span className="vent-slot" />
                <span className="vent-slot" />
                <span className="vent-slot" />
                <span className="vent-slot" />
              </div>
            </div>

            {/* Sunken Beveled Socket Frame around the card */}
            <div className="lp-hero-socket-frame">
              {/* Radiating connector pins on left and right borders of socket */}
              <div className="lp-socket-flange-pins left-flange">
                <span className="flange-pin" />
                <span className="flange-pin" />
                <span className="flange-pin" />
              </div>
              <div className="lp-socket-flange-pins right-flange">
                <span className="flange-pin" />
                <span className="flange-pin" />
                <span className="flange-pin" />
              </div>

              <div className="lp-hero-computer-card">
                {/* Top Accents: 3 vertical micro-slots on left + Shield badge on right */}
                <div className="lp-hero-card-header">
                  <div className="lp-hero-micro-slots">
                    <span className="hero-micro-slot" />
                    <span className="hero-micro-slot" />
                    <span className="hero-micro-slot" />
                  </div>
                  <div className="lp-hero-glyph">
                    <div className="lp-diamond-badge">
                      <ShieldCheck size={14} className="lp-glyph-icon" />
                    </div>
                  </div>
                </div>

                {/* Center Card Content: Eyebrow + Title + Subcopy in unified left-aligned group with smooth fade */}
                <div className="lp-hero-card-content">
                  <AnimatePresence mode="wait">
                    <motion.div
                      key={`hub-text-${activeStateIdx}`}
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.22 }}
                    >
                      {/* Eyebrow Label */}
                      <div className="lp-engine-eyebrow">
                        {currentState.hubEyebrow}
                      </div>

                      {/* Main Heading: SecureMail AI Engine */}
                      <h3 className="lp-hero-card-title">
                        SECUREMAIL<br />AI ENGINE
                      </h3>

                      {/* Monospace Subcopy explaining the active phase */}
                      <p className="lp-hero-card-subcopy">
                        {currentState.hubSubcopy}
                      </p>
                    </motion.div>
                  </AnimatePresence>
                </div>

                {/* Carousel Control Bar with arrows & micro-dot buttons */}
                <div className="lp-hero-carousel-pill">
                  <button
                    type="button"
                    className="lp-pill-chevron-btn"
                    onClick={handlePrev}
                    aria-label="Previous pipeline phase"
                  >
                    <ChevronLeft size={13} />
                    <span className="btn-micro-dots">··</span>
                  </button>

                  <AnimatePresence mode="wait">
                    <motion.span
                      key={currentState.themeTag}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      transition={{ duration: 0.2 }}
                      className="lp-pill-label-text"
                    >
                      {currentState.themeTag}
                    </motion.span>
                  </AnimatePresence>

                  <button
                    type="button"
                    className="lp-pill-chevron-btn"
                    onClick={handleNext}
                    aria-label="Next pipeline phase"
                  >
                    <span className="btn-micro-dots">··</span>
                    <ChevronRight size={13} />
                  </button>
                </div>
              </div>
            </div>

            {/* Extruded Dispenser Slot & Sleek Slide-Out Telemetry Card */}
            <div className="lp-ticket-dispenser-wrap">
              <div className="lp-ticket-slot-mouth">
                <span className="lp-mouth-inner-shadow" />
              </div>

              {/* Sleek Slide-Out Telemetry Card with Smooth Dispense Motion */}
              <AnimatePresence mode="wait">
                <motion.div
                  key={`telemetry-card-${activeStateIdx}`}
                  className="lp-telemetry-output-card"
                  initial={{ y: -24, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  exit={{ y: 16, opacity: 0 }}
                  transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                  whileHover={{ y: -3, transition: { duration: 0.15 } }}
                  onClick={() => onLaunchApp && onLaunchApp()}
                  role="button"
                  tabIndex={0}
                  title="Launch Cockpit"
                >
                  <div className="lp-telemetry-card-inner">
                    <div className="lp-telemetry-card-eyebrow">{currentState.ticket.eyebrow}</div>
                    <div className="lp-telemetry-card-headline">{currentState.ticket.headline}</div>
                    <div className="lp-telemetry-action-row">
                      <span className="lp-telemetry-action-text">{currentState.ticket.code}</span>
                      <span className="lp-telemetry-action-arrow">→</span>
                    </div>
                  </div>
                </motion.div>
              </AnimatePresence>
            </div>
          </div>

          {/* -------------------------------------------------------------
              RIGHT CONDUIT: Dynamic 45° Bus Traces with Ladder Rungs
              ORANGE SIGNAL ONLY FLOWS TO WHERE THE ACTIVE CARD COMES!
              - If Slot 0 is active: Flows ONLY along the top 45° branch!
              - If Slot 1 is active: Flows ONLY along the middle horizontal branch!
              - If Slot 2 is active: Flows ONLY along the bottom 45° branch!
              ------------------------------------------------------------- */}
          <div className={`lp-pcb-conduit-right ${isSignalsStopped ? 'signals-stopped' : ''}`} aria-hidden="true">
            <svg className="lp-conduit-svg" viewBox="0 0 120 380" fill="none" preserveAspectRatio="none">
              <defs>
                <filter id="milledShadowRight" x="-10%" y="-10%" width="120%" height="120%">
                  <feDropShadow dx="0" dy="1" stdDeviation="1" floodColor="#000000" floodOpacity="0.2" />
                </filter>
                {/* Smooth Fade Gradient along Right Conduit: Entry fade-in (0-25%), bright core (25-70%), exit fade-out (70-100%) */}
                <linearGradient id="lp-flow-fade-right" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="120" y2="0">
                  <stop offset="0%" className="lp-grad-stop-orange" stopOpacity="0.05" />
                  <stop offset="22%" className="lp-grad-stop-orange" stopOpacity="0.9" />
                  <stop offset="60%" className="lp-grad-stop-orange" stopOpacity="1" />
                  <stop offset="85%" className="lp-grad-stop-orange" stopOpacity="0.45" />
                  <stop offset="100%" className="lp-grad-stop-orange" stopOpacity="0.05" />
                </linearGradient>
                <linearGradient id="lp-bed-fade-right" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="120" y2="0">
                  <stop offset="0%" className="lp-grad-stop-orange" stopOpacity="0.04" />
                  <stop offset="25%" className="lp-grad-stop-orange" stopOpacity="0.22" />
                  <stop offset="60%" className="lp-grad-stop-orange" stopOpacity="0.25" />
                  <stop offset="85%" className="lp-grad-stop-orange" stopOpacity="0.1" />
                  <stop offset="100%" className="lp-grad-stop-orange" stopOpacity="0.02" />
                </linearGradient>
              </defs>

              {/* Milled Recessed Channel Backgrounds (3 separate unmerged channels) */}
              <path d="M 0 154 L 32 154 L 96 58 L 120 58" className="lp-milled-channel" />
              <path d="M 0 190 L 120 190" className="lp-milled-channel" />
              <path d="M 0 226 L 32 226 L 96 322 L 120 322" className="lp-milled-channel" />

              {/* Ladder Rungs Crossbars across tracks */}
              <path d="M 0 154 L 32 154 L 96 58 L 120 58" className="lp-ladder-rungs" />
              <path d="M 0 190 L 120 190" className="lp-ladder-rungs" />
              <path d="M 0 226 L 32 226 L 96 322 L 120 322" className="lp-ladder-rungs" />

              {/* Permanent etched grey double-rail tracks */}
              {/* Center to Slot 0 (top channel) */}
              <path d="M 0 149.5 L 30 149.5 L 94 53.5 L 120 53.5" className="lp-rail-track" />
              <path d="M 0 158.5 L 34 158.5 L 98 62.5 L 120 62.5" className="lp-rail-track" />

              {/* Center to Slot 1 (middle channel) */}
              <path d="M 0 185.5 L 120 185.5" className="lp-rail-track" />
              <path d="M 0 194.5 L 120 194.5" className="lp-rail-track" />

              {/* Center to Slot 2 (bottom channel) */}
              <path d="M 0 221.5 L 34 221.5 L 98 317.5 L 120 317.5" className="lp-rail-track" />
              <path d="M 0 230.5 L 30 230.5 L 94 326.5 L 120 326.5" className="lp-rail-track" />

              {/* Solder Via Pads (3 stacked circular pads at left edge + elbow pads, matching photo) */}
              <circle cx="16" cy="154" r="4" className="lp-via-pad" />
              <circle cx="16" cy="154" r="1.5" fill="#11141a" />
              <circle cx="16" cy="190" r="4" className="lp-via-pad" />
              <circle cx="16" cy="190" r="1.5" fill="#11141a" />
              <circle cx="16" cy="226" r="4" className="lp-via-pad" />
              <circle cx="16" cy="226" r="1.5" fill="#11141a" />

              <circle cx="96" cy="58" r="3.5" className="lp-via-pad" />
              <circle cx="96" cy="322" r="3.5" className="lp-via-pad" />

              {/* RIGHT CONDUIT: Strictly ONLY ONE line active at any time, with smooth cross-fade */}
              {/* Branch 0 (Top Shelf) */}
              <path
                d="M 0 154 L 32 154 L 96 58 L 120 58"
                stroke="url(#lp-flow-fade-right)"
                className={`lp-flow-dots ${activeStateIdx === 0 ? 'is-active' : 'is-faded'}`}
              />
              <g className={`lp-trace-flow-group ${activeStateIdx === 0 ? 'is-active' : 'is-faded'}`}>
                <path d="M 0 154 L 32 154 L 96 58 L 120 58" stroke="url(#lp-bed-fade-right)" className="lp-flow-channel-bed" />
                <path d="M 0 154 L 32 154 L 96 58 L 120 58" stroke="url(#lp-flow-fade-right)" className="lp-flow-signal-tail" />
                <path d="M 0 154 L 32 154 L 96 58 L 120 58" stroke="url(#lp-flow-fade-right)" className="lp-flow-signal-packet" />
              </g>

              {/* Branch 1 (Middle Shelf) */}
              <path
                d="M 0 190 L 120 190"
                stroke="url(#lp-flow-fade-right)"
                className={`lp-flow-dots ${activeStateIdx === 1 ? 'is-active' : 'is-faded'}`}
              />
              <g className={`lp-trace-flow-group ${activeStateIdx === 1 ? 'is-active' : 'is-faded'}`}>
                <path d="M 0 190 L 120 190" stroke="url(#lp-bed-fade-right)" className="lp-flow-channel-bed" />
                <path d="M 0 190 L 120 190" stroke="url(#lp-flow-fade-right)" className="lp-flow-signal-tail" />
                <path d="M 0 190 L 120 190" stroke="url(#lp-flow-fade-right)" className="lp-flow-signal-packet" />
              </g>

              {/* Branch 2 (Bottom Shelf) */}
              <path
                d="M 0 226 L 32 226 L 96 322 L 120 322"
                stroke="url(#lp-flow-fade-right)"
                className={`lp-flow-dots ${activeStateIdx === 2 ? 'is-active' : 'is-faded'}`}
              />
              <g className={`lp-trace-flow-group ${activeStateIdx === 2 ? 'is-active' : 'is-faded'}`}>
                <path d="M 0 226 L 32 226 L 96 322 L 120 322" stroke="url(#lp-bed-fade-right)" className="lp-flow-channel-bed" />
                <path d="M 0 226 L 32 226 L 96 322 L 120 322" stroke="url(#lp-flow-fade-right)" className="lp-flow-signal-tail" />
                <path d="M 0 226 L 32 226 L 96 322 L 120 322" stroke="url(#lp-flow-fade-right)" className="lp-flow-signal-packet" />
              </g>
            </svg>
          </div>

          {/* -------------------------------------------------------------
              COLUMN 3: Right Expansion Cartridge Slots (SecureMail Outputs)
              - Active slot displays the FULL EXPANDED CARD with title, sub,
                black icon pill, and ORANGE status LED on shelf lip!
              - Inactive slots display the sleek COLLAPSED WHITE BAR with
                just two black dots (··) on the shelf bracket!
              - Under each shelf: Gold comb connector pins plugging into socket!
              ------------------------------------------------------------- */}
          <div className="lp-pcb-col-right">
            <div className="lp-cartridges-stack-wrapper">
              {RIGHT_CARTRIDGES.map((cartridge, idx) => {
                const isCurrentActive = displayedRightIdx === idx

                return (
                  <div
                    key={cartridge.id}
                    className={`lp-cartridge-slot-container ${isCurrentActive ? 'slot-expanded' : 'slot-collapsed'}`}
                    onClick={() => changeStage(idx)}
                    role="button"
                    tabIndex={0}
                  >
                    {/* Card Pocket: Card is slotted BEHIND the front socket bar */}
                    <div className="lp-cartridge-card-pocket">
                      <AnimatePresence mode="wait">
                        {isCurrentActive && (
                          <motion.div
                            key={`active-cartridge-${idx}`}
                            variants={rightCardMotionVariants}
                            initial="initial"
                            animate="animate"
                            exit="exit"
                            style={{ width: '100%' }}
                          >
                            <div className="lp-cartridge-expanded-body">
                              <div className="lp-cartridge-content-row">
                                <div className="lp-cartridge-text-block">
                                  <motion.span variants={textPowerVariants} className="lp-cartridge-title">
                                    {cartridge.title}
                                  </motion.span>
                                  <motion.span variants={textPowerVariants} className="lp-cartridge-subline">
                                    {cartridge.sub}
                                  </motion.span>
                                </div>
                                <div className="lp-cartridge-black-pill">
                                  {cartridge.icons.map((ic, i) => (
                                    <span key={i} className="pill-mini-icon">{renderCardBadgeIcon(ic)}</span>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>

                    {/* Permanent 3D Front Socket Bar (in front of card, never moves, not attached!) */}
                    <div className={`lp-front-socket-bar ${isCurrentActive ? 'bar-active' : ''}`}>
                      <div className="lp-cartridge-status-dots">
                        <span className={isCurrentActive ? 'cartridge-led-orange' : 'cartridge-dot-dark'} />
                        <span className="cartridge-dot-dark" />
                      </div>
                    </div>

                    {/* Gold Comb Connector Pins beneath front bar */}
                    <div className="lp-shelf-connector-pins">
                      <span className="comb-pin" />
                      <span className="comb-pin" />
                      <span className="comb-pin" />
                      <span className="comb-pin" />
                      <span className="comb-pin" />
                      <span className="comb-pin" />
                      <span className="comb-pin" />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
