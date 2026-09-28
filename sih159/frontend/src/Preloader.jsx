import React, { useState, useEffect, useRef, useCallback } from 'react'
import HalftoneBloom from './HalftoneBloom.jsx'
import FuzzyText from './FuzzyText.jsx'
import { Shield, Sparkles, ArrowRight, Zap } from 'lucide-react'
import './preloader.css'

const DURATION_MS = 5000
const EXIT_TRANSITION_MS = 400

const BOOT_STAGES = [
  { threshold: 0, text: "[01/05] INITIALIZING NEURAL CRYPTOGRAPHIC SCANNER..." },
  { threshold: 20, text: "[02/05] CALIBRATING NIST FIPS 203 ML-KEM QUANTUM RADAR..." },
  { threshold: 45, text: "[03/05] AUDITING MTA-STS & DANE (RFC 8461 / RFC 7672)..." },
  { threshold: 72, text: "[04/05] DETECTING STARTTLS STRIPPING & MITM ATTACK SURFACES..." },
  { threshold: 92, text: "[05/05] CRYPTOGRAPHIC POSTURE VERIFIED · READY" },
]

export default function Preloader({ theme = 'dark', onComplete }) {
  const [progress, setProgress] = useState(0)
  const [stageText, setStageText] = useState(BOOT_STAGES[0].text)
  const [isExiting, setIsExiting] = useState(false)
  
  const startTimeRef = useRef(null)
  const hasFinishedRef = useRef(false)
  const rafRef = useRef(null)

  const isLight = theme === 'light'

  // Finish and dismiss the preloader
  const finish = useCallback(() => {
    if (hasFinishedRef.current) return
    hasFinishedRef.current = true
    setIsExiting(true)
    setTimeout(() => {
      if (onComplete) onComplete()
    }, EXIT_TRANSITION_MS)
  }, [onComplete])

  useEffect(() => {
    startTimeRef.current = performance.now()

    const step = (now) => {
      if (hasFinishedRef.current) return

      const elapsed = now - startTimeRef.current
      const rawPct = Math.min(100, (elapsed / DURATION_MS) * 100)
      const currentPct = Math.floor(rawPct)
      
      setProgress(currentPct)

      // Update current telemetry diagnostic message
      for (let i = BOOT_STAGES.length - 1; i >= 0; i--) {
        if (currentPct >= BOOT_STAGES[i].threshold) {
          setStageText(BOOT_STAGES[i].text)
          break
        }
      }

      if (elapsed >= DURATION_MS - EXIT_TRANSITION_MS && !isExiting) {
        setIsExiting(true)
      }

      if (elapsed >= DURATION_MS) {
        finish()
        return
      }

      rafRef.current = requestAnimationFrame(step)
    }

    rafRef.current = requestAnimationFrame(step)

    // Keyboard shortcut to skip (Escape or Space)
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' || e.key === ' ' || e.key === 'Enter') {
        finish()
      }
    }
    window.addEventListener('keydown', handleKeyDown)

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [finish, isExiting])

  // Halftone Bloom Theme Configuration
  const bloomConfig = isLight
    ? {
        background: "#ffffff",
        color1: "#742ec5", // Signature royal purple of SecureMailScope light mode
        color2: "#2563eb", // Deep cobalt blue
        speed: 45,
        size: 190,
        dotSize: 6.5,
        hover: 180,
      }
    : {
        background: "#07090c", // Exact void background of SecureMailScope dark mode
        color1: "#ccff00", // Signature neon chartreuse
        color2: "#00f0ff", // Cyber cyan
        speed: 50,
        size: 200,
        dotSize: 6,
        hover: 200,
      }

  // Text Noise Theme Configuration
  const fuzzyConfig = isLight
    ? {
        color: "#0f172a",
        gradientEnd: "#742ec5",
        useGradient: true,
        baseIntensity: 2.0,
        hoverIntensity: 5.0,
      }
    : {
        color: "#ffffff",
        gradientEnd: "#ccff00",
        useGradient: true,
        baseIntensity: 2.2,
        hoverIntensity: 5.5,
      }

  return (
    <div
      className={`sms-preloader-root ${isLight ? 'theme-light' : 'theme-dark'} ${isExiting ? 'phase-exit' : ''}`}
      role="progressbar"
      aria-valuenow={progress}
      aria-valuemin="0"
      aria-valuemax="100"
      aria-label="SecureMailScope Loading Sequence"
    >
      {/* 1. Halftone Bloom Shader Canvas Background */}
      <div className="sms-preloader-bg-canvas" aria-hidden="true">
        <HalftoneBloom
          background={bloomConfig.background}
          color1={bloomConfig.color1}
          color2={bloomConfig.color2}
          speed={bloomConfig.speed}
          size={bloomConfig.size}
          dotSize={bloomConfig.dotSize}
          hover={bloomConfig.hover}
        />
      </div>

      {/* 2. Theme-matched Vignette Depth Overlay */}
      <div className="sms-preloader-vignette" aria-hidden="true" />

      {/* 3. Skip Action Button */}
      <button
        className="sms-preloader-skip-btn"
        onClick={finish}
        title="Enter SecureMailScope immediately [Esc]"
      >
        <span>ENTER</span>
        <ArrowRight size={13} />
      </button>

      {/* 4. Central Content: Noise Text + Telemetry Bar */}
      <div className="sms-preloader-content">
        {/* Security Enclave Badge */}
        <div className="sms-preloader-badge">
          <span className="sms-preloader-led" />
          <Shield size={12} strokeWidth={2.4} />
          <span>CRYPTOGRAPHIC AUDIT SUITE v2.4</span>
        </div>

        {/* Text Noise (FuzzyText) Logo */}
        <div className="sms-preloader-fuzzy-wrap">
          <FuzzyText
            text="SecureMailScope"
            font={{
              fontSize: "clamp(34px, 6.8vw, 86px)",
              textAlign: "center",
              fontFamily: "'Syne', 'Inter', system-ui, sans-serif",
              fontWeight: 700,
              lineHeight: "1.08em",
              letterSpacing: "-0.01em",
            }}
            color={fuzzyConfig.color}
            gradientEnd={fuzzyConfig.gradientEnd}
            useGradient={fuzzyConfig.useGradient}
            baseIntensity={fuzzyConfig.baseIntensity}
            hoverIntensity={fuzzyConfig.hoverIntensity}
            glitchMode={true}
            glitchInterval={1500}
            glitchDuration={200}
            fuzzRange={24}
          />
        </div>

        {/* Subtitle */}
        <p className="sms-preloader-tagline">
          Zero-Touch Wire Telemetry &bull; Post-Quantum Cryptographic Posture &bull; MTA-STS Defense
        </p>

        {/* Telemetry Progress Card */}
        <div className="sms-preloader-hud-card">
          <div className="sms-preloader-telemetry-row">
            <span className="sms-preloader-telemetry-text">{stageText}</span>
            <span className="sms-preloader-percent">{String(progress).padStart(2, '0')}%</span>
          </div>

          {/* Progress Bar */}
          <div className="sms-preloader-progress-track">
            <div
              className="sms-preloader-progress-fill"
              style={{ width: `${progress}%` }}
            />
          </div>

          <div className="sms-preloader-hud-footer">
            <span>BUFFER: {(Math.max(0, (DURATION_MS - (progress / 100) * DURATION_MS)) / 1000).toFixed(1)}S</span>
            <span>SECURE PROTOCOL ENGAGED</span>
          </div>
        </div>

        {/* Protocol Standard Badges */}
        <div className="sms-preloader-chips" aria-hidden="true">
          <span className="sms-preloader-chip">RFC 3207 STARTTLS</span>
          <span className="sms-preloader-chip">RFC 8461 MTA-STS</span>
          <span className="sms-preloader-chip">NIST FIPS 203 ML-KEM</span>
          <span className="sms-preloader-chip">PCI-DSS 4.0</span>
        </div>
      </div>
    </div>
  )
}
