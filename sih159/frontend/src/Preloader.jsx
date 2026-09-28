import React, { useState, useEffect, useRef, useCallback } from 'react'
import HalftoneBloom from './HalftoneBloom.jsx'
import FuzzyText from './FuzzyText.jsx'
import './preloader.css'

const DURATION_MS = 5000
const EXIT_TRANSITION_MS = 300

export default function Preloader({ theme = 'dark', onComplete }) {
  const [isExiting, setIsExiting] = useState(false)
  
  const startTimeRef = useRef(null)
  const hasFinishedRef = useRef(false)
  const rafRef = useRef(null)

  const isLight = theme === 'light'

  // Finish and dismiss the preloader
  const finish = useCallback(() => {
    if (hasFinishedRef.current) return
    hasFinishedRef.current = true
    
    // Immediately set exit state — this:
    // 1. Adds pointer-events:none via CSS so clicks pass through instantly
    // 2. Removes HalftoneBloom from DOM to stop the GPU shader loop
    setIsExiting(true)

    // Cancel the render loop immediately
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current)
      rafRef.current = null
    }

    // Notify parent after the fade-out animation completes
    setTimeout(() => {
      if (onComplete) onComplete()
    }, EXIT_TRANSITION_MS)
  }, [onComplete])

  useEffect(() => {
    startTimeRef.current = performance.now()

    const step = (now) => {
      if (hasFinishedRef.current) return

      const elapsed = now - startTimeRef.current

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
  }, [finish])

  // Halftone Bloom Theme Configuration
  const bloomConfig = isLight
    ? {
        background: "#ffffff",
        color1: "#742ec5",
        color2: "#2563eb",
        speed: 45,
        size: 190,
        dotSize: 6.5,
        hover: 180,
      }
    : {
        background: "#07090c",
        color1: "#ccff00",
        color2: "#00f0ff",
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
      aria-label="SecureMailScope Loading Sequence"
    >
      {/* 1. Halftone Bloom Shader Canvas — REMOVED on exit to free GPU immediately */}
      {!isExiting && (
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
      )}

      {/* 2. Theme-matched Vignette Depth Overlay */}
      <div className="sms-preloader-vignette" aria-hidden="true" />

      {/* 3. Skip Action Button */}
      {!isExiting && (
        <button
          className="sms-preloader-skip-btn"
          onClick={finish}
          title="Skip intro [Esc]"
        >
          <span>SKIP</span>
        </button>
      )}

      {/* 4. Central Content */}
      <div className="sms-preloader-content">
        {/* Text Noise (FuzzyText) Logo — also removed on exit to stop canvas loop */}
        {!isExiting && (
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
        )}

        {/* Subtitle */}
        <p className="sms-preloader-tagline">
          Zero-Touch Wire Telemetry &bull; Post-Quantum Cryptographic Posture &bull; MTA-STS Defense
        </p>
      </div>
    </div>
  )
}
