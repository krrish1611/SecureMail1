import React, { useRef, useState, useCallback } from 'react'
import pixelMailFrontDark from './assets/pixel_mail_dark.png'
import pixelMailFrontLight from './assets/pixel_mail_light.png'
import pixelMailBackDark from './assets/pixel_mail_back_dark.png'
import pixelMailBackLight from './assets/pixel_mail_back_light.png'
import pixelMailOpenBackDark from './assets/pixel_mail_open_back_dark.png'
import pixelMailOpenBackLight from './assets/pixel_mail_open_back_light.png'
import pixelMailPocketLipDark from './assets/pixel_mail_pocket_lip_dark.png'
import pixelMailPocketLipLight from './assets/pixel_mail_pocket_lip_light.png'
import pixelMailLetterDark from './assets/pixel_mail_letter_dark.png'
import pixelMailLetterLight from './assets/pixel_mail_letter_light.png'

/**
 * AsciiPixelEnvelope
 * 
 * 3D Rotating Pixel Art Mail Envelope Hero CTA with Sci-Fi Texture Pattern:
 * 1. Textured mail envelope body matching dark and light mode themes.
 * 2. Continuous 3D rotation in idle state with front and back faces (no hover changes until click).
 * 3. On click: Rotation locks to front, envelope opens, and themed pixel letter glides upwards.
 * 4. Cinematic portal zoom: Letter zooms forward into the screen to launch the website.
 * 5. 'Get Started' text at the bottom of the mail (no button, pure text).
 */
export default function AsciiPixelEnvelope({ onLaunchApp, theme = 'light' }) {
  const isTransitioningRef = useRef(false)
  
  // Animation states: 'idle' -> 'opening' -> 'zooming'
  const [animState, setAnimState] = useState('idle')

  // Themed textured mail assets matching active dark/light mode
  const isLight = theme === 'light'
  const frontImg = isLight ? pixelMailFrontLight : pixelMailFrontDark
  const backImg = isLight ? pixelMailBackLight : pixelMailBackDark
  const openBackImg = isLight ? pixelMailOpenBackLight : pixelMailOpenBackDark
  const pocketLipImg = isLight ? pixelMailPocketLipLight : pixelMailPocketLipDark
  const letterSrc = isLight ? pixelMailLetterLight : pixelMailLetterDark

  // Reduced motion preference
  const prefersReducedMotion = typeof window !== 'undefined' 
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches

  const handleClick = useCallback(() => {
    if (isTransitioningRef.current) return
    isTransitioningRef.current = true

    if (prefersReducedMotion) {
      if (onLaunchApp) onLaunchApp()
      return
    }

    // Step 1: Open envelope & start letter slide
    setAnimState('opening')

    // Step 2: Letter zooms into the screen towards the website
    setTimeout(() => {
      setAnimState('zooming')
    }, 900)

    // Step 3: Launch website console
    setTimeout(() => {
      if (onLaunchApp) onLaunchApp()
    }, 1350)
  }, [onLaunchApp, prefersReducedMotion])

  return (
    <div 
      className={`lp-floating-envelope-stage ${theme === 'light' ? 'theme-light' : 'theme-dark'} ${animState !== 'idle' ? 'transitioning' : ''}`}
    >
      <div 
        className={`lp-floating-envelope-viewport lp-pixel-envelope-viewport state-${animState}`}
        onClick={handleClick}
        title="Click to Open Mail & Launch SecureMailScope"
      >
        {/* ================================================================= */}
        {/* STATE 1: IDLE 3D ROTATING ENVELOPE (Unchanged by hover)            */}
        {/* ================================================================= */}
        {animState === 'idle' && (
          <div className="lp-pixel-3d-flipper">
            <div className="lp-pixel-3d-spinner">
              {/* Front Face: Themed Textured Mail Front */}
              <div className="lp-pixel-card-face lp-pixel-face-front">
                <img 
                  src={frontImg} 
                  alt="SecureMailScope Textured Mail" 
                  className="lp-pixel-face-img"
                  draggable={false}
                />
                <div className="lp-pixel-mail-get-started on-mail">
                  <span>get started</span>
                  <span className="lp-pixel-mail-arrow">→</span>
                </div>
              </div>

              {/* Back Face: Themed Textured Mail Back */}
              <div className="lp-pixel-card-face lp-pixel-face-back">
                <img 
                  src={backImg} 
                  alt="SecureMailScope Textured Mail Back" 
                  className="lp-pixel-face-img"
                  draggable={false}
                />
                <div className="lp-pixel-mail-get-started on-mail">
                  <span>get started</span>
                  <span className="lp-pixel-mail-arrow">→</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* STATE 2 & 3: OPEN ENVELOPE + THEMED LETTER EMERGES & ZOOMS        */}
        {/* ================================================================= */}
        {animState !== 'idle' && (
          <div className={`lp-pixel-open-rig ${animState}`}>
            {/* Layer 1: Open Back Wall & Upward Pointing Flap */}
            <div className="lp-pixel-layer-back">
              <img 
                src={openBackImg} 
                alt="Open Envelope Back" 
                className="lp-pixel-open-bg-img"
                draggable={false}
              />
            </div>

            {/* Layer 2: Emerging Themed Pixel Art Letter */}
            <div className={`lp-pixel-letter-carriage ${animState}`}>
              <img 
                src={letterSrc} 
                alt="SecureMailScope Clearance Letter" 
                className="lp-pixel-letter-doc"
                draggable={false}
              />
            </div>

            {/* Layer 3: Front Pocket Lip (Letter slides out from behind this!) */}
            <div className={`lp-pixel-layer-pocket ${animState === 'zooming' ? 'fade-out' : ''}`}>
              <img 
                src={pocketLipImg} 
                alt="Front Pocket Lip" 
                className="lp-pixel-pocket-img"
                draggable={false}
              />
            </div>
          </div>
        )}

        {/* Ambient Ground Floating Shadow */}
        <div 
          className={`lp-envelope-floating-shadow lp-pixel-floating-shadow ${animState !== 'idle' ? 'shadow-opening' : ''}`}
          aria-hidden="true"
        />

        {/* Accessible Button Overlay */}
        <button
          type="button"
          className="lp-envelope-accessible-btn"
          onClick={handleClick}
          aria-label="Click to Open Mail and Launch SecureMailScope Console"
        >
          <span className="sr-only">Click to Open Mail & Launch SecureMailScope</span>
        </button>
      </div>
    </div>
  )
}
