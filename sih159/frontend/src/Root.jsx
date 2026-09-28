import React, { useState, useEffect, useRef } from 'react'
import App from './App.jsx'
import LandingPage from './LandingPage.jsx'
import ErrorBoundary from './ErrorBoundary.jsx'

export default function Root() {
  // Theme state synchronized across both landing page and main app
  const [theme, setTheme] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('sms_landing_theme')
      if (saved) return saved
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark'
      }
      return 'light'
    }
    return 'light'
  })

  // Synchronize <html> and <body> styles & classes immediately to eliminate white flash
  useEffect(() => {
    const isDark = theme === 'dark'
    document.documentElement.classList.remove('theme-light', 'theme-dark')
    document.documentElement.classList.add(isDark ? 'theme-dark' : 'theme-light')
    document.body.classList.remove('theme-light', 'theme-dark')
    document.body.classList.add(isDark ? 'theme-dark' : 'theme-light')
    
    document.documentElement.style.backgroundColor = isDark ? '#07090c' : '#ffffff'
    document.body.style.backgroundColor = isDark ? '#07090c' : '#ffffff'
    document.documentElement.style.colorScheme = isDark ? 'dark' : 'light'
  }, [theme])

  const toggleTheme = () => {
    const nextTheme = theme === 'light' ? 'dark' : 'light'
    setTheme(nextTheme)
    if (typeof window !== 'undefined') {
      localStorage.setItem('sms_landing_theme', nextTheme)
    }
  }

  // Check initial route from hash or URL query
  const getInitialView = () => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash
      const params = new URLSearchParams(window.location.search)
      if (hash === '#/app' || params.get('view') === 'app' || params.get('app') === 'true') {
        return 'app'
      }
    }
    return 'landing'
  }

  const [currentView, setCurrentView] = useState(getInitialView)
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [transitionPhase, setTransitionPhase] = useState('idle') // 'idle' | 'covering' | 'uncovering'
  const isTransitioningRef = useRef(false)

  // Smooth cinematic portal transition between Landing Page and Main Application
  const transitionTo = (targetView) => {
    if (isTransitioningRef.current || currentView === targetView) return
    isTransitioningRef.current = true
    setIsTransitioning(true)
    setTransitionPhase('covering')

    // Step 1: Smooth theme-matched curtain rises (200ms)
    setTimeout(() => {
      if (targetView === 'app') {
        window.location.hash = '#/app'
      } else {
        window.location.hash = '#/'
      }
      setCurrentView(targetView)
      window.scrollTo({ top: 0, behavior: 'instant' })
      setTransitionPhase('uncovering')

      // Step 2: Smooth curtain unveils with view entrance animation (280ms)
      setTimeout(() => {
        setIsTransitioning(false)
        setTransitionPhase('idle')
        isTransitioningRef.current = false
      }, 280)
    }, 200)
  }

  const launchApp = () => {
    transitionTo('app')
  }

  const returnToLanding = () => {
    transitionTo('landing')
  }

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash
      if (hash === '#/app' && currentView !== 'app' && !isTransitioningRef.current) {
        transitionTo('app')
      } else if ((hash === '' || hash === '#/' || hash === '#') && currentView !== 'landing' && !isTransitioningRef.current) {
        transitionTo('landing')
      }
    }

    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [currentView])

  return (
    <div className={`root-view-wrapper ${theme === 'light' ? 'theme-light' : 'theme-dark'}`}>
      {/* Smooth Cinematic View Transition Curtain */}
      <div 
        className={`root-transition-curtain ${theme === 'light' ? 'theme-light' : 'theme-dark'} phase-${transitionPhase} ${isTransitioning ? 'active' : ''}`}
        aria-hidden="true"
      >
        <div className="root-transition-glow" />
        <div className="root-transition-beam" />
      </div>

      {/* Active View Container with Seamless Entry Animation & Error Boundary */}
      <div key={currentView} className="root-active-view-container view-enter-smooth">
        <ErrorBoundary>
          {currentView === 'app' ? (
            <div style={{ position: 'relative' }}>
              {/* Unobtrusive Floating Pill to return to Landing Page */}
              <button
                className={`lp-return-pill ${theme === 'light' ? 'theme-light' : 'theme-dark'}`}
                onClick={returnToLanding}
                title="Return to SecureMailScope Overview & Architecture"
              >
                <span>←</span>
                <span>Landing Page</span>
              </button>

              {/* The transformed product application console */}
              <App theme={theme} toggleTheme={toggleTheme} />
            </div>
          ) : (
            <LandingPage onLaunchApp={launchApp} theme={theme} toggleTheme={toggleTheme} />
          )}
        </ErrorBoundary>
      </div>
    </div>
  )
}
