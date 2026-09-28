import React, { useEffect, useRef } from 'react'

const parseFontSize = (fontSize) => {
  if (typeof fontSize === "number") return `${fontSize}px`
  if (typeof fontSize === "string" && fontSize.length > 0) return fontSize
  return "88px"
}

const parseLetterSpacing = (letterSpacing) => {
  if (typeof letterSpacing === "number") return letterSpacing
  if (typeof letterSpacing === "string") {
    const parsed = Number.parseFloat(letterSpacing)
    if (!Number.isNaN(parsed)) {
      if (letterSpacing.endsWith("em")) return parsed * 16
      return parsed
    }
  }
  return 0
}

const parseFontWeight = (fontWeight) => {
  if (typeof fontWeight === "number") return fontWeight
  if (typeof fontWeight === "string") {
    const parsed = Number.parseInt(fontWeight, 10)
    if (!Number.isNaN(parsed)) return parsed
  }
  return 700
}

function BaseFuzzyText({
  text = "SecureMailScope",
  font = {
    fontFamily: "'Syne', 'Inter', system-ui, sans-serif",
    fontWeight: 700,
    fontSize: "88px",
    lineHeight: "1.1em",
    letterSpacing: "-0.01em",
    textAlign: "center",
  },
  color = "#ffffff",
  useGradient = false,
  gradientEnd = "#ccff00",
  baseIntensity = 2.2,
  hoverIntensity = 5.5,
  clickEffect = true,
  clickIntensity = 1.2,
  fuzzRange = 26,
  fps = 60,
  enableHover = true,
  glitchMode = true,
  glitchInterval = 1800,
  glitchDuration = 220,
}) {
  const canvasRef = useRef(null)
  const interactionRef = useRef({ hovering: false, clicking: false })
  const clickTimeoutRef = useRef(undefined)

  const handlePointerEnter = () => {
    if (!enableHover) return
    interactionRef.current.hovering = true
  }

  const handlePointerLeave = () => {
    interactionRef.current.hovering = false
  }

  const handlePointerDown = (e) => {
    if (!clickEffect) return
    e.preventDefault()
    interactionRef.current.clicking = true
    clearTimeout(clickTimeoutRef.current)
    clickTimeoutRef.current = setTimeout(() => {
      interactionRef.current.clicking = false
    }, 400)
  }

  useEffect(() => {
    let animationFrameId = 0
    let isCancelled = false
    let glitchTimeoutId = undefined
    let glitchEndTimeoutId = undefined

    const canvas = canvasRef.current
    if (!canvas) return

    interactionRef.current.hovering = false
    interactionRef.current.clicking = false

    const init = async () => {
      const ctx = canvas.getContext("2d")
      if (!ctx) return

      const fontSizeStr = parseFontSize(font.fontSize)
      const fontWeight = parseFontWeight(font.fontWeight)
      const letterSpacing = parseLetterSpacing(font.letterSpacing)
      const computedFontFamily =
        font.fontFamily && font.fontFamily !== "inherit"
          ? String(font.fontFamily)
          : window.getComputedStyle(canvas).fontFamily || "sans-serif"

      const fontString = `${fontWeight} ${fontSizeStr} ${computedFontFamily}`

      try {
        if (document.fonts && document.fonts.load) {
          await document.fonts.load(fontString)
        }
      } catch (err) {
        try {
          await document.fonts?.ready
        } catch (e) {}
      }
      if (isCancelled) return

      let numericFontSize
      if (typeof font.fontSize === "number") {
        numericFontSize = font.fontSize
      } else {
        const temp = document.createElement("span")
        temp.style.fontSize = fontSizeStr
        temp.style.visibility = "hidden"
        temp.style.position = "absolute"
        document.body.appendChild(temp)
        numericFontSize = Number.parseFloat(window.getComputedStyle(temp).fontSize) || 72
        document.body.removeChild(temp)
      }

      const offscreen = document.createElement("canvas")
      const offCtx = offscreen.getContext("2d")
      if (!offCtx) return

      offCtx.font = fontString
      offCtx.textBaseline = "alphabetic"

      let totalWidth = 0
      if (letterSpacing !== 0) {
        for (const char of text) {
          totalWidth += offCtx.measureText(char).width + letterSpacing
        }
        totalWidth -= letterSpacing
      } else {
        totalWidth = offCtx.measureText(text).width
      }

      const metrics = offCtx.measureText(text)
      const actualLeft = metrics.actualBoundingBoxLeft ?? 0
      const actualRight =
        letterSpacing !== 0
          ? totalWidth
          : (metrics.actualBoundingBoxRight ?? metrics.width)
      const actualAscent =
        metrics.actualBoundingBoxAscent ?? numericFontSize
      const actualDescent =
        metrics.actualBoundingBoxDescent ?? numericFontSize * 0.2

      const textBoundingWidth = Math.ceil(
        letterSpacing !== 0 ? totalWidth : actualLeft + actualRight
      )
      const tightHeight = Math.ceil(actualAscent + actualDescent)

      const extraWidthBuffer = 10
      const offscreenWidth = textBoundingWidth + extraWidthBuffer

      offscreen.width = Math.max(1, offscreenWidth)
      offscreen.height = Math.max(1, tightHeight)

      const xOffset = extraWidthBuffer / 2
      offCtx.font = fontString
      offCtx.textBaseline = "alphabetic"

      if (useGradient) {
        const grad = offCtx.createLinearGradient(0, 0, offscreenWidth, 0)
        grad.addColorStop(0, color)
        grad.addColorStop(1, gradientEnd)
        offCtx.fillStyle = grad
      } else {
        offCtx.fillStyle = color
      }

      if (letterSpacing !== 0) {
        let xPos = xOffset
        for (const char of text) {
          offCtx.fillText(char, xPos, actualAscent)
          xPos += offCtx.measureText(char).width + letterSpacing
        }
      } else {
        offCtx.fillText(text, xOffset - actualLeft, actualAscent)
      }

      const horizontalMargin = fuzzRange + 20
      const verticalMargin = 0
      canvas.width = offscreenWidth + horizontalMargin * 2
      canvas.height = tightHeight + verticalMargin * 2
      ctx.setTransform(1, 0, 0, 1, 0, 0)
      ctx.translate(horizontalMargin, verticalMargin)

      let isGlitching = false
      let lastFrameTime = 0
      const frameDuration = 1000 / fps

      const startGlitchLoop = () => {
        if (!glitchMode || isCancelled) return
        glitchTimeoutId = setTimeout(() => {
          if (isCancelled) return
          isGlitching = true
          glitchEndTimeoutId = setTimeout(() => {
            isGlitching = false
            startGlitchLoop()
          }, glitchDuration)
        }, glitchInterval)
      }

      if (glitchMode) startGlitchLoop()

      const run = (timestamp) => {
        if (isCancelled) return

        if (timestamp - lastFrameTime < frameDuration) {
          animationFrameId = window.requestAnimationFrame(run)
          return
        }
        lastFrameTime = timestamp

        ctx.clearRect(
          -fuzzRange - 20,
          -fuzzRange - 10,
          offscreenWidth + 2 * (fuzzRange + 20),
          tightHeight + 2 * (fuzzRange + 10)
        )

        const { hovering, clicking } = interactionRef.current
        let currentIntensity = baseIntensity / 10
        if (clicking || isGlitching) {
          currentIntensity = clicking ? clickIntensity : 1
        } else if (hovering) {
          currentIntensity = hoverIntensity / 10
        }

        for (let j = 0; j < tightHeight; j++) {
          const dx = Math.floor(
            currentIntensity * (Math.random() - 0.5) * fuzzRange
          )
          ctx.drawImage(
            offscreen,
            0,
            j,
            offscreenWidth,
            1,
            dx,
            j,
            offscreenWidth,
            1
          )
        }

        animationFrameId = window.requestAnimationFrame(run)
      }

      animationFrameId = window.requestAnimationFrame(run)

      canvas.cleanupFuzzyText = () => {
        window.cancelAnimationFrame(animationFrameId)
        clearTimeout(glitchTimeoutId)
        clearTimeout(glitchEndTimeoutId)
      }
    }

    init()

    return () => {
      isCancelled = true
      window.cancelAnimationFrame(animationFrameId)
      clearTimeout(glitchTimeoutId)
      clearTimeout(glitchEndTimeoutId)
      clearTimeout(clickTimeoutRef.current)
      canvas?.cleanupFuzzyText?.()
    }
  }, [
    text,
    font,
    color,
    enableHover,
    baseIntensity,
    hoverIntensity,
    clickIntensity,
    fuzzRange,
    fps,
    clickEffect,
    glitchMode,
    glitchInterval,
    glitchDuration,
    useGradient,
    gradientEnd,
  ])

  return (
    <div
      style={{
        width: "100%",
        textAlign: font.textAlign || "center",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
      }}
    >
      <canvas
        ref={canvasRef}
        onPointerEnter={handlePointerEnter}
        onPointerLeave={handlePointerLeave}
        onPointerDown={handlePointerDown}
        style={{
          display: "inline-block",
          maxWidth: "100%",
          height: "auto",
          pointerEvents: "auto",
          touchAction: "manipulation",
          cursor: enableHover || clickEffect ? "pointer" : "default",
          userSelect: "none",
          verticalAlign: "top",
        }}
      />
    </div>
  )
}

const defaultPresetProps = {
  text: "SecureMailScope",
  font: {
    fontSize: "clamp(34px, 7vw, 92px)",
    textAlign: "center",
    fontFamily: "'Syne', 'Space Grotesk', -apple-system, sans-serif",
    fontWeight: 700,
    lineHeight: "1.1em",
    letterSpacing: "-0.01em",
  },
}

export default function FuzzyText(props) {
  return <BaseFuzzyText {...defaultPresetProps} {...props} />
}
