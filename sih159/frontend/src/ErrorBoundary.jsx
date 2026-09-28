import React from 'react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('SecureMailScope ErrorBoundary caught an error:', error, errorInfo)
    this.setState({ error, errorInfo })
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
    if (this.props.onReset) {
      this.props.onReset()
    } else {
      window.location.reload()
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '80vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '24px',
          fontFamily: 'Inter, sans-serif'
        }}>
          <div style={{
            maxWidth: '600px',
            width: '100%',
            background: 'var(--bg-surface, #0d1117)',
            border: '1px solid var(--border-color, rgba(255, 255, 255, 0.15))',
            borderRadius: '12px',
            padding: '32px',
            boxShadow: '0 12px 40px rgba(0,0,0,0.5)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '40px', marginBottom: '16px' }}>🛡️</div>
            <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary, #f0f6fc)', marginBottom: '10px' }}>
              Interface Recovery Notice
            </h2>
            <p style={{ fontSize: '14px', color: 'var(--text-secondary, #94a3b8)', marginBottom: '20px', lineHeight: 1.6 }}>
              A temporary render interruption was caught safely by SecureMailScope. Your session and backend data remain intact.
            </p>
            {this.state.error && (
              <pre style={{
                background: 'rgba(0,0,0,0.4)',
                padding: '12px',
                borderRadius: '6px',
                fontSize: '12px',
                color: '#ff595e',
                overflowX: 'auto',
                textAlign: 'left',
                marginBottom: '20px',
                maxHeight: '120px'
              }}>
                {this.state.error.toString()}
              </pre>
            )}
            <button
              onClick={this.handleReset}
              style={{
                background: 'var(--primary, #c8ff00)',
                color: 'var(--primary-text, #07090c)',
                border: 'none',
                padding: '10px 24px',
                borderRadius: '6px',
                fontWeight: 700,
                cursor: 'pointer',
                fontSize: '14px'
              }}
            >
              🔄 Refresh View
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
