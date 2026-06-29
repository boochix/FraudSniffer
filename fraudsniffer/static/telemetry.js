/**
 * FraudSniffer Telemetry Collector
 * ─────────────────────────────────
 * Lightweight client-side library that collects browser/device telemetry
 * during document submission for behavioral fraud analytics.
 *
 * Collects:
 *  - Canvas Fingerprint (hardware-based rendering hash)
 *  - Keystroke dynamics (total typing duration, key intervals)
 *  - Submission duration (time from page load to submit click)
 *  - Browser metadata (timezone, language, screen, platform, user-agent)
 */

(function (global) {
    'use strict';

    const Telemetry = {};

    // ── Timing ──────────────────────────────────────────────────
    let _pageLoadTime = Date.now();
    let _firstKeystrokeTime = null;
    let _lastKeystrokeTime = null;
    let _keystrokeCount = 0;
    let _initialized = false;

    /**
     * Initialize telemetry collection.
     * Call once when the upload form becomes interactive.
     */
    Telemetry.init = function () {
        if (_initialized) return;
        _initialized = true;
        _pageLoadTime = Date.now();
        _firstKeystrokeTime = null;
        _lastKeystrokeTime = null;
        _keystrokeCount = 0;

        // Attach keystroke listeners to all form inputs
        document.addEventListener('keydown', _onKeyDown, true);
        console.log('[Telemetry] Initialized — tracking keystrokes and submission timing');
    };

    /**
     * Reset all timers (e.g. when re-opening the form).
     */
    Telemetry.reset = function () {
        _pageLoadTime = Date.now();
        _firstKeystrokeTime = null;
        _lastKeystrokeTime = null;
        _keystrokeCount = 0;
    };

    // ── Keystroke Handler ───────────────────────────────────────
    function _onKeyDown(e) {
        const now = Date.now();
        if (!_firstKeystrokeTime) {
            _firstKeystrokeTime = now;
        }
        _lastKeystrokeTime = now;
        _keystrokeCount++;
    }

    // ── Canvas Fingerprint ──────────────────────────────────────
    /**
     * Generate a unique canvas fingerprint by rendering styled text
     * onto an offscreen canvas and hashing the pixel data.
     * Different GPUs/font renderers produce subtly different outputs.
     */
    Telemetry.getCanvasFingerprint = async function () {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 280;
            canvas.height = 60;
            const ctx = canvas.getContext('2d');
            if (!ctx) return 'canvas-unsupported';

            // Background
            ctx.fillStyle = '#f0f0f0';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Primary text with specific font stack
            ctx.textBaseline = 'alphabetic';
            ctx.font = '14px "Arial", "Helvetica Neue", sans-serif';
            ctx.fillStyle = '#3c763d';
            ctx.fillText('FraudSniffer Canvas FP 🏦💎', 2, 20);

            // Secondary text with different styling
            ctx.font = 'bold 12px "Times New Roman", serif';
            ctx.fillStyle = '#8a6d3b';
            ctx.fillText('Behavioral Analytics Layer v1.0', 4, 40);

            // Draw geometric shapes for additional uniqueness
            ctx.strokeStyle = '#31708f';
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.arc(240, 30, 15, 0, Math.PI * 2);
            ctx.stroke();

            // Get the data URL and hash it
            const dataUrl = canvas.toDataURL('image/png');
            const hash = await _sha256(dataUrl);
            return hash;
        } catch (err) {
            console.warn('[Telemetry] Canvas fingerprint failed:', err);
            return 'canvas-error';
        }
    };

    // ── SHA-256 Hash ────────────────────────────────────────────
    async function _sha256(message) {
        if (typeof crypto !== 'undefined' && crypto.subtle) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
        // Fallback: simple DJB2 hash (non-cryptographic, for environments without SubtleCrypto)
        let hash = 5381;
        for (let i = 0; i < message.length; i++) {
            hash = ((hash << 5) + hash + message.charCodeAt(i)) & 0xFFFFFFFF;
        }
        return 'djb2-' + (hash >>> 0).toString(16);
    }

    // ── Browser Metadata ────────────────────────────────────────
    /**
     * Collect browser environment metadata.
     */
    Telemetry.getBrowserMetadata = function () {
        return {
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown',
            language: navigator.language || navigator.userLanguage || 'Unknown',
            screen_resolution: `${screen.width}x${screen.height}`,
            platform: navigator.platform || 'Unknown',
            user_agent: navigator.userAgent || 'Unknown',
        };
    };

    // ── Assemble Final Payload ──────────────────────────────────
    /**
     * Produce the complete telemetry payload to attach to the form submission.
     * Call this right before submitting the form.
     */
    Telemetry.collect = async function () {
        const now = Date.now();
        const submissionDuration = now - _pageLoadTime;
        const keystrokeDuration = (_firstKeystrokeTime && _lastKeystrokeTime)
            ? (_lastKeystrokeTime - _firstKeystrokeTime)
            : 0;

        const canvasFingerprint = await Telemetry.getCanvasFingerprint();
        const browserMeta = Telemetry.getBrowserMetadata();

        return {
            canvas_fingerprint: canvasFingerprint,
            timezone: browserMeta.timezone,
            language: browserMeta.language,
            screen_resolution: browserMeta.screen_resolution,
            platform: browserMeta.platform,
            user_agent: browserMeta.user_agent,
            keystroke_duration_ms: keystrokeDuration,
            submission_duration_ms: submissionDuration,
            keystroke_count: _keystrokeCount,
            // ip_address is injected server-side for security
        };
    };

    // ── Export ───────────────────────────────────────────────────
    global.FraudSnifferTelemetry = Telemetry;

})(typeof window !== 'undefined' ? window : this);
