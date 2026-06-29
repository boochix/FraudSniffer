/**
 * FraudSniffer Dashboard — app.js
 * ──────────────────────────────────────────────
 * Vanilla JavaScript controller for the FraudSniffer compliance UI.
 * Connects to the Flask API (same-origin, relative paths).
 *
 * Structure:
 *   1. Constants & Config
 *   2. DOM References
 *   3. State
 *   4. Utility Helpers
 *   5. Toast Notifications
 *   6. Tab Navigation
 *   7. Dropzone & File Selection
 *   8. Metadata Builder
 *   9. Document Submission
 *  10. Document Lookup
 *  11. Result Rendering
 *  12. History Tab
 *  13. System / Health Tab
 *  14. Review Submission
 *  15. Self-Test
 *  16. Initialisation
 */
(function () {
  'use strict';

  /* ───────────────────────── 1. Constants ───────────────────────── */

  /** Human-readable labels for risk reason codes. */
  var REASON_LABELS = {
    SEAL_MISMATCH:        'Seal Mismatch',
    JOB_SALARY_ANOMALY:   'Job-Salary Anomaly',
    FORM_PDF_MISMATCH:    'Form-PDF Mismatch',
    PARSE_COVERAGE_LOW:   'Low Parse Coverage',
    META_BACKDATE:        'Metadata Backdating',
    SALARY_OUTLIER:       'Salary Outlier',
    TEMPLATE_GENERATED:   'Template Generated',
    SEMANTIC_INCOHERENCE: 'Semantic Incoherence',
    HASH_CHAIN_BREAK:     'Hash Chain Break',
    OCR_EXTRACTION_FAILED:'OCR Failure',
    OCR_INCONSISTENCY:    'OCR Inconsistency',
    GHOST_PROPERTY:       'Ghost Property',
    PACKAGE_MISMATCH:     'Package Mismatch',
    ELA_TAMPERING:        'ELA Tampering',
    PDF_FONT_MISMATCH:    'PDF Font Mismatch',
    PDF_OBJECT_ANOMALY:   'PDF Object Anomaly',
    HIDDEN_TEXT_LAYER:    'Hidden Text Layer',
    RAW_OCR_DIVERGENCE:   'Raw/OCR Divergence',
    CROSS_DOCUMENT_REUSE: 'Cross-Document Reuse',
    DEVICE_CLONE:         'Device Clone',
    IMPOSSIBLE_TRAVEL:    'Impossible Travel',
    VPN_DETECTED:         'VPN/Tor/Proxy',
    SCRIPTED_SUBMISSION:  'Scripted Submission',
    KNOWN_DEVICE_CLUSTER: 'Device Cluster',
    REPEATED_PATTERN:     'Repeat Pattern',
    PAN_NAME_MISMATCH:    'PAN Name Mismatch',
    COMPANY_NOT_FOUND:    'Company Not Found',
    IFSC_INVALID:         'Invalid IFSC',
    BANK_ACCOUNT_MISMATCH:'Bank Account Mismatch',
    GST_STATE_CODE_INVALID:'Invalid GST State Code',
    GSTIN_PAN_MISMATCH:   'GSTIN PAN Mismatch',
    DUPLICATE_DOCUMENT:   'Duplicate Document',
    SIMILAR_DOCUMENT_FOUND:'Similar Document Found',
    BILL_CONSUMER_MISMATCH:'Bill Consumer Mismatch',
    BILL_STALE:           'Stale Utility Bill',
    BILL_MATH_MISMATCH:   'Bill Math Mismatch',
    TAX_MATH_MISMATCH:    'Tax Math Mismatch'
  };

  /** Visual config per risk state. */
  var STATE_CONFIG = {
    LOW:     { cls: 'low',     label: 'Low Risk',  color: '#16a34a' },
    WATCH:   { cls: 'watch',   label: 'Needs Review', color: '#ca8a04' },
    SUSPECT: { cls: 'suspect', label: 'High Risk', color: '#dc2626' },
    BLOCK:   { cls: 'block',   label: 'Critical',  color: '#991b1b' }
  };

  /** Feature-status badge styling. */
  var STATUS_BADGE = {
    REAL:         { text: 'Real',         cls: 'badge-ok' },
    DERIVED:      { text: 'Derived',      cls: 'badge-info' },
    LLM_INFERRED: { text: 'LLM Inferred', cls: 'badge-info' },
    SIMULATED:    { text: 'Simulated',    cls: 'badge-warn' },
    UNAVAILABLE:  { text: 'Unavailable',  cls: 'badge-muted' }
  };

  /** Human-readable labels for document types. */
  var DOC_TYPE_LABELS = {
    GST_REGISTRATION:    'GST Registration',
    INCOME_TAX_FORM:     'Income Tax Form',
    COMPANY_REGISTRATION: 'Company Registration',
    UTILITY_BILL:         'Utility Bill',
    PAYSLIP:              'Payslip'
  };

  /* ───────────────────────── 2. DOM References ──────────────────── */

  /**
   * Lazy-lookup helper. Caches elements after first access so we
   * don't re-query the DOM on every render cycle.
   */
  var _cache = {};
  function $(id) {
    if (!_cache[id]) {
      _cache[id] = document.getElementById(id) || document.querySelector(id);
    }
    return _cache[id];
  }

  /* ───────────────────────── 3. State ───────────────────────────── */

  var currentDocId   = null;   // The doc_id currently displayed
  var advancedMode   = false;  // Whether raw-JSON editor is open
  var selectedFile   = null;   // File chosen via dropzone / input
  var toastTimeout   = null;   // Prevent toast pile-ups
  var lastAuditReport = null;  // Last fetched PQC audit report for export
  var forensicWorkspaceState = { data: null, page: 1, totalPages: 1 };
  var datasetStale   = true;   // Flag to force dataset reload after review changes

  /* ───────────────────────── 4. Utility Helpers ─────────────────── */

  /**
   * Format a Unix epoch (seconds or milliseconds) to a locale string.
   * @param {number} ts — Unix timestamp
   * @returns {string}
   */
  function formatTimestamp(ts) {
    if (!ts && ts !== 0) return '—';
    // Heuristic: if > 1e12 it's already ms
    var ms = ts > 1e12 ? ts : ts * 1000;
    try {
      return new Date(ms).toLocaleString('en-IN', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: true
      });
    } catch (_) {
      return new Date(ms).toLocaleString();
    }
  }

  /**
   * Copy a string to the clipboard with a toast confirmation.
   * @param {string} text
   */
  function copyToClipboard(text) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        showToast('Copied to clipboard', 'success');
      }).catch(function () {
        fallbackCopy(text);
      });
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      showToast('Copied to clipboard', 'success');
    } catch (_) {
      showToast('Copy failed — please copy manually', 'error');
    }
    document.body.removeChild(ta);
  }

  /** Escape HTML to prevent injection inside rendered strings. */
  function esc(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str == null ? '' : String(str)));
    return div.innerHTML;
  }

  /**
   * Wrapper around fetch with standard error handling.
   * Returns parsed JSON on success; throws on HTTP error.
   */
  function api(method, url, body, isFormData) {
    var opts = { method: method, headers: {} };
    if (body && !isFormData) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    } else if (body && isFormData) {
      opts.body = body; // FormData — browser sets Content-Type
    }
    return fetch(url, opts).then(function (res) {
      return res.json().then(function (json) {
        if (!res.ok) {
          var msg = json.error || json.message || ('HTTP ' + res.status);
          throw new Error(msg);
        }
        return json;
      });
    });
  }

  /* ───────────────────────── 5. Toast Notifications ─────────────── */

  /**
   * Show a brief, non-blocking notification bar.
   * @param {string} message
   * @param {'success'|'error'|'info'} type
   */
  function showToast(message, type) {
    type = type || 'info';
    var existing = document.getElementById('app-toast');
    if (existing) existing.remove();
    clearTimeout(toastTimeout);

    var toast = document.createElement('div');
    toast.id = 'app-toast';
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    document.body.appendChild(toast);

    // Force reflow then add visible class for animation
    void toast.offsetWidth;
    toast.classList.add('toast-visible');

    toastTimeout = setTimeout(function () {
      toast.classList.remove('toast-visible');
      setTimeout(function () { toast.remove(); }, 300);
    }, 4000);
  }

  /* ───────────────────────── 6. Tab Navigation ──────────────────── */

  function initTabs() {
    var btns = document.querySelectorAll('[data-tab]');
    btns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        activateTab(btn.getAttribute('data-tab'));
      });
    });
  }

  function activateTab(name) {
    // Deactivate all tabs
    document.querySelectorAll('[data-tab]').forEach(function (b) {
      b.classList.remove('active');
    });
    document.querySelectorAll('.tab-content').forEach(function (el) {
      el.classList.remove('active');
    });

    // Activate chosen
    var btn = document.querySelector('[data-tab="' + name + '"]');
    if (btn) btn.classList.add('active');
    var pane = document.getElementById('tab-' + name);
    if (pane) pane.classList.add('active');

    // Update hash (no scroll)
    history.replaceState(null, '', '#' + name);

    // Lazy-load tab data
    if (name === 'history') loadHistory();
    if (name === 'dataset') { datasetStale = false; loadDataset(); }
    if (name === 'system')  loadHealth();
  }

  /* ───────────────────────── 7. Dropzone & File ─────────────────── */

  function initDropzone() {
    var zone  = $('dropzone');
    var input = $('file-input');
    var label = $('file-name');
    if (!zone || !input) return;

    // Click the zone → trigger hidden input
    zone.addEventListener('click', function () { input.click(); });

    // File chosen via picker
    input.addEventListener('change', function () {
      if (input.files.length) {
        selectedFile = input.files[0];
        if (label) label.textContent = selectedFile.name;
        zone.classList.add('has-file');
      }
    });

    // Drag events
    zone.addEventListener('dragover', function (e) {
      e.preventDefault();
      zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', function (e) {
      e.preventDefault();
      zone.classList.remove('drag-over');
    });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('drag-over');
      if (e.dataTransfer.files.length) {
        selectedFile = e.dataTransfer.files[0];
        input.files = e.dataTransfer.files; // sync the input
        if (label) label.textContent = selectedFile.name;
        zone.classList.add('has-file');
      }
    });
  }

  /* ───────────────────────── 8. Metadata Builder ────────────────── */

  /**
   * Assemble a metadata object from the structured form fields.
   * If advanced mode is active and the raw-JSON textarea has valid
   * content, that takes precedence (merged over form fields).
   */
  function buildMetadata() {
    var docType  = $('doc-type');
    var loan     = $('meta-loan');
    var job      = $('meta-job');
    var city     = $('meta-city');
    var duration = $('meta-duration');
    var docDate  = $('meta-doc-date');
    var pdfDate  = $('meta-pdf-date');
    var employee = $('meta-employee');
    var employer = $('meta-employer');
    var salary   = $('meta-salary');

    var meta = {};

    if (docType  && docType.value)  meta.doc_type             = docType.value;
    if (loan     && loan.value)     meta.loan_amount           = parseFloat(loan.value);
    if (job      && job.value)      meta.job_title             = job.value;
    if (city     && city.value)     meta.city                  = city.value;
    if (duration && duration.value) meta.employment_duration    = parseInt(duration.value, 10);
    if (docDate  && docDate.value)  meta.claimed_document_date = docDate.value;
    if (pdfDate  && pdfDate.value)  meta.pdf_created_date      = pdfDate.value;
    if (employee && employee.value) meta.employee_name         = employee.value;
    if (employer && employer.value) meta.employer_name         = employer.value;
    if (salary   && salary.value)   meta.salary_amount         = parseFloat(salary.value);

    // Advanced override — raw JSON editor wins
    if (advancedMode) {
      var raw = $('meta-json');
      if (raw && raw.value && raw.value.trim()) {
        try {
          var override = JSON.parse(raw.value);
          // Merge: raw JSON properties overwrite form fields
          for (var key in override) {
            if (override.hasOwnProperty(key)) {
              meta[key] = override[key];
            }
          }
        } catch (e) {
          showToast('Invalid JSON in advanced editor — using form fields only', 'error');
        }
      }
    }

    return meta;
  }

  /* ───────────────────────── 9. Document Submission ──────────────── */

  function submitDocument() {
    var btn    = $('submit-btn');
    var status = $('submit-status');

    if (!selectedFile) {
      showToast('Please select a document file first', 'error');
      return;
    }

    var metadata = buildMetadata();

    // Enter loading state
    btn.disabled = true;
    btn.classList.add('loading');
    var originalText = btn.textContent;
    btn.textContent = 'Collecting telemetry…';
    if (status) status.textContent = 'Collecting device telemetry…';

    // Collect telemetry (async) then submit
    var telemetryPromise = (typeof FraudSnifferTelemetry !== 'undefined')
      ? FraudSnifferTelemetry.collect()
      : Promise.resolve({});

    telemetryPromise.then(function (telemetryPayload) {
      var form = new FormData();
      form.append('file', selectedFile);
      form.append('metadata', JSON.stringify(metadata));
      form.append('telemetry', JSON.stringify(telemetryPayload));

      btn.textContent = 'Analyzing…';
      if (status) status.textContent = 'Uploading and analyzing document…';

      return api('POST', '/api/documents/submit', form, true);
    })
      .then(function (data) {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.textContent = originalText;
        if (status) status.textContent = 'Completed — ' + data.doc_id;
        currentDocId = data.doc_id;
        renderResults(data);
        showToast('Analysis complete', 'success');
        loadStats();
        // Reset telemetry timers for next submission
        if (typeof FraudSnifferTelemetry !== 'undefined') {
          FraudSnifferTelemetry.reset();
        }
      })
      .catch(function (err) {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.textContent = originalText;
        if (status) status.textContent = 'Error';
        showToast(err.message || 'Submission failed', 'error');
      });
  }

  /* ───────────────────────── 10. Document Lookup ────────────────── */

  function loadDocument(docId) {
    if (!docId) {
      showToast('Enter a document ID', 'error');
      return;
    }
    showToast('Loading ' + docId + '…', 'info');

    api('GET', '/api/documents/' + encodeURIComponent(docId) + '/risk')
      .then(function (data) {
        currentDocId = docId;
        renderResults(data);
      })
      .catch(function (err) {
        showToast(err.message || 'Document not found', 'error');
      });
  }

  /* ───────────────────────── 11. Result Rendering ───────────────── */

  /**
   * Master renderer: populates every result element from a risk JSON
   * response object.
   */
  function renderResults(data) {
    var section = $('results-section');
    if (!section) return;

    currentDocId = data.doc_id;
    var stateKey = (data.state || 'LOW').toUpperCase();
    var cfg = STATE_CONFIG[stateKey] || STATE_CONFIG.LOW;

    // ── Risk banner ────────────────────────────────────────────
    var banner = $('risk-banner');
    if (banner) {
      banner.className = 'risk-banner ' + cfg.cls;
    }

    // ── Core fields ────────────────────────────────────────────
    setText('result-doc-id', data.doc_id);
    setText('result-score', data.fraud_score != null
      ? (data.fraud_score * 100).toFixed(1) + '%'
      : '—');
    setText('result-state', data.ui_state_label || cfg.label);
    setText('result-summary', data.final_reason_summary || '');
    setText('result-time', data.processing_time_ms != null
      ? data.processing_time_ms + ' ms'
      : '—');

    // ── Document Classification Card ──────────────────────────
    var docTypeLabel = DOC_TYPE_LABELS[(data.document_type || '').toUpperCase()] || humanize(data.document_type || '—');
    setText('classification-type', docTypeLabel);
    
    if (data.classification_confidence != null) {
      var confidenceVal = data.classification_confidence;
      var confidencePct = (confidenceVal * 100).toFixed(0) + '%';
      setText('classification-confidence', confidencePct);
      var bar = $('classification-progress-bar');
      if (bar) {
        bar.style.width = confidencePct;
        if (confidenceVal >= 0.90) {
          bar.style.backgroundColor = 'var(--success)';
        } else if (confidenceVal >= 0.70) {
          bar.style.backgroundColor = 'var(--warning)';
        } else {
          bar.style.backgroundColor = 'var(--danger)';
        }
      }
    } else {
      setText('classification-confidence', '—');
      var bar = $('classification-progress-bar');
      if (bar) bar.style.width = '0%';
    }
    setText('classification-method', 'Keyword Density Analysis');

    // ── Reason-code badges ─────────────────────────────────────
    var reasonsContainer = $('result-reasons');
    if (reasonsContainer) {
      reasonsContainer.innerHTML = '';
      var reasons = data.risk_decision_reason_codes || [];
      if (!reasons.length) {
        reasonsContainer.innerHTML = '<span class="empty-ok"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> No rules triggered</span>';
      } else {
        reasons.forEach(function (code) {
          var row = document.createElement('div');
          row.className = 'reason-row';
          row.style.display = 'flex';
          row.style.alignItems = 'center';
          row.style.justifyContent = 'space-between';
          row.style.marginBottom = '8px';
          row.style.gap = '8px';

          var badge = document.createElement('span');
          badge.className = 'badge badge-danger';
          badge.textContent = REASON_LABELS[code] || code;
          badge.style.margin = '0';
          badge.style.flex = '1';

          var explainBtn = document.createElement('button');
          explainBtn.className = 'btn-explain-rule';
          explainBtn.setAttribute('data-rule', code);
          explainBtn.textContent = 'Explain';
          explainBtn.style.padding = '2px 8px';
          explainBtn.style.fontSize = '11px';
          explainBtn.style.borderRadius = '4px';
          explainBtn.style.border = '1px solid var(--primary-cyan)';
          explainBtn.style.background = 'transparent';
          explainBtn.style.color = 'var(--primary-cyan)';
          explainBtn.style.cursor = 'pointer';
          explainBtn.style.transition = 'all 0.2s';
          
          explainBtn.addEventListener('click', function() {
            explainRule(data.doc_id, code);
          });

          row.appendChild(badge);
          row.appendChild(explainBtn);
          reasonsContainer.appendChild(row);
        });
      }
    }

    // ── Warning badges ─────────────────────────────────────────
    renderBadges('result-warnings',
      (data.warnings || []).map(function (w) {
        return { text: w, cls: 'badge-warn' };
      }),
      '<span class="empty-ok"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> No system warnings detected</span>'
    );

    // ── Confidence breakdown bars ──────────────────────────────
    renderConfidenceBars(data.confidence_breakdown || {});

    // ── OCR table ──────────────────────────────────────────────
    renderOcrTable(data);

    // ── Semantic Check ─────────────────────────────────────────
    renderSemanticCheck(data);

    // ── Seal Evidence ──────────────────────────────────────────
    renderSealEvidence(data);

    // ── Advanced Forensics ─────────────────────────────────────
    renderAdvancedForensics(data);

    // ── PQC Audit Ledger ───────────────────────────────────────
    renderPqcAuditTrail(data.doc_id);

    // ── Behavioral Analytics Inspector ─────────────────────────
    renderBehavioralInspector(data);

    // ── Feature status table ───────────────────────────────────
    renderFeatureTable(data.feature_status || {});

    // ── Artifacts: original & annotated ────────────────────────
    var origFrame = $('original-frame');
    var artifacts = data.artifacts || {};

    if (origFrame) {
      origFrame.src = artifacts.original_file_url
        || ('/api/documents/' + encodeURIComponent(data.doc_id) + '/original');
    }
    renderForensicWorkspace(data);

    // ── Pipeline timeline ──────────────────────────────────────
    renderTimeline(data.processing_timeline || []);

    // ── Raw JSON ───────────────────────────────────────────────
    var jsonOut = $('json-output');
    if (jsonOut) {
      jsonOut.textContent = JSON.stringify(data, null, 2);
    }

    // ── Populate review fields with existing review data ───────
    if (data.review) {
      var rn = $('review-notes');
      var rb = $('review-by');
      var rv = $('review-verdict');
      if (rn && data.review.review_notes) rn.value = data.review.review_notes;
      if (rb && data.review.reviewed_by)  rb.value = data.review.reviewed_by;
      if (rv && data.review.manual_verdict) rv.value = data.review.manual_verdict;
    }

    // ── Show & scroll ──────────────────────────────────────────
    section.classList.remove('hidden');
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // ── AI Copilot ─────────────────────────────────────────────
    loadAIAssistant(data.doc_id);
  }

  /* ── Rendering sub-helpers ── */

  function setText(id, text) {
    var el = $(id);
    if (el) el.textContent = text != null ? String(text) : '';
  }

  /**
   * Render an array of {text, cls} badge objects into a container.
   */
  function renderBadges(containerId, items, emptyHtml) {
    var container = $(containerId);
    if (!container) return;
    container.innerHTML = '';
    if (!items.length) {
container.innerHTML = emptyHtml || '<span class="text-muted">None</span>';
      return;
    }
    items.forEach(function (item) {
      var span = document.createElement('span');
      span.className = 'badge ' + (item.cls || '');
      span.textContent = item.text;
      container.appendChild(span);
    });
  }

  // Duplicate renderOcrTable removed to avoid redundancy. Actual function resides lower in code.

  /**
   * Render Semantic Check panel. Shows rationale and mismatch score.
   */
  function renderSemanticCheck(data) {
    var container = $('semantic-result');
    if (!container) return;
    var semantic = data.semantic_check;
    if (!semantic) {
      container.innerHTML = '<p class="text-muted text-sm">No semantic check data</p>';
      return;
    }

    var scorePct = (semantic.score * 100).toFixed(1) + '%';
    var isWarning = semantic.score > 0.40;
    var statusClass = isWarning ? 'badge-danger' : 'badge-ok';
    var statusText = isWarning ? 'Semantic Inconsistency' : 'Pass';

    container.innerHTML = 
      '<div class="flex-between mb-8">' +
        '<span class="text-sm">Analysis Source: <strong>' + esc(semantic.source) + '</strong></span>' +
        '<span class="badge ' + statusClass + '">' + statusText + '</span>' +
      '</div>' +
      '<div class="flex-between mb-8">' +
        '<span class="text-sm">Semantic Mismatch Score:</span>' +
        '<strong style="color: ' + (isWarning ? '#dc2626' : '#16a34a') + '">' + scorePct + '</strong>' +
      '</div>' +
      '<div class="text-sm text-secondary" style="background: var(--bg); padding: 10px; border-radius: var(--radius); border: 1px solid var(--border); line-height: 1.4;">' +
        '<strong>Rationale:</strong><br>' + esc(semantic.rationale) +
      '</div>';
  }

  /**
   * Render Seal Evidence panel. Shows distance metrics, details,
   * and side-by-side extracted/reference/comparison overlay.
   */
  function renderSealEvidence(data) {
    var container = $('seal-result');
    if (!container) return;
    var seal = data.seal_evidence;
    if (!seal) {
      container.innerHTML = '<p class="text-muted text-sm">No seal data</p>';
      return;
    }

    var isOk = seal.feature_status === 'REAL';
    var badgeClass = isOk ? 'badge-ok' : 'badge-muted';
    var badgeText = isOk ? 'Seal Located' : 'No Seal Found';

    var html = '';
    html += '<div class="flex-between mb-8">' +
              '<span class="text-sm">Status: <span class="badge ' + badgeClass + '">' + badgeText + '</span></span>';
    
    if (seal.seal_phash_distance !== null) {
      var distVal = seal.seal_phash_distance.toFixed(3);
      var mismatch = seal.raw_hamming_distance > 10;
      var distColor = mismatch ? '#dc2626' : '#16a34a';
      html += '<span class="text-sm">Perceptual Distance: <strong style="color: ' + distColor + '">' + distVal + '</strong></span>';
    }
    html += '</div>';

    html += '<p class="text-sm text-secondary mb-12" style="line-height: 1.4;">' + esc(seal.evidence) + '</p>';

    if (seal.extracted_seal_url || seal.reference_seal_url) {
      html += '<div class="seal-images-grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px;">';
      
      if (seal.reference_seal_url) {
        html += '<div style="text-align: center;">' +
                  '<div class="text-xs text-muted mb-4">Reference Seal</div>' +
                  '<img src="' + seal.reference_seal_url + '" style="max-height: 80px; object-fit: contain; margin: 0 auto; border: 1px solid var(--border); border-radius: var(--radius); padding: 4px; background: white;" alt="Reference Seal">' +
                '</div>';
      }
      
      if (seal.extracted_seal_url) {
        html += '<div style="text-align: center;">' +
                  '<div class="text-xs text-muted mb-4">Extracted Seal</div>' +
                  '<img src="' + seal.extracted_seal_url + '" style="max-height: 80px; object-fit: contain; margin: 0 auto; border: 1px solid var(--border); border-radius: var(--radius); padding: 4px; background: white;" alt="Extracted Seal">' +
                '</div>';
      }

      var comparisonUrl = '/api/documents/' + encodeURIComponent(data.doc_id) + '/seal/comparison';
      html += '<div style="text-align: center;">' +
                '<div class="text-xs text-muted mb-4">Diff Overlay</div>' +
                '<img src="' + comparisonUrl + '" onerror="this.style.display=\'none\'; this.nextElementSibling.style.display=\'block\';" style="max-height: 80px; object-fit: contain; margin: 0 auto; border: 1px solid var(--border); border-radius: var(--radius); padding: 4px; background: white;" alt="Seal comparison overlay">' +
                '<div class="text-xs text-muted" style="display: none; height: 80px; line-height: 80px; border: 1px dashed var(--border); border-radius: var(--radius);">N/A</div>' +
              '</div>';

      html += '</div>';
    }

    container.innerHTML = html;
  }

  /**
   * Render PQC Cryptographic Audit Ledger. Fetches verified timeline events.
   */
  function renderPqcAuditTrail(docId) {
    var badge = $('pqc-integrity-badge');
    var msg = $('pqc-integrity-message');
    var container = $('pqc-audit-timeline');
    var statsEl = $('pqc-verification-stats');
    var schemeEl = $('pqc-scheme-info');

    if (!badge || !msg || !container) return;

    badge.className = 'badge badge-muted';
    badge.textContent = 'Verifying...';
    msg.textContent = 'Fetching cryptographic chain...';
    if (statsEl) statsEl.innerHTML = '';
    if (schemeEl) schemeEl.innerHTML = '';

    api('GET', '/api/documents/' + encodeURIComponent(docId) + '/audit_trail')
      .then(function (res) {
        var verification = res.verification_result || {};
        var stats = res.verification_stats || verification || {};
        var ok = res.pqc_integrity_ok;
        lastAuditReport = buildAuditReport(docId, res);

        badge.className = 'badge ' + (ok ? 'badge-ok' : 'badge-danger');
        badge.innerHTML = ok 
          ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Verified Chain' 
          : 'Chain Compromised';
        msg.textContent = res.pqc_integrity_message || '';

        if (statsEl) {
          var blocks = (stats.blocks_verified || 0) + ' / ' + (stats.total_blocks || 0);
          var sigs = (stats.signatures_valid || 0) + ' / ' + (stats.total_signatures || 0);
          var pct = stats.verification_percentage != null ? Number(stats.verification_percentage).toFixed(1) + '%' : '0.0%';
          var verifyMs = stats.verification_time_ms != null ? Number(stats.verification_time_ms).toFixed(2) + ' ms' : '—';
          var status = ok ? 'VERIFIED' : 'FAILED';
          var failedAt = stats.verification_failed_at
            ? '<span class="text-danger">Failure Time: ' + esc(stats.verification_failed_at) + '</span>'
            : '';
          statsEl.innerHTML =
            '<div style="display:flex; flex-wrap:wrap; gap:8px 14px;">' +
              '<span><strong>Blocks Verified:</strong> ' + esc(blocks) + '</span>' +
              '<span><strong>Signatures Valid:</strong> ' + esc(sigs) + '</span>' +
              '<span><strong>Verification:</strong> ' + esc(pct) + '</span>' +
              '<span><strong>Integrity Status:</strong> ' + esc(status) + '</span>' +
              '<span><strong>Verification Time:</strong> ' + esc(verifyMs) + '</span>' +
              failedAt +
            '</div>';
        }

        if (schemeEl) {
          schemeEl.innerHTML =
            '<div style="display:flex; flex-wrap:wrap; gap:8px 14px;">' +
              '<span><strong>Lattice Signature Scheme</strong>: ' + esc(formatScheme(stats.signature_scheme || 'dilithium3-local-v2')) + '</span>' +
              '<span><strong>Signer:</strong> ' + esc(stats.signer_id || 'audit-key-001') + '</span>' +
              '<span><strong>Chain Version:</strong> v' + esc(stats.chain_version || 2) + '</span>' +
            '</div>';
        }

        var timeline = res.pqc_audit_trail || [];
        if (!timeline.length) {
          container.innerHTML = '<p class="text-muted text-sm">No audit chain data available.</p>';
          return;
        }

        var html = '<ol class="pqc-timeline" style="list-style: none; padding: 0; display: flex; flex-direction: column; gap: 12px;">';
        timeline.forEach(function (evt, idx) {
          var dateStr = formatTimestamp(evt.timestamp);
          var typeLabel = esc(evt.event_type);
          
          var detailsText = '';
          var details = evt.details || {};
          if (evt.event_type === 'UPLOADED') {
            detailsText = 'Persisted original document file to disk path.';
          } else if (evt.event_type === 'HASHED') {
            detailsText = 'Computed SHA3-256 digest: <code style="font-size: 11px; word-break: break-all;">' + esc(details.file_hash_sha3) + '</code>';
          } else if (evt.event_type === 'PARSED') {
            detailsText = 'Validated user form metadata inputs.';
          } else if (evt.event_type === 'OCR_COMPLETE') {
            var count = details.fields_extracted ? details.fields_extracted.length : 0;
            var ocrPct = details.ocr_confidence != null ? (Number(details.ocr_confidence) * 100).toFixed(1) + '%' : 'unavailable';
            detailsText = 'OCR processing complete. Extracted ' + count + ' fields with ' + ocrPct + ' confidence.';
          } else if (evt.event_type === 'EXTERNAL_VERIFIED') {
            var ifscIcon = details.ifsc_verified ? '✓' : '✗';
            var ifscClass = details.ifsc_verified ? 'text-success' : 'text-danger';
            var compIcon = details.company_verified ? '✓' : '✗';
            var compClass = details.company_verified ? 'text-success' : 'text-danger';
            var panIcon = details.pan_verified ? '✓' : '✗';
            var panClass = details.pan_verified ? 'text-success' : 'text-danger';
            var bankIcon = details.bank_account_verified ? '✓' : '✗';
            var bankClass = details.bank_account_verified ? 'text-success' : 'text-danger';
            
            detailsText = 
              '<div style="margin-top: 4px; display: flex; flex-direction: column; gap: 4px; font-weight: 500;">' +
                '<span class="' + ifscClass + '">' + ifscIcon + ' IFSC code verified (live lookup)</span>' +
                '<span class="' + compClass + '">' + compIcon + ' Company registration verified (prototype)</span>' +
                '<span class="' + panClass + '">' + panIcon + ' PAN identity matching verified (prototype)</span>' +
                '<span class="' + bankClass + '">' + bankIcon + ' Bank account matching verified (prototype)</span>' +
              '</div>';
          } else if (evt.event_type === 'FEATURES_EXTRACTED') {
            detailsText = 'Extracted structural risk features.';
          } else if (evt.event_type === 'SEMANTIC_CHECKED') {
            detailsText = 'Ran semantic cross-reference checks (Source: ' + esc(details.source) + ').';
          } else if (evt.event_type === 'RULES_EVALUATED') {
            var codes = details.reasons || [];
            detailsText = codes.length > 0
              ? 'Evaluated risk compliance rules. Triggered codes: <span class="text-danger">' + esc(codes.join(', ')) + '</span>'
              : 'Evaluated risk compliance rules. No violations triggered.';
          } else if (evt.event_type === 'BEHAVIOR_EVALUATED') {
            var behaviorRules = details.risk_triggered || [];
            var behaviorScore = details.behavioral_score != null
              ? (Number(details.behavioral_score) * 100).toFixed(1) + '%'
              : '0.0%';
            detailsText =
              'Behavioral telemetry checked. Canvas fingerprint: <code>' + esc(details.fingerprint || 'none') + '</code>' +
              ', IP: <code>' + esc(details.ip_address || 'unknown') + '</code>' +
              ', behavioral score: <strong>' + esc(behaviorScore) + '</strong>. ' +
              (behaviorRules.length
                ? 'Triggered rules: <span class="text-danger">' + esc(behaviorRules.join(', ')) + '</span>.'
                : 'No behavioral risk rules triggered.');
          } else if (evt.event_type === 'FORENSICS_EVALUATED') {
            var elaScore = details.ela_score != null ? (Number(details.ela_score) * 100).toFixed(1) + '%' : 'N/A';
            var rawDistance = details.raw_ocr_divergence != null ? (Number(details.raw_ocr_divergence) * 100).toFixed(1) + '%' : 'N/A';
            detailsText =
              'Advanced forensics completed. ELA max score: <strong>' + esc(elaScore) + '</strong>, ' +
              'font anomalies: <strong>' + esc(details.pdf_font_anomalies || 0) + '</strong>, ' +
              'object anomalies: <strong>' + esc(details.pdf_object_anomalies || 0) + '</strong>, ' +
              'hidden text spans: <strong>' + esc(details.hidden_text_spans || 0) + '</strong>, ' +
              'raw/OCR token divergence: <strong>' + esc(rawDistance) + '</strong>.';
          } else if (evt.event_type === 'SIMILARITY_EVALUATED') {
            var topScore = details.top_score != null ? (Number(details.top_score) * 100).toFixed(1) + '%' : 'N/A';
            detailsText =
              'Cross-document reuse scan completed. Candidates checked: <strong>' + esc(details.candidate_count || 0) + '</strong>, ' +
              'reuse matches: <strong>' + esc(details.match_count || 0) + '</strong>, ' +
              'highest similarity: <strong>' + esc(topScore) + '</strong>.';
          } else if (evt.event_type === 'ML_SCORED') {
            detailsText = 'Assessed anomaly scores. Fraud Score: <strong>' + (details.fraud_score * 100).toFixed(1) + '%</strong> (Risk State: ' + esc(details.state) + ').';
          } else if (evt.event_type === 'FINALIZED') {
            detailsText = 'Finalized document verification: <em>' + esc(details.final_reason_summary) + '</em>';
          } else if (evt.event_type === 'REVIEW_SUBMITTED') {
            detailsText = 'Underwriter Review submitted by <strong>' + esc(details.reviewed_by) + '</strong> (Verdict: <strong class="badge-info">' + esc(details.manual_verdict) + '</strong>). Notes: <em>' + esc(details.review_notes) + '</em>';
          } else if (evt.event_type === 'PROCESSING_ERROR') {
            detailsText =
              '<span class="text-danger">Processing error: ' + esc(details.error || 'Unknown error') + '</span>' +
              (details.traceback
                ? '<pre class="pqc-error-trace">' + esc(details.traceback) + '</pre>'
                : '');
          } else {
            detailsText = esc(JSON.stringify(details));
          }

          var eventVerified = evt.signature_verified !== false;
          var secureBadge = '<span class="badge ' + (eventVerified ? 'badge-ok' : 'badge-danger') + '" style="font-size: 9px; padding: 1px 4px; display: inline-flex; align-items: center; gap: 2px;">' +
                              '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> ' +
                              (eventVerified ? 'Verified' : 'Unverified') +
                            '</span>';
          var auditMeta = '';
          if (evt.payload_hash || evt.signed_at || evt.signer_id) {
            auditMeta =
              '<div class="text-muted" style="font-size: 11px; margin-top: 2px; word-break: break-all;">' +
                (evt.signed_at ? 'Signed: ' + esc(evt.signed_at) + ' · ' : '') +
                (evt.signer_id ? 'Signer: ' + esc(evt.signer_id) + ' · ' : '') +
                (evt.payload_hash ? 'Payload: ' + esc(evt.payload_hash) : '') +
              '</div>';
          }

          html += '<li class="pqc-step" style="border-left: 2px solid ' + (eventVerified ? '#16a34a' : '#dc2626') + '; padding-left: 12px; position: relative; padding-bottom: 4px;">' +
                    '<div style="font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 8px;">' +
                      '<span>' + dateStr + '</span>' +
                      secureBadge +
                    '</div>' +
                    '<div style="font-size: 13px; font-weight: 600; margin-top: 2px;">' + typeLabel + '</div>' +
                    '<div class="text-secondary" style="font-size: 12px; margin-top: 2px; line-height: 1.35;">' + detailsText + '</div>' +
                    auditMeta +
                  '</li>';
        });
        html += '</ol>';
        container.innerHTML = html;
      })
      .catch(function (err) {
        badge.className = 'badge badge-danger';
        badge.textContent = 'Verification Failed';
        msg.textContent = err.message || 'Error communicating with audit ledger.';
        if (statsEl) statsEl.innerHTML = '';
        if (schemeEl) schemeEl.innerHTML = '';
        container.innerHTML = '<p class="text-danger text-sm">Failed to retrieve audit trail.</p>';
      });
  }

  function formatScheme(scheme) {
    if (!scheme) return 'Dilithium3-Local-v2';
    return String(scheme)
      .split('-')
      .map(function (part) {
        return part.charAt(0).toUpperCase() + part.slice(1);
      })
      .join('-')
      .replace('Dilithium3', 'Dilithium3');
  }

  function buildAuditReport(docId, res) {
    var verification = res.verification_result || {};
    var timeline = res.pqc_audit_trail || [];
    return {
      document_id: docId,
      generated_at: new Date().toISOString(),
      block_count: verification.total_blocks || timeline.length,
      blocks_verified: verification.blocks_verified || 0,
      signatures_valid: verification.signatures_valid || 0,
      total_signatures: verification.total_signatures || 0,
      verification_percentage: verification.verification_percentage || 0,
      sha3_integrity: verification.failure_type === 'hash_link' ? 'FAILED' : 'OK',
      signature_status: verification.ok ? 'VERIFIED' : 'FAILED',
      verification_time_ms: verification.verification_time_ms,
      verification_failed_at: verification.verification_failed_at || null,
      signature_scheme: verification.signature_scheme || 'dilithium3-local-v2',
      signer_id: verification.signer_id || 'audit-key-001',
      failure_type: verification.failure_type || null,
      failure_message: verification.message || null,
      timeline: timeline
    };
  }

  function exportAuditReport() {
    if (!lastAuditReport) {
      showToast('No audit report available yet', 'error');
      return;
    }
    var blob = new Blob([JSON.stringify(lastAuditReport, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = (lastAuditReport.document_id || 'fraudsniffer') + '_audit_report.json';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Audit report exported', 'success');
  }

  /**
   * Render confidence breakdown as labelled horizontal bars.
   */
  function renderConfidenceBars(breakdown) {
    var container = $('confidence-bars');
    if (!container) return;
    container.innerHTML = '';

    var keys = Object.keys(breakdown);
    if (!keys.length) {
      container.innerHTML = '<span class="text-muted">No confidence signals</span>';
      return;
    }

    keys
      .sort(function (a, b) { return breakdown[b] - breakdown[a]; })
      .forEach(function (key) {
        var value = breakdown[key];
        var pct   = Math.min(value * 100, 100);
        var row   = document.createElement('div');
        row.className = 'confidence-row';
        var color = barColor(value, key);
        row.innerHTML =
          '<div class="confidence-label">' + esc(humanize(key)) + '</div>' +
          '<div class="confidence-track">' +
            '<div class="confidence-fill" style="width:' + pct.toFixed(1) + '%;' +
              'background:' + color + '"></div>' +
          '</div>' +
          '<div class="confidence-value" style="color:' + color + '">' + (value * 100).toFixed(1) + '%</div>';
        container.appendChild(row);
      });
  }

  /** Semantic color map for confidence signal types. */
  var SIGNAL_COLORS = {
    seal_mismatch:           '#f59e0b',  // amber
    seal_phash_distance:     '#f59e0b',  // amber
    metadata_backdating:     '#dc2626',  // red
    form_pdf_mismatch:       '#dc2626',  // red
    hash_chain_integrity:    '#dc2626',  // red
    parse_coverage_low:      '#eab308',  // yellow
    job_salary_anomaly:      '#f97316',  // orange
    income_mismatch:         '#f97316',  // orange
    llm_semantic_coherence:  '#dc2626',  // red
    template_generation:     '#ca8a04',  // dark amber
  };

  function barColor(v, key) {
    if (key && SIGNAL_COLORS[key]) return SIGNAL_COLORS[key];
    if (v >= 0.3) return '#dc2626';
    if (v >= 0.15) return '#ca8a04';
    return '#16a34a';
  }

  /**
   * Convert snake_case keys to Title Case labels.
   */
  function humanize(str) {
    return str.replace(/_/g, ' ').replace(/\b\w/g, function (c) {
      return c.toUpperCase();
    });
  }

  /**
   * Render OCR fields table. Pulls from data.feature_status
   * data.feature_values, and data.ocr_confidence.
   */
  function renderOcrTable(data) {
    var tbody = $('ocr-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    var featureStatus = data.feature_status || {};
    var featureValues = data.feature_values || {};
    var preferredOrder = [
      'employee_name',
      'employee_id',
      'employer_name',
      'company_name',
      'designation',
      'department',
      'date',
      'date_of_issue',
      'pay_period',
      'salary_amount',
      'gross_pay',
      'net_pay',
      'total_deductions',
      'provident_fund',
      'professional_tax',
      'tds',
      'pan_number',
      'ifsc_code',
      'bank_account'
    ];
    var keys = preferredOrder.filter(function (key) {
      return Object.prototype.hasOwnProperty.call(featureStatus, key);
    });
    if (!keys.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="text-muted">No OCR data</td></tr>';
      return;
    }

    keys.forEach(function (fieldName) {
      var status = featureStatus[fieldName];
      var badge  = STATUS_BADGE[status] || { text: status, cls: '' };
      var val = featureValues[fieldName];
      var valText = '—';
      if (val !== undefined && val !== null) {
        if (typeof val === 'number') {
          if (/salary|pay|deductions|tax|fund|tds/i.test(fieldName)) {
            valText = '₹' + val.toLocaleString('en-IN');
          } else {
            valText = String(val);
          }
        } else {
          valText = String(val);
        }
      }
      
      var statusHtml = '<span class="badge ' + badge.cls + '">' + esc(badge.text) + '</span>';
      
      if (data.external_verification) {
        var ext = data.external_verification;
        if (fieldName === 'company_name' || fieldName === 'employer_name') {
          var comp = ext.company;
          if (comp) {
            if (comp.valid) {
              statusHtml = '<span class="badge badge-verified" title="CIN: ' + esc(comp.cin) + '">MCA Registry (Prototype)</span>';
            } else if (comp.error && comp.error.indexOf('Company name is empty') === -1 && comp.error.indexOf('not found in document') === -1) {
              statusHtml = '<span class="badge badge-error">Unregistered (MCA)</span>';
            }
          }
        } else if (fieldName === 'pan_number') {
          var pan = ext.pan;
          if (pan) {
            if (pan.valid) {
              statusHtml = '<span class="badge badge-verified" title="Registered Name: ' + esc(pan.registered_name) + '">Registry Verification (Prototype)</span>';
            } else if (pan.error && pan.error.indexOf('PAN or employee') === -1 && pan.error.indexOf('not found') === -1) {
              if (pan.error.indexOf('unregistered') !== -1) {
                statusHtml = '<span class="badge badge-error" title="' + esc(pan.error) + '">Unregistered (PAN)</span>';
              } else {
                statusHtml = '<span class="badge badge-mismatch" title="' + esc(pan.error) + '">Name Mismatch</span>';
              }
            }
          }
        } else if (fieldName === 'ifsc_code') {
          var ifsc = ext.ifsc;
          if (ifsc) {
            if (ifsc.valid) {
              var desc = ifsc.bank + ' - ' + ifsc.branch;
              statusHtml = '<span class="badge badge-verified" title="' + esc(desc) + '">Verified: ' + esc(desc) + '</span>';
            } else if (ifsc.error && ifsc.error.indexOf('not found') === -1) {
              statusHtml = '<span class="badge badge-error" title="' + esc(ifsc.error) + '">Invalid IFSC</span>';
            }
          }
        } else if (fieldName === 'bank_account') {
          var bank = ext.bank_account;
          if (bank) {
            if (bank.valid) {
              statusHtml = '<span class="badge badge-verified" title="Beneficiary: ' + esc(bank.beneficiary_name) + '">Verified (' + esc(bank.beneficiary_name) + ')</span>';
            } else if (bank.error && bank.error.indexOf('not found') === -1) {
              statusHtml = '<span class="badge badge-mismatch" title="' + esc(bank.error) + '">Mismatch</span>';
            }
          }
        }
      }

      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + esc(humanize(fieldName)) + '</td>' +
        '<td class="text-mono">' + esc(valText) + '</td>' +
        '<td>' + statusHtml + '</td>';
      tbody.appendChild(tr);
    });

    // OCR confidence footer
    if (data.ocr_confidence != null) {
      var tfr = document.createElement('tr');
      tfr.className = 'table-footer-row';
      tfr.innerHTML =
        '<td colspan="2"><strong>Overall OCR Confidence</strong></td>' +
        '<td><strong>' + (data.ocr_confidence * 100).toFixed(1) + '%</strong></td>';
      tbody.appendChild(tfr);
    }

    // Update the OCR confidence header display (Item A)
    var confVal = $('ocr-confidence-val');
    if (confVal) {
      if (data.ocr_confidence != null) {
        var pctOcr = (data.ocr_confidence * 100).toFixed(1);
        confVal.textContent = pctOcr + '%';
        confVal.style.color = data.ocr_confidence >= 0.8
          ? '#16a34a'
          : data.ocr_confidence >= 0.5 ? '#ca8a04' : '#dc2626';
      } else {
        confVal.textContent = '—';
        confVal.style.color = '';
      }
    }
  }

  /**
   * Feature-status table (separate from OCR table for the full
   * feature_status map).
   */
  function renderFeatureTable(featureStatus) {
    var tbody = $('feature-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    var keys = Object.keys(featureStatus);
    if (!keys.length) {
      tbody.innerHTML = '<tr><td colspan="2" class="text-muted">No features</td></tr>';
      return;
    }

    keys.forEach(function (fieldName) {
      var status = featureStatus[fieldName];
      var badge  = STATUS_BADGE[status] || { text: status, cls: '' };
      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + esc(humanize(fieldName)) + '</td>' +
        '<td><span class="badge ' + badge.cls + '">' + esc(badge.text) + '</span></td>';
      tbody.appendChild(tr);
    });
  }

  /**
   * Render pipeline processing timeline (vertical step list).
   * Each entry has { state, timestamp, detail, error_message }.
   */
  function renderTimeline(events) {
    var container = $('timeline-container');
    if (!container) return;
    container.innerHTML = '';

    if (!events || !events.length) {
      container.innerHTML = '<span class="text-muted">No timeline data</span>';
      return;
    }

    var list = document.createElement('ol');
    list.className = 'timeline';

    events.forEach(function (evt, idx) {
      var li = document.createElement('li');
      li.className = 'timeline-step';
      if (evt.error_message) li.classList.add('timeline-error');
      if (idx === events.length - 1) li.classList.add('timeline-current');

      var label = humanize(evt.state);
      var time  = formatTimestamp(evt.timestamp);
      var extra = '';
      if (evt.error_message) {
        extra = '<div class="timeline-error-msg">' + esc(evt.error_message) + '</div>';
      }
      li.innerHTML =
        '<div class="timeline-marker"></div>' +
        '<div class="timeline-body">' +
          '<strong>' + esc(label) + '</strong>' +
          '<span class="timeline-time">' + esc(time) + '</span>' +
          extra +
        '</div>';
      list.appendChild(li);
    });

    container.appendChild(list);
  }

  /* ───────────────────────── 12. History Tab ────────────────────── */

  function loadHistory() {
    var tbody = $('history-table-body');
    var empty = $('history-empty');
    if (!tbody) return;

    api('GET', '/api/documents')
      .then(function (docs) {
        tbody.innerHTML = '';
        if (!docs || !docs.length) {
          if (empty) empty.classList.remove('hidden');
          return;
        }
        if (empty) empty.classList.add('hidden');

        docs.forEach(function (doc) {
          var stateKey = (doc.state || 'LOW').toUpperCase();
          var cfg      = STATE_CONFIG[stateKey] || STATE_CONFIG.LOW;
          var tr = document.createElement('tr');
          tr.innerHTML =
            '<td>' +
              '<a href="#" class="link-doc" data-id="' + esc(doc.doc_id) + '">' +
                esc(doc.doc_id) +
              '</a>' +
            '</td>' +
            '<td><span class="badge badge-' + cfg.cls + '">' + esc(cfg.label) + '</span></td>' +
            '<td>' + (doc.fraud_score != null ? (doc.fraud_score * 100).toFixed(1) + '%' : '—') + '</td>' +
            '<td class="cell-summary">' + esc(doc.final_reason_summary || '') + '</td>' +
            '<td class="text-mono" style="font-size: 12px;">' + esc(doc.device_name || '—') + '</td>' +
            '<td>' + formatTimestamp(doc.created_at) + '</td>' +
            '<td><button class="btn btn-secondary btn-xs link-doc" data-id="' + esc(doc.doc_id) + '" style="font-size: 11px; padding: 2px 6px;">View</button></td>';
          tbody.appendChild(tr);
        });

        // Attach click handlers to doc links
        tbody.querySelectorAll('.link-doc').forEach(function (a) {
          a.addEventListener('click', function (e) {
            e.preventDefault();
            var id = a.getAttribute('data-id');
            activateTab('analyze');
            loadDocument(id);
            // Also set the lookup input
            var lookupInput = $('lookup-id');
            if (lookupInput) lookupInput.value = id;
          });
        });
      })
      .catch(function (err) {
        // If the endpoint doesn't exist yet, show empty state gracefully
        if (empty) empty.classList.remove('hidden');
        tbody.innerHTML = '';
      });
  }

  /* ───────────────────────── 12b. Dataset & Accuracy Tab ────────── */

  function loadDataset() {
    var tbody = $('dataset-table-body');
    var empty = $('dataset-empty');
    if (!tbody) return;

    // Reset metrics to loading/initial state
    setText('accuracy-metric', '—');
    setText('precision-metric', '—');
    setText('recall-metric', '—');
    setText('f1-metric', '—');
    setText('total-count-metric', '0');
    setText('reviewed-count-metric', '0');
    setText('cell-tn', '—');
    setText('cell-fn', '—');
    setText('cell-fp', '—');
    setText('cell-tp', '—');

    api('GET', '/api/dataset/accuracy')
      .then(function (res) {
        // Set metrics
        setText('accuracy-metric', res.reviewed_count > 0 ? (res.accuracy * 100).toFixed(1) + '%' : 'N/A');
        setText('precision-metric', res.reviewed_count > 0 ? (res.precision * 100).toFixed(1) + '%' : 'N/A');
        setText('recall-metric', res.reviewed_count > 0 ? (res.recall * 100).toFixed(1) + '%' : 'N/A');
        setText('f1-metric', res.reviewed_count > 0 ? (res.f1_score * 100).toFixed(1) + '%' : 'N/A');
        setText('total-count-metric', res.total_count);
        setText('reviewed-count-metric', res.reviewed_count);
        
        // Set confusion matrix cells
        setText('cell-tn', res.reviewed_count > 0 ? res.true_negatives + ' (TN)' : '—');
        setText('cell-fn', res.reviewed_count > 0 ? res.false_negatives + ' (FN)' : '—');
        setText('cell-fp', res.reviewed_count > 0 ? res.false_positives + ' (FP)' : '—');
        setText('cell-tp', res.reviewed_count > 0 ? res.true_positives + ' (TP)' : '—');

        tbody.innerHTML = '';
        var list = res.dataset || [];
        if (!list.length) {
          if (empty) empty.classList.remove('hidden');
          return;
        }
        if (empty) empty.classList.add('hidden');

        list.forEach(function (doc) {
          var stateKey = (doc.model_state || 'LOW').toUpperCase();
          var cfg = STATE_CONFIG[stateKey] || STATE_CONFIG.LOW;
          
          var verdict = doc.manual_verdict || 'PENDING';
          var verdictClass = 'badge-muted';
          if (verdict === 'APPROVED') verdictClass = 'badge-ok';
          else if (verdict === 'REJECTED') verdictClass = 'badge-danger';
          else if (verdict === 'ESCALATE') verdictClass = 'badge-warn';

          // Compare Model Pred vs Human Verdict
          var matchText = '—';
          var matchClass = 'text-muted';
          
          if (verdict === 'APPROVED' || verdict === 'REJECTED') {
            var isModelFraud = (doc.model_state === 'SUSPECT' || doc.model_state === 'BLOCK');
            var isHumanFraud = (verdict === 'REJECTED');
            if (isModelFraud === isHumanFraud) {
              matchText = 'MATCH';
              matchClass = 'text-success';
            } else {
              matchText = isModelFraud ? 'FALSE POSITIVE' : 'FALSE NEGATIVE';
              matchClass = isModelFraud ? 'text-warn' : 'text-danger';
            }
          }

          var tr = document.createElement('tr');
          tr.innerHTML =
            '<td>' +
              '<a href="#" class="link-doc" data-id="' + esc(doc.doc_id) + '">' +
                esc(doc.doc_id) +
              '</a>' +
            '</td>' +
            '<td>' + formatTimestamp(doc.created_at) + '</td>' +
            '<td>' + (doc.fraud_score != null ? (doc.fraud_score * 100).toFixed(1) + '%' : '—') + '</td>' +
            '<td><span class="badge badge-' + cfg.cls + '">' + esc(cfg.label) + '</span></td>' +
            '<td class="text-mono" style="font-size: 12px;">' + esc(doc.device_name || '—') + '</td>' +
            '<td><span class="badge ' + verdictClass + '">' + esc(verdict) + '</span></td>' +
            '<td class="text-mono">' + esc(doc.reviewed_by || '—') + '</td>' +
            '<td class="cell-summary" title="' + esc(doc.review_notes || '') + '">' + esc(doc.review_notes || '—') + '</td>' +
            '<td style="font-weight: 600;" class="' + matchClass + '">' + esc(matchText) + '</td>';
          tbody.appendChild(tr);
        });

        // Attach click handlers to doc links
        tbody.querySelectorAll('.link-doc').forEach(function (a) {
          a.addEventListener('click', function (e) {
            e.preventDefault();
            var id = a.getAttribute('data-id');
            activateTab('analyze');
            loadDocument(id);
            // Also set the lookup input
            var lookupInput = $('lookup-id');
            if (lookupInput) lookupInput.value = id;
          });
        });
      })
      .catch(function (err) {
        showToast('Failed to load dataset: ' + err.message, 'error');
        tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center" style="padding:40px">Error loading data</td></tr>';
      });
  }

  /* ───────────────────────── 13. System / Health ────────────────── */

  var ERROR_TYPE_LABELS = {
    missing_package: 'Missing Package',
    import_error: 'Import Error',
    dependency_conflict: 'Dependency Conflict'
  };

  function loadHealth() {
    var grid = $('health-grid');
    var summaryEl = $('health-summary');
    var bannerEl = $('install-banner');
    if (!grid) return;

    api('GET', '/api/health')
      .then(function (health) {
        grid.innerHTML = '';
        if (summaryEl) summaryEl.innerHTML = '';
        if (bannerEl) bannerEl.innerHTML = '';

        var deps = health.dependencies || {};
        var keys = Object.keys(deps);
        var allHealthy = health.all_healthy !== false;
        var availCount = 0;
        var totalCount = keys.length;

        // ── Summary banner ───────────────────────────────────
        keys.forEach(function (key) {
          if (deps[key].status === 'available') availCount++;
        });

        if (summaryEl) {
          var summaryDiv = document.createElement('div');
          summaryDiv.className = 'health-summary ' + (allHealthy ? 'all-ok' : 'has-issues');
          if (allHealthy) {
            summaryDiv.innerHTML =
              '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' +
              ' All ' + totalCount + ' dependencies healthy';
          } else {
            summaryDiv.innerHTML =
              '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
              ' ' + availCount + ' of ' + totalCount + ' dependencies available';
          }
          summaryEl.appendChild(summaryDiv);
        }

        // ── Install guidance banner ───────────────────────────
        if (!allHealthy && health.install_command && bannerEl) {
          var banner = document.createElement('div');
          banner.className = 'install-banner';
          banner.innerHTML =
            '<span class="install-icon">📦</span>' +
            '<div class="install-body">' +
              '<div class="install-title">Missing dependencies detected</div>' +
              '<div class="install-desc">Install the missing packages to restore full functionality:</div>' +
              '<code class="install-cmd" id="install-cmd-copy" title="Click to copy">' +
                esc(health.install_command) +
                ' <span class="copy-hint">⧉ click to copy</span>' +
              '</code>' +
            '</div>';
          bannerEl.appendChild(banner);

          // Copy-to-clipboard on click
          var cmdEl = banner.querySelector('#install-cmd-copy');
          if (cmdEl) {
            cmdEl.addEventListener('click', function () {
              copyToClipboard(health.install_command);
              showToast('Install command copied to clipboard', 'success');
            });
          }
        }

        // ── Dependency cards ─────────────────────────────────
        keys.forEach(function (key) {
          var dep = deps[key];
          var isOk = dep.status === 'available';
          var isMissing = dep.status === 'missing' || dep.status === 'error';
          var hasFallback = !!dep.fallback;

          var cardClass = 'health-item';
          if (isOk) cardClass += ' ok';
          else if (hasFallback) cardClass += ' degraded';
          else cardClass += ' error';

          var card = document.createElement('div');
          card.className = cardClass;

          // Top row: icon + name + badge
          var iconChar = isOk ? '✓' : '⚠';
          var badgeClass = isOk ? 'badge-ok' : (hasFallback ? 'badge-warn' : 'badge-danger');
          var badgeText = isOk ? 'Available' : (ERROR_TYPE_LABELS[dep.error_type] || 'Unavailable');
          var versionHtml = dep.version ? '<div class="health-version">v' + esc(dep.version) + '</div>' : '';

          var html =
            '<div class="health-top">' +
              '<div class="health-icon">' + iconChar + '</div>' +
              '<div class="health-info">' +
                '<div class="health-name">' + esc(key) + '</div>' +
                versionHtml +
              '</div>' +
              '<span class="badge ' + badgeClass + '">' + esc(badgeText) + '</span>' +
            '</div>';

          // Feature tags
          if (dep.features && dep.features.length) {
            html += '<div class="health-features">';
            dep.features.forEach(function (f) {
              html += '<span class="health-feature-tag">' + esc(f) + '</span>';
            });
            html += '</div>';
          }

          // Error detail
          if (isMissing && dep.error) {
            html += '<div class="health-error">' + esc(dep.error) + '</div>';
          }

          // Fallback note
          if (isMissing && dep.fallback) {
            html += '<div class="health-fallback">↪ ' + esc(dep.fallback) + '</div>';
          }

          card.innerHTML = html;
          grid.appendChild(card);
        });

        var pqc = health.pqc_diagnostics;
        if (pqc) {
          var pqcOk = pqc.keys_loaded && pqc.signature_roundtrip_ok && pqc.ledger_verified && pqc.signatures_valid;
          var pqcResult = pqc.verification_result || {};
          var pqcCard = document.createElement('div');
          pqcCard.className = 'health-item ' + (pqcOk ? 'ok' : 'error');
          var pqcBadge = pqcOk ? 'Verified' : 'Needs Attention';
          var pqcPct = pqcResult.verification_percentage != null
            ? Number(pqcResult.verification_percentage).toFixed(1) + '%'
            : '0.0%';
          pqcCard.innerHTML =
            '<div class="health-top">' +
              '<div class="health-icon">' + (pqcOk ? '✓' : '!') + '</div>' +
              '<div class="health-info">' +
                '<div class="health-name">PQC Audit Ledger</div>' +
                '<div class="health-version">Lattice Signature Scheme: ' + esc(formatScheme(pqc.signature_scheme)) + '</div>' +
              '</div>' +
              '<span class="badge ' + (pqcOk ? 'badge-ok' : 'badge-danger') + '">' + esc(pqcBadge) + '</span>' +
            '</div>' +
            '<div class="health-features">' +
              '<span class="health-feature-tag">' + (pqc.keys_loaded ? '✓' : '!') + ' PQC Keys Loaded</span>' +
              '<span class="health-feature-tag">' + (pqc.ledger_verified ? '✓' : '!') + ' Ledger Verified</span>' +
              '<span class="health-feature-tag">' + (pqc.signatures_valid ? '✓' : '!') + ' Signatures Valid</span>' +
              '<span class="health-feature-tag">Verification ' + esc(pqcPct) + '</span>' +
              '<span class="health-feature-tag">Signer ' + esc(pqc.signer_id || 'audit-key-001') + '</span>' +
            '</div>' +
            (pqcResult.message ? '<div class="health-fallback">' + esc(pqcResult.message) + '</div>' : '');
          grid.appendChild(pqcCard);
        }

        // ── Populate Platform Info card ───────────────────────
        setText('sys-api-base', window.location.origin);
        setText('sys-model', health.model_version || 'fraud_model_v1.0');

        var dbPath = health.db_path || '';
        var dbLabel = dbPath
          ? (dbPath.match(/\.sqlite|fraudsniffer\.db/i) ? 'SQLite' : dbPath)
          : '—';
        setText('sys-db', dbLabel);

        setText('sys-storage',
          health.data_dir
            ? 'Local Filesystem + SHA3 Audit Store'
            : '—'
        );
      })
      .catch(function () {
        grid.innerHTML =
          '<div class="text-muted">Unable to fetch system health. ' +
          'The /api/health endpoint may not be available.</div>';
      });
  }

  /**
   * Fetch and display platform usage statistics (metric counts).
   */
  function loadStats() {
    api('GET', '/api/stats')
      .then(function (stats) {
        setText('metric-docs-processed', stats.documents_processed != null ? stats.documents_processed.toLocaleString() : '0');
        setText('metric-audit-events', stats.audit_events != null ? stats.audit_events.toLocaleString() : '0');
        setText('metric-duplicate-matches', stats.duplicate_matches != null ? stats.duplicate_matches.toLocaleString() : '0');
        setText('metric-cross-document-templates', stats.cross_document_templates != null ? stats.cross_document_templates.toLocaleString() : '0');
        setText('metric-registry-verifications', stats.registry_verifications != null ? stats.registry_verifications.toLocaleString() : '0');
      })
      .catch(function (err) {
        console.error('Failed to load system stats:', err);
      });
  }

  /* ───────────────────────── 14. Review Submission ──────────────── */

  function submitReview() {
    if (!currentDocId) {
      showToast('No document loaded — analyze or look up a document first', 'error');
      return;
    }

    var notes   = $('review-notes');
    var by      = $('review-by');
    var verdict = $('review-verdict');
    var btn     = $('review-btn');

    var payload = {
      review_notes:  notes   ? notes.value   : '',
      reviewed_by:   by      ? by.value      : '',
      manual_verdict: verdict ? verdict.value : ''
    };

    if (!payload.reviewed_by) {
      showToast('Enter your name before submitting a review', 'error');
      return;
    }

    if (!payload.manual_verdict) {
      showToast('Select a verdict (Approved / Rejected / Escalate) before submitting', 'error');
      return;
    }

    btn.disabled = true;
    var origText = btn.textContent;
    btn.textContent = 'Saving…';

    api('POST', '/api/reviews/' + encodeURIComponent(currentDocId), payload)
      .then(function (res) {
        btn.disabled = false;
        btn.textContent = origText;
        showToast('Review saved — verdict: ' + payload.manual_verdict, 'success');
        renderPqcAuditTrail(currentDocId);
        // Mark dataset as stale so it reloads with updated metrics
        datasetStale = true;
        // Update the verdict badge on the current document's history row (if visible)
        var verdictBadge = document.querySelector('.link-doc[data-id="' + currentDocId + '"]');
        if (verdictBadge) {
          var row = verdictBadge.closest('tr');
          if (row) {
            var cells = row.querySelectorAll('td');
            // The human verdict cell is the 6th column (index 5) in the dataset table
            if (cells.length > 5) {
              var cls = payload.manual_verdict === 'APPROVED' ? 'badge-ok' :
                        payload.manual_verdict === 'REJECTED' ? 'badge-danger' : 'badge-warn';
              cells[5].innerHTML = '<span class="badge ' + cls + '">' + esc(payload.manual_verdict) + '</span>';
            }
          }
        }
      })
      .catch(function (err) {
        btn.disabled = false;
        btn.textContent = origText;
        showToast(err.message || 'Review failed', 'error');
      });
  }

  /* ───────────────────────── 15. Self-Test ──────────────────────── */

  /**
   * Programmatic self-test: create a minimal text file, submit it,
   * and verify the response contains the expected fields.
   */
  function runSelfTest() {
    var output = $('self-test-output');
    var btn    = $('run-self-test');
    if (!output) return;

    btn.disabled = true;
    output.textContent = 'Running self-test…\n';

    // Build a tiny synthetic payload
    var blob = new Blob(
      ['FraudSniffer self-test payload — ' + new Date().toISOString()],
      { type: 'text/plain' }
    );
    var testFile = new File([blob], 'self_test.txt', { type: 'text/plain' });
    var form = new FormData();
    form.append('file', testFile);
    form.append('metadata', JSON.stringify({
      doc_type: 'PAYSLIP',
      job_title: 'Self Test',
      loan_amount: 100000,
      city: 'Mumbai'
    }));

    var start = performance.now();

    api('POST', '/api/documents/submit', form, true)
      .then(function (data) {
        var elapsed = (performance.now() - start).toFixed(0);
        var lines = [];
        lines.push('✓  Self-test completed in ' + elapsed + ' ms');
        lines.push('');

        // Verify required fields
        var required = [
          'doc_id', 'fraud_score', 'state', 'ui_state_label',
          'processing_time_ms', 'feature_status', 'confidence_breakdown',
          'seal_evidence', 'pipeline_state'
        ];
        var missing = [];
        required.forEach(function (f) {
          if (data[f] === undefined || data[f] === null) missing.push(f);
        });

        if (missing.length) {
          lines.push('⚠  Missing fields: ' + missing.join(', '));
        } else {
          lines.push('✓  All required fields present');
        }

        lines.push('   doc_id:           ' + data.doc_id);
        lines.push('   fraud_score:      ' + data.fraud_score);
        lines.push('   state:            ' + data.state);
        lines.push('   pipeline_state:   ' + data.pipeline_state);
        lines.push('   model_version:    ' + data.model_version);
        lines.push('   processing_time:  ' + data.processing_time_ms + ' ms');
        lines.push('   reason_codes:     ' + (data.risk_decision_reason_codes || []).join(', '));
        lines.push('');
        lines.push('✓  API is operational');

        output.textContent = lines.join('\n');
        btn.disabled = false;
        showToast('Self-test passed', 'success');
      })
      .catch(function (err) {
        output.textContent = '✗  Self-test FAILED\n\n   ' + (err.message || err);
        btn.disabled = false;
        showToast('Self-test failed', 'error');
      });
  }

  /* ── Interactive Forensic Workspace ───────────────────────── */

  function forensicsPayload(data) {
    var advanced = data.advanced_forensics || {};
    return {
      advanced: advanced,
      visual: advanced.visual || {},
      pdf: advanced.pdf || {},
      adversarial: advanced.adversarial_text || {}
    };
  }

  function getWorkspacePages(data) {
    var payload = forensicsPayload(data);
    var seen = {};
    var pages = [];

    function addPage(value) {
      var page = parseInt(value, 10);
      if (!page || page < 1 || seen[page]) return;
      seen[page] = true;
      pages.push(page);
    }

    (payload.pdf.pages || []).forEach(function (item) { addPage(item.page); });
    ((payload.visual.ela || {}).pages || []).forEach(function (item) { addPage(item.page); });
    addPage(1);

    return pages.sort(function (a, b) { return a - b; });
  }

  function getWorkspacePageInfo(data, pageNumber) {
    var pages = (forensicsPayload(data).pdf.pages || []);
    for (var i = 0; i < pages.length; i += 1) {
      if (parseInt(pages[i].page, 10) === pageNumber) return pages[i];
    }
    return null;
  }

  function getElaPage(data, pageNumber) {
    var pages = ((forensicsPayload(data).visual.ela || {}).pages || []);
    for (var i = 0; i < pages.length; i += 1) {
      if (parseInt(pages[i].page, 10) === pageNumber) return pages[i];
    }
    return null;
  }

  function bindForensicWorkspaceControls() {
    var prev = $('workspace-prev');
    var next = $('workspace-next');
    var opacity = $('workspace-ela-opacity');
    var fontToggle = $('workspace-font-toggle');
    var hiddenToggle = $('workspace-hidden-toggle');

    if (prev) {
      prev.onclick = function () {
        var index = forensicWorkspaceState.pages.indexOf(forensicWorkspaceState.page);
        if (index > 0) {
          forensicWorkspaceState.page = forensicWorkspaceState.pages[index - 1];
          updateForensicWorkspace();
        }
      };
    }
    if (next) {
      next.onclick = function () {
        var index = forensicWorkspaceState.pages.indexOf(forensicWorkspaceState.page);
        if (index < forensicWorkspaceState.pages.length - 1) {
          forensicWorkspaceState.page = forensicWorkspaceState.pages[index + 1];
          updateForensicWorkspace();
        }
      };
    }
    if (opacity) {
      opacity.oninput = function () { updateElaOpacity(); };
    }
    if (fontToggle) {
      fontToggle.onchange = function () { renderForensicBoxes(); };
    }
    if (hiddenToggle) {
      hiddenToggle.onchange = function () { renderForensicBoxes(); };
    }
  }

  function renderForensicWorkspace(data) {
    var workspace = $('forensic-workspace');
    if (!workspace || !data || !data.doc_id) return;

    var pages = getWorkspacePages(data);
    forensicWorkspaceState = {
      data: data,
      page: pages[0] || 1,
      pages: pages,
      totalPages: pages.length || 1
    };
    bindForensicWorkspaceControls();
    updateForensicWorkspace();
  }

  function updateElaOpacity() {
    var opacity = $('workspace-ela-opacity');
    var value = $('workspace-ela-value');
    var elaImage = $('workspace-ela-image');
    var pct = opacity ? parseInt(opacity.value || '0', 10) : 0;
    if (value) value.textContent = pct + '%';
    if (elaImage) elaImage.style.opacity = String(Math.max(0, Math.min(100, pct)) / 100);
  }

  function updateForensicWorkspace() {
    var data = forensicWorkspaceState.data;
    if (!data || !data.doc_id) return;

    var page = forensicWorkspaceState.page || 1;
    var pageIndex = forensicWorkspaceState.pages.indexOf(page);
    var pageLabel = $('workspace-page-label');
    var prev = $('workspace-prev');
    var next = $('workspace-next');
    var empty = $('workspace-empty');
    var baseImage = $('workspace-base-image');
    var elaImage = $('workspace-ela-image');

    if (pageLabel) {
      pageLabel.textContent = 'Page ' + page + ' / ' + forensicWorkspaceState.totalPages;
    }
    if (prev) prev.disabled = pageIndex <= 0;
    if (next) next.disabled = pageIndex >= forensicWorkspaceState.pages.length - 1;
    if (empty) empty.classList.add('hidden');
    if (!baseImage || !elaImage) return;

    var baseSrc = '/api/documents/' + encodeURIComponent(data.doc_id) + '/page/' + encodeURIComponent(page);
    baseImage.onload = function () { renderForensicBoxes(); };
    baseImage.onerror = function () {
      renderForensicBoxes();
      showToast('Document page preview could not be rendered', 'error');
    };
    if (baseImage.getAttribute('data-src') !== baseSrc) {
      baseImage.setAttribute('data-src', baseSrc);
      baseImage.src = baseSrc;
    } else if (baseImage.complete) {
      renderForensicBoxes();
    }

    var elaPage = getElaPage(data, page);
    if (elaPage && elaPage.artifact_url) {
      elaImage.src = elaPage.artifact_url;
      elaImage.classList.remove('hidden');
    } else {
      elaImage.removeAttribute('src');
      elaImage.classList.add('hidden');
    }
    updateElaOpacity();
  }

  function rectTitleFor(kind, item) {
    if (kind === 'font') {
      return 'Font anomaly: ' + (item.text || 'span') +
        ' | Font ' + (item.font || 'unknown') +
        ' | Dominant ' + (item.dominant_font || 'unknown') +
        ' | Size ' + (item.size || 'n/a') +
        ' vs median ' + (item.median_size || 'n/a');
    }
    return 'Hidden text span: ' + (item.text || 'invisible text') +
      ' | Font ' + (item.font || 'unknown') +
      ' | Size ' + (item.size || 'n/a');
  }

  function addOverlayRect(svg, bbox, className, titleText) {
    if (!bbox || bbox.length < 4) return;
    var x0 = Number(bbox[0]);
    var y0 = Number(bbox[1]);
    var x1 = Number(bbox[2]);
    var y1 = Number(bbox[3]);
    if (![x0, y0, x1, y1].every(isFinite) || x1 <= x0 || y1 <= y0) return;

    var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', x0);
    rect.setAttribute('y', y0);
    rect.setAttribute('width', x1 - x0);
    rect.setAttribute('height', y1 - y0);
    rect.setAttribute('class', className);
    rect.setAttribute('tabindex', '0');
    var title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = titleText;
    rect.appendChild(title);
    svg.appendChild(rect);
  }

  function renderForensicBoxes() {
    var data = forensicWorkspaceState.data;
    var svg = $('workspace-svg');
    var baseImage = $('workspace-base-image');
    if (!data || !svg || !baseImage) return;

    var page = forensicWorkspaceState.page || 1;
    var info = getWorkspacePageInfo(data, page) || {};
    var width = Number(info.width || baseImage.naturalWidth || 1);
    var height = Number(info.height || baseImage.naturalHeight || 1);
    svg.innerHTML = '';
    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    svg.setAttribute('preserveAspectRatio', 'none');

    var payload = forensicsPayload(data);
    var fontToggle = $('workspace-font-toggle');
    var hiddenToggle = $('workspace-hidden-toggle');
    var fontItems = (((payload.pdf.font_audit || {}).anomalies || []));
    var hiddenItems = (((payload.adversarial.hidden_text || {}).hidden_spans || payload.pdf.hidden_text_spans || []));

    if (!fontToggle || fontToggle.checked) {
      fontItems.forEach(function (item) {
        if (parseInt(item.page || 1, 10) === page) {
          addOverlayRect(svg, item.bbox, 'workspace-box workspace-box-font', rectTitleFor('font', item));
        }
      });
    }
    if (!hiddenToggle || hiddenToggle.checked) {
      hiddenItems.forEach(function (item) {
        if (parseInt(item.page || 1, 10) === page) {
          addOverlayRect(svg, item.bbox, 'workspace-box workspace-box-hidden', rectTitleFor('hidden', item));
        }
      });
    }
  }

  /* ── Advanced Forensics Renderer ──────────────────────────── */

  function renderAdvancedForensics(data) {
    var container = $('advanced-forensics');
    if (!container) return;
    container.innerHTML = '';

    var advanced = data.advanced_forensics || {};
    var visual = advanced.visual || {};
    var ela = visual.ela || {};
    var pdf = advanced.pdf || {};
    var adversarial = advanced.adversarial_text || {};
    var matches = data.similarity_matches || [];
    var elaPages = ela.pages || [];
    var triggered = [];

    if (ela.triggered) triggered.push('ELA');
    if (pdf.font_audit && pdf.font_audit.triggered) triggered.push('PDF fonts');
    if (pdf.object_audit && pdf.object_audit.triggered) triggered.push('PDF objects');
    if (adversarial.hidden_text && adversarial.hidden_text.triggered) triggered.push('Hidden text');
    if (adversarial.raw_ocr_divergence && adversarial.raw_ocr_divergence.triggered) triggered.push('Raw/OCR');
    if (matches.length) triggered.push('Similarity');

    var header = document.createElement('div');
    header.className = 'forensics-header';
    header.innerHTML =
      '<h3>Advanced Forensics</h3>' +
      '<span class="forensics-badge ' + (triggered.length ? 'badge-danger' : 'badge-ok') + '">' +
      (triggered.length
        ? triggered.length + ' signal' + (triggered.length > 1 ? 's' : '')
        : (elaPages.length ? 'Clean, heatmap generated' : 'Clean')) +
      '</span>';
    container.appendChild(header);

    var grid = document.createElement('div');
    grid.className = 'forensics-grid';
    container.appendChild(grid);

    var elaCard = document.createElement('div');
    elaCard.className = 'forensics-card';
    var elaScore = ela.max_score != null ? Number(ela.max_score) : 0;
    var heatmap = elaPages[0] || {};
    var thresholdPct = ela.threshold != null ? (Number(ela.threshold) * 100).toFixed(1) + '%' : 'N/A';
    elaCard.innerHTML =
      '<div class="forensics-card-head">' +
        '<span>Error Level Analysis</span>' +
        '<strong class="' + (ela.triggered ? 'text-danger' : 'text-success') + '">' +
          (ela.triggered ? 'Triggered ' : 'Clean ') + (elaScore * 100).toFixed(1) + '%' +
        '</strong>' +
      '</div>' +
      '<p>' + esc(ela.detail || 'No ELA data available.') + ' Threshold: ' + esc(thresholdPct) + '.</p>' +
      (heatmap.artifact_url
        ? '<img class="forensics-heatmap" src="' + esc(heatmap.artifact_url) + '" alt="ELA heatmap">'
        : '<div class="forensics-empty">No heatmap artifact</div>');
    grid.appendChild(elaCard);

    var fontAudit = pdf.font_audit || {};
    var objectAudit = pdf.object_audit || {};
    var pdfCard = document.createElement('div');
    pdfCard.className = 'forensics-card';
    var fontRows = (fontAudit.anomalies || []).slice(0, 4).map(function (item) {
      return '<li><strong>' + esc(item.font || 'Unknown') + '</strong>: ' + esc(item.text || '') + '</li>';
    }).join('');
    var objectRows = (objectAudit.anomalies || []).slice(0, 3).map(function (item) {
      return '<li>' + esc(item) + '</li>';
    }).join('');
    pdfCard.innerHTML =
      '<div class="forensics-card-head">' +
        '<span>PDF Structure Audit</span>' +
        '<strong class="' + ((fontAudit.triggered || objectAudit.triggered) ? 'text-danger' : 'text-success') + '">' +
          ((fontAudit.triggered || objectAudit.triggered) ? 'Flagged' : 'Pass') +
        '</strong>' +
      '</div>' +
      '<p>Dominant font: <span class="text-mono">' + esc(fontAudit.dominant_font || 'N/A') + '</span></p>' +
      (fontRows ? '<ul class="forensics-list">' + fontRows + '</ul>' : '<div class="forensics-empty">No suspicious font spans</div>') +
      (objectRows ? '<ul class="forensics-list">' + objectRows + '</ul>' : '');
    grid.appendChild(pdfCard);

    var hidden = adversarial.hidden_text || {};
    var divergence = adversarial.raw_ocr_divergence || {};
    var advCard = document.createElement('div');
    advCard.className = 'forensics-card';
    var extraTokens = (divergence.extra_raw_tokens || []).slice(0, 8).join(', ');
    advCard.innerHTML =
      '<div class="forensics-card-head">' +
        '<span>Adversarial Text Defense</span>' +
        '<strong class="' + ((hidden.triggered || divergence.triggered) ? 'text-danger' : 'text-success') + '">' +
          ((hidden.triggered || divergence.triggered) ? 'Flagged' : 'Pass') +
        '</strong>' +
      '</div>' +
      '<div class="forensics-kv"><span>Hidden spans</span><strong>' + esc(hidden.hidden_span_count || 0) + '</strong></div>' +
      '<div class="forensics-kv"><span>Hidden Unicode</span><strong>' + esc(hidden.hidden_unicode_count || 0) + '</strong></div>' +
      '<div class="forensics-kv"><span>Raw/visual distance</span><strong>' + ((Number(divergence.distance || 0)) * 100).toFixed(1) + '%</strong></div>' +
      (extraTokens ? '<p class="text-sm text-muted">Extra raw tokens: ' + esc(extraTokens) + '</p>' : '');
    grid.appendChild(advCard);

    var simCard = document.createElement('div');
    simCard.className = 'forensics-card';
    var matchRows = matches.slice(0, 5).map(function (match) {
      return '<li>' +
        '<span class="text-mono">' + esc(match.doc_id || 'unknown') + '</span>' +
        '<strong>' + (Number(match.score || 0) * 100).toFixed(1) + '%</strong>' +
        '</li>';
    }).join('');
    simCard.innerHTML =
      '<div class="forensics-card-head">' +
        '<span>Cross-Document Reuse <span style="cursor:help;" title="Checks for similar structural layout templates (layout, fonts, skeleton structure). Shared layout templates suggest document generation tools.">ⓘ</span></span>' +
        '<strong class="' + (matches.length ? 'text-danger' : 'text-success') + '">' +
          (matches.length ? matches.length + ' match' + (matches.length > 1 ? 'es' : '') : 'None') +
        '</strong>' +
      '</div>' +
      (matchRows ? '<ul class="forensics-match-list">' + matchRows + '</ul>' : '<div class="forensics-empty">No reused template matches</div>');
    grid.appendChild(simCard);
  }

  /* ── Behavioral Inspector Renderer ────────────────────────── */

  /**
   * Renders the Behavioral Analytics Inspector panel.
   * Shows telemetry data (fingerprint, IP, timezone, etc.) and
   * any behavioral risk alerts triggered by the backend.
   */
  function renderBehavioralInspector(data) {
    var container = $('behavioral-inspector');
    if (!container) return;
    container.innerHTML = '';

    var alerts = data.behavioral_risks || [];
    var docId = data.doc_id;

    // ── Header ─────────────────────────────────────────────────
    var header = document.createElement('div');
    header.className = 'behavioral-header';
    header.innerHTML =
      '<h3>' +
      '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' +
      '</svg>' +
      ' Behavioral Analytics Inspector' +
      '</h3>' +
      '<span class="behavioral-badge ' + (alerts.length ? 'badge-danger' : 'badge-ok') + '">' +
      (alerts.length ? alerts.length + ' alert' + (alerts.length > 1 ? 's' : '') : 'Clean') +
      '</span>';
    container.appendChild(header);

    // ── Telemetry Grid (fetched async) ─────────────────────────
    var telGrid = document.createElement('div');
    telGrid.className = 'telemetry-grid';
    telGrid.innerHTML = '<div class="telemetry-loading">Loading telemetry data…</div>';
    container.appendChild(telGrid);

    // Fetch telemetry details from the API
    api('GET', '/api/documents/' + encodeURIComponent(docId) + '/telemetry')
      .then(function (tel) {
        telGrid.innerHTML = '';
        var fields = [
          { label: 'Canvas Fingerprint', value: tel.canvas_fingerprint, mono: true },
          { label: 'IP Address', value: tel.ip_address },
          { label: 'Timezone', value: tel.timezone },
          { label: 'Language', value: tel.language },
          { label: 'Screen Resolution', value: tel.screen_resolution },
          { label: 'Platform', value: tel.platform },
          { label: 'User Agent', value: (tel.user_agent || '').substring(0, 80) },
          { label: 'Keystroke Duration', value: tel.keystroke_duration_ms + ' ms' },
          { label: 'Submission Duration', value: tel.submission_duration_ms + ' ms' },
          { label: 'Device Submissions (total)', value: tel.device_total_submissions },
          { label: 'VPN Detected', value: tel.vpn_detected ? 'Yes ⚠️' : 'No' },
          { label: 'Tor Detected', value: tel.tor_detected ? 'Yes ⚠️' : 'No' },
        ];
        fields.forEach(function (f) {
          var row = document.createElement('div');
          row.className = 'telemetry-row';
          row.innerHTML =
            '<span class="telemetry-label">' + esc(f.label) + '</span>' +
            '<span class="telemetry-value' + (f.mono ? ' mono' : '') + '">' +
            esc(f.value || '—') +
            '</span>';
          telGrid.appendChild(row);
        });

        // Canvas fingerprint copy button
        if (tel.canvas_fingerprint) {
          var copyRow = document.createElement('div');
          copyRow.className = 'telemetry-row telemetry-copy-row';
          copyRow.innerHTML = '<button class="btn-small" id="copy-fingerprint">Copy Fingerprint</button>';
          telGrid.appendChild(copyRow);
          var cpBtn = document.getElementById('copy-fingerprint');
          if (cpBtn) {
            cpBtn.addEventListener('click', function () {
              copyToClipboard(tel.canvas_fingerprint);
            });
          }
        }
      })
      .catch(function () {
        telGrid.innerHTML = '<div class="telemetry-empty">No telemetry data available</div>';
      });

    // ── Behavioral Alerts ──────────────────────────────────────
    if (alerts.length) {
      var alertSection = document.createElement('div');
      alertSection.className = 'behavioral-alerts';
      alertSection.innerHTML = '<h4>⚠ Behavioral Risk Alerts</h4>';

      alerts.forEach(function (alert) {
        var severityCls = alert.severity === 'HIGH' ? 'alert-high'
          : alert.severity === 'MEDIUM' ? 'alert-medium' : 'alert-low';

        var card = document.createElement('div');
        card.className = 'behavioral-alert-card ' + severityCls;
        card.innerHTML =
          '<div class="alert-header">' +
          '<span class="alert-rule">' + esc(REASON_LABELS[alert.rule] || alert.rule) + '</span>' +
          '<span class="alert-severity badge-' + alert.severity.toLowerCase() + '">' + esc(alert.severity) + '</span>' +
          '<span class="alert-score">' + (alert.score * 100).toFixed(1) + '%</span>' +
          '</div>' +
          '<div class="alert-detail">' + esc(alert.detail) + '</div>';

        // Expandable evidence
        if (alert.evidence && Object.keys(alert.evidence).length) {
          var evidenceBtn = document.createElement('button');
          evidenceBtn.className = 'btn-small btn-evidence';
          evidenceBtn.textContent = 'Show Evidence';
          var evidenceDiv = document.createElement('pre');
          evidenceDiv.className = 'alert-evidence hidden';
          evidenceDiv.textContent = JSON.stringify(alert.evidence, null, 2);
          evidenceBtn.addEventListener('click', function () {
            evidenceDiv.classList.toggle('hidden');
            evidenceBtn.textContent = evidenceDiv.classList.contains('hidden')
              ? 'Show Evidence' : 'Hide Evidence';
          });
          card.appendChild(evidenceBtn);
          card.appendChild(evidenceDiv);
        }

        alertSection.appendChild(card);
      });
      container.appendChild(alertSection);
    } else {
      var cleanMsg = document.createElement('div');
      cleanMsg.className = 'behavioral-clean';
      cleanMsg.innerHTML =
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
        '<polyline points="20 6 9 17 4 12"/>' +
        '</svg>' +
        ' No behavioral anomalies detected';
      container.appendChild(cleanMsg);
    }
  }

  /* ── AI Copilot Helpers ── */
  var currentAiNotesDraft = '';

  function loadAIAssistant(docId) {
    api('GET', '/api/documents/' + encodeURIComponent(docId) + '/assistant/chat')
      .then(function (history) {
        var chatHistory = $('ai-chat-history');
        if (!chatHistory) return;
        chatHistory.innerHTML = '<div class="chat-bubble assistant"><p class="chat-message-text">Hello! I am your AI Copilot. Ask me questions about this document or click a triggered rule\'s <strong>[Explain]</strong> button to analyze specific anomalies.</p></div>';
        
        (history || []).forEach(function (msg) {
          appendChatBubble(msg.role, msg.message);
        });
      });
      
    var container = $('ai-report-container');
    if (container) {
      container.innerHTML = '<p class="text-muted text-sm">Click "Generate AI Report" to synthesize case findings.</p>';
    }
    var notesFooter = $('ai-notes-draft-footer');
    if (notesFooter) notesFooter.classList.add('hidden');
    currentAiNotesDraft = '';
  }

  function generateAIReport() {
    if (!currentDocId) return;
    var container = $('ai-report-container');
    if (!container) return;
    container.innerHTML = '<div style="display:flex; justify-content:center; align-items:center; padding: 20px;"><span class="spinner"></span><span style="margin-left:8px; color:var(--text-secondary)">Generating AI report...</span></div>';
    
    api('POST', '/api/documents/' + encodeURIComponent(currentDocId) + '/assistant/report')
      .then(function (res) {
        container.innerHTML = '<div class="ai-report-text">' + formatMarkdown(res.summary) + '</div>';
        currentAiNotesDraft = res.draft_notes;
        var notesFooter = $('ai-notes-draft-footer');
        if (notesFooter) notesFooter.classList.remove('hidden');
      })
      .catch(function () {
        container.innerHTML = '<p class="text-danger text-sm">Failed to generate AI report. Please check if Ollama or the server is running.</p>';
      });
  }

  function explainRule(docId, ruleCode) {
    var chatHistory = $('ai-chat-history');
    if (!chatHistory) return;
    
    var copilotSection = $('ai-copilot-section');
    if (copilotSection) {
      copilotSection.scrollIntoView({ behavior: 'smooth' });
    }

    appendChatBubble('user', 'Explain finding: ' + ruleCode);
    var typingBubble = appendChatBubble('assistant', '<span class="typing-indicator"><span></span><span></span><span></span></span>');

    api('POST', '/api/documents/' + encodeURIComponent(docId) + '/assistant/chat?explain_rule=' + encodeURIComponent(ruleCode), {})
      .then(function(res) {
        if (typingBubble) typingBubble.remove();
        appendChatBubble('assistant', res.message);
      })
      .catch(function() {
        if (typingBubble) typingBubble.remove();
        appendChatBubble('assistant', 'Error: Unable to fetch explanation for ' + ruleCode);
      });
  }

  function sendChatMessage() {
    if (!currentDocId) return;
    var input = $('ai-chat-input');
    if (!input || !input.value.trim()) return;
    var text = input.value.trim();
    input.value = '';
    
    appendChatBubble('user', text);
    var typingBubble = appendChatBubble('assistant', '<span class="typing-indicator"><span></span><span></span><span></span></span>');
    
    api('POST', '/api/documents/' + encodeURIComponent(currentDocId) + '/assistant/chat', { message: text })
      .then(function (res) {
        if (typingBubble) typingBubble.remove();
        appendChatBubble('assistant', res.message);
      })
      .catch(function () {
        if (typingBubble) typingBubble.remove();
        appendChatBubble('assistant', 'Error: Unable to reach AI Copilot.');
      });
  }

  function appendChatBubble(role, htmlContent) {
    var chatHistory = $('ai-chat-history');
    if (!chatHistory) return null;
    
    var div = document.createElement('div');
    div.className = 'chat-bubble ' + role;
    
    var p = document.createElement('p');
    p.className = 'chat-message-text';
    p.innerHTML = htmlContent;
    
    div.appendChild(p);
    chatHistory.appendChild(div);
    chatHistory.scrollTop = chatHistory.scrollHeight;
    return div;
  }

  function applyAIDraftNotes() {
    var textarea = $('review-notes');
    if (textarea && currentAiNotesDraft) {
      textarea.value = currentAiNotesDraft;
      showToast('AI drafted review notes applied!', 'success');
    }
  }

  function formatMarkdown(text) {
    if (!text) return '';
    var processed = text.replace(/^(?:###|#+)\s*(.*?)(?:\r?\n|$)/gm, '<h4 style="margin: 12px 0 6px 0; font-size: 14px; font-weight: 600; color: var(--text);">$1</h4>');
    processed = processed.replace(/^\s*(?:[-\*•])\s*(.*?)(?:\r?\n|$)/gm, '• $1\n');
    processed = processed.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    var html = processed.replace(/\r?\n/g, '<br>');
    return html;
  }

  /* ───────────────────────── 16. Initialisation ─────────────────── */

  document.addEventListener('DOMContentLoaded', function () {

    // Initialize telemetry collector
    if (typeof FraudSnifferTelemetry !== 'undefined') {
      FraudSnifferTelemetry.init();
    }

    // Tabs
    initTabs();

    // Dropzone / file input
    initDropzone();

    // Upload form submit
    var form = $('upload-form');
    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        submitDocument();
      });
    }
    var submitBtn = $('submit-btn');
    if (submitBtn && !form) {
      // Fallback: if there's no <form>, bind directly
      submitBtn.addEventListener('click', function (e) {
        e.preventDefault();
        submitDocument();
      });
    }

    // Lookup button
    var lookupBtn = $('lookup-btn');
    if (lookupBtn) {
      lookupBtn.addEventListener('click', function () {
        var input = $('lookup-id');
        loadDocument(input ? input.value.trim() : '');
      });
    }
    // Also allow Enter in the lookup input
    var lookupInput = $('lookup-id');
    if (lookupInput) {
      lookupInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          loadDocument(lookupInput.value.trim());
        }
      });
    }

    // Advanced JSON toggle
    var advToggle = $('advanced-toggle');
    if (advToggle) {
      advToggle.addEventListener('click', function () {
        advancedMode = !advancedMode;
        var section = $('advanced-section');
        if (section) {
          section.classList.toggle('hidden', !advancedMode);
        }
        advToggle.textContent = advancedMode ? 'Hide JSON Editor' : 'Advanced: Raw JSON';
      });
    }

    // Review submit
    var reviewBtn = $('review-btn');
    if (reviewBtn) {
      reviewBtn.addEventListener('click', function (e) {
        e.preventDefault();
        submitReview();
      });
    }

    // Self-test button
    var selfTestBtn = $('run-self-test');
    if (selfTestBtn) {
      selfTestBtn.addEventListener('click', function () {
        runSelfTest();
      });
    }

    // History refresh button
    var refreshBtn = $('refresh-history');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', function () {
        loadHistory();
      });
    }

    // Dataset refresh button
    var refreshDatasetBtn = $('refresh-dataset');
    if (refreshDatasetBtn) {
      refreshDatasetBtn.addEventListener('click', function () {
        loadDataset();
      });
    }

    // Health refresh button
    var refreshHealthBtn = $('refresh-health');
    if (refreshHealthBtn) {
      refreshHealthBtn.addEventListener('click', function () {
        loadHealth();
        showToast('Refreshing dependency status…', 'info');
      });
    }

    // Doc-ID copy handler
    var copyBtn = $('copy-doc-id');
    if (copyBtn) {
      copyBtn.addEventListener('click', function (e) {
        e.preventDefault();
        copyToClipboard(currentDocId);
      });
    }

    // Export JSON handler
    var exportBtn = $('export-json');
    if (exportBtn) {
      exportBtn.addEventListener('click', function () {
        var jsonOut = $('json-output');
        if (!jsonOut || !jsonOut.textContent || jsonOut.textContent === '{}') {
          showToast('No results to export', 'error');
          return;
        }
        var blob = new Blob([jsonOut.textContent], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = (currentDocId || 'fraudsniffer_result') + '.json';
        a.click();
        URL.revokeObjectURL(url);
        showToast('JSON exported', 'success');
      });
    }

    var exportAuditBtn = $('export-audit-report');
    if (exportAuditBtn) {
      exportAuditBtn.addEventListener('click', function () {
        exportAuditReport();
      });
    }

    // Clear file button
    var clearBtn = $('clear-file');
    if (clearBtn) {
      clearBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        selectedFile = null;
        var input = $('file-input');
        if (input) input.value = '';
        var zone = $('dropzone');
        if (zone) zone.classList.remove('has-file');
      });
    }

    // Test scenario buttons
    var testClean = $('test-text-clean');
    if (testClean) {
      testClean.addEventListener('click', function () {
        var blob = new Blob(
          ['Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 48000\nDate: 2026-05-01\nDesignation: Software Engineer'],
          { type: 'text/plain' }
        );
        selectedFile = new File([blob], 'clean_payslip.txt', { type: 'text/plain' });
        var zone = $('dropzone');
        var label = $('file-name');
        if (zone) zone.classList.add('has-file');
        if (label) label.textContent = 'clean_payslip.txt';
        var jobInput = $('meta-job');
        if (jobInput) jobInput.value = 'Software Engineer';
        showToast('Clean test document loaded — click Analyze', 'info');
      });
    }

    var testEmpty = $('test-text-empty');
    if (testEmpty) {
      testEmpty.addEventListener('click', function () {
        var blob = new Blob(['This document has no payslip fields.'], { type: 'text/plain' });
        selectedFile = new File([blob], 'empty_doc.txt', { type: 'text/plain' });
        var zone = $('dropzone');
        var label = $('file-name');
        if (zone) zone.classList.add('has-file');
        if (label) label.textContent = 'empty_doc.txt';
        showToast('Empty test document loaded — click Analyze', 'info');
      });
    }

    var testMismatch = $('test-mismatch');
    if (testMismatch) {
      testMismatch.addEventListener('click', function () {
        var blob = new Blob(
          ['Employee Name: Rahul Verma\nEmployer: Skyline Infrastructure\nSalary: 475000\nDesignation: Junior Sales Executive'],
          { type: 'text/plain' }
        );
        selectedFile = new File([blob], 'mismatch_payslip.txt', { type: 'text/plain' });
        var zone = $('dropzone');
        var label = $('file-name');
        if (zone) zone.classList.add('has-file');
        if (label) label.textContent = 'mismatch_payslip.txt';
        // Set mismatching metadata
        var empInput = $('meta-employee');
        var jobInput = $('meta-job');
        if (empInput) empInput.value = 'Someone Else';
        if (jobInput) jobInput.value = 'Software Engineer';
        showToast('Mismatch test loaded — metadata intentionally conflicts', 'info');
      });
    }

    // ── Initial data loads ──────────────────────────────────────
    // Determine starting tab from URL hash
    var hash = window.location.hash.replace('#', '') || 'analyze';
    activateTab(hash);

    // Pre-load history and health in background regardless of tab
    loadHistory();
    loadHealth();
    loadStats();

    // AI Copilot Listeners
    var generateReportBtn = $('generate-ai-report-btn');
    if (generateReportBtn) {
      generateReportBtn.addEventListener('click', function () {
        generateAIReport();
      });
    }

    var applyNotesBtn = $('apply-ai-notes-btn');
    if (applyNotesBtn) {
      applyNotesBtn.addEventListener('click', function () {
        applyAIDraftNotes();
      });
    }

    var sendChatBtn = $('ai-chat-send-btn');
    if (sendChatBtn) {
      sendChatBtn.addEventListener('click', function () {
        sendChatMessage();
      });
    }

    var chatInput = $('ai-chat-input');
    if (chatInput) {
      chatInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          sendChatMessage();
        }
      });
    }
  });

})();
