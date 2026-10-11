/**
 * ProofChain Registry — Interactive Application JavaScript
 * ========================================================
 * Spline 3D UI controls, Deterministic Canonical Hashing
 * (json-sorted-v1 RFC 8785 & raw-bytes-v1), RFC 6962 Leaf Hashes,
 * and live search/filtering.
 */

(function () {
  'use strict';

  // ─── Toast Notification Helper ──────────────────────────────────
  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `
      <i data-lucide="check-circle" style="width:16px;height:16px;color:var(--color-accent-cyan);"></i>
      <span>${message}</span>
    `;
    container.appendChild(toast);

    if (window.lucide) window.lucide.createIcons();

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  // ─── Clipboard Copy Event Handlers ──────────────────────────────
  document.addEventListener('click', function (e) {
    const copyBtn = e.target.closest('[data-copy], .btn-copy-hash');
    if (!copyBtn) return;

    const hashToCopy = copyBtn.getAttribute('data-copy') || 
                       copyBtn.closest('.hash-cell')?.querySelector('.table__hash')?.getAttribute('title') ||
                       document.getElementById('hash-preview-text')?.textContent;

    if (hashToCopy && !hashToCopy.includes('Awaiting') && !hashToCopy.includes('Type')) {
      navigator.clipboard.writeText(hashToCopy).then(() => {
        showToast('SHA-256 Fingerprint copied to clipboard!', 'success');
      }).catch(() => {
        showToast('Copied to clipboard', 'info');
      });
    }
  });

  // ─── Records Table Live Filtering ────────────────────────────────
  const searchInput = document.getElementById('search-records');
  const filterCanon = document.getElementById('filter-canon');
  const filterType = document.getElementById('filter-type');
  const filterStatus = document.getElementById('filter-status');
  const recordsTable = document.getElementById('records-table');

  function filterRecords() {
    if (!recordsTable) return;
    const query = (searchInput?.value || '').toLowerCase().trim();
    const selectedCanon = (filterCanon?.value || '').toLowerCase();
    const selectedType = (filterType?.value || '').toLowerCase();
    const selectedStatus = (filterStatus?.value || '').toLowerCase();

    const rows = recordsTable.querySelectorAll('tbody tr.record-row');
    rows.forEach(row => {
      const rowText = row.textContent.toLowerCase();
      const rowCanon = (row.getAttribute('data-canon') || '').toLowerCase();
      const rowType = (row.getAttribute('data-type') || '').toLowerCase();
      const rowStatus = (row.getAttribute('data-status') || '').toLowerCase();

      const matchesQuery = !query || rowText.includes(query);
      const matchesCanon = !selectedCanon || rowCanon === selectedCanon;
      const matchesType = !selectedType || rowType === selectedType;
      const matchesStatus = !selectedStatus || rowStatus === selectedStatus;

      row.style.display = (matchesQuery && matchesCanon && matchesType && matchesStatus) ? '' : 'none';
    });
  }

  if (searchInput) searchInput.addEventListener('input', filterRecords);
  if (filterCanon) filterCanon.addEventListener('change', filterRecords);
  if (filterType) filterType.addEventListener('change', filterRecords);
  if (filterStatus) filterStatus.addEventListener('change', filterRecords);

  // ─── WebCrypto SHA-256 Real-time Computation ────────────────────
  async function computeSha256(bufferOrString) {
    let data;
    if (typeof bufferOrString === 'string') {
      const encoder = new TextEncoder();
      data = encoder.encode(bufferOrString);
    } else {
      data = bufferOrString;
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // RFC 6962 Domain-Separated Merkle Leaf: SHA-256(0x00 || fp_bytes)
  async function computeLeafHash(fpHex) {
    const fpBytes = new Uint8Array(fpHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const leafData = new Uint8Array(1 + fpBytes.length);
    leafData[0] = 0x00; // Leaf prefix
    leafData.set(fpBytes, 1);
    return await computeSha256(leafData);
  }

  // ─── RFC 8785 Canonical JSON Reducer (json-sorted-v1) ─────────────
  function normaliseCanonical(value) {
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isInteger(value)) {
        throw new Error('Floating-point numbers are not allowed under json-sorted-v1; use integers or strings');
      }
      return value;
    }
    if (typeof value === 'string') {
      return value.normalize('NFC');
    }
    if (Array.isArray(value)) {
      return value.map(normaliseCanonical);
    }
    if (typeof value === 'object') {
      const sortedKeys = Object.keys(value).sort();
      const result = {};
      for (const k of sortedKeys) {
        const normKey = k.normalize('NFC');
        result[normKey] = normaliseCanonical(value[k]);
      }
      return result;
    }
    throw new Error(`Unsupported value type: ${typeof value}`);
  }

  function canonicalJsonString(obj) {
    const normalised = normaliseCanonical(obj);
    return JSON.stringify(normalised);
  }

  // ─── Register Form Interactivity ─────────────────────────────────
  const cardCanonJson = document.getElementById('card-canon-json');
  const cardCanonRaw = document.getElementById('card-canon-raw');
  const radioCanonJson = document.getElementById('radio-canon-json');
  const radioCanonRaw = document.getElementById('radio-canon-raw');
  const jsonSection = document.getElementById('json-input-section');
  const fileSection = document.getElementById('file-input-section');
  const canonIndicator = document.getElementById('canon-mode-indicator');
  const jsonContent = document.getElementById('json-content');
  const hashPreviewText = document.getElementById('hash-preview-text');
  const leafPreviewText = document.getElementById('leaf-preview-text');
  const canonErrorBanner = document.getElementById('canon-error-banner');
  const canonErrorMsg = document.getElementById('canon-error-msg');
  const btnLoadSample = document.getElementById('btn-load-sample-json');

  function updateCanonMode(isJson) {
    if (isJson) {
      cardCanonJson?.classList.add('canon-card--active');
      cardCanonRaw?.classList.remove('canon-card--active');
      if (radioCanonJson) radioCanonJson.checked = true;
      if (jsonSection) jsonSection.style.display = 'block';
      if (fileSection) fileSection.style.display = 'none';
      if (canonIndicator) canonIndicator.textContent = 'json-sorted-v1 (RFC 8785)';
      recalcJsonFingerprint();
    } else {
      cardCanonRaw?.classList.add('canon-card--active');
      cardCanonJson?.classList.remove('canon-card--active');
      if (radioCanonRaw) radioCanonRaw.checked = true;
      if (jsonSection) jsonSection.style.display = 'none';
      if (fileSection) fileSection.style.display = 'block';
      if (canonIndicator) canonIndicator.textContent = 'raw-bytes-v1 (Unaltered)';
      if (fileInput?.files[0]) {
        handleFileSelect(fileInput.files[0]);
      } else {
        if (hashPreviewText) hashPreviewText.textContent = 'Select or drop a file to compute raw SHA-256...';
        if (leafPreviewText) leafPreviewText.textContent = 'Awaiting file payload...';
      }
    }
  }

  if (cardCanonJson) cardCanonJson.addEventListener('click', () => updateCanonMode(true));
  if (cardCanonRaw) cardCanonRaw.addEventListener('click', () => updateCanonMode(false));

  async function recalcJsonFingerprint() {
    if (!jsonContent) return;
    const text = jsonContent.value.trim();
    if (!text) {
      if (hashPreviewText) hashPreviewText.textContent = 'Type structured JSON above...';
      if (leafPreviewText) leafPreviewText.textContent = 'Awaiting fingerprint...';
      if (canonErrorBanner) canonErrorBanner.style.display = 'none';
      return;
    }

    try {
      const parsed = JSON.parse(text);
      const canonStr = canonicalJsonString(parsed);
      const fp = await computeSha256(canonStr);
      const leaf = await computeLeafHash(fp);

      if (canonErrorBanner) canonErrorBanner.style.display = 'none';
      if (hashPreviewText) hashPreviewText.textContent = fp;
      if (leafPreviewText) leafPreviewText.textContent = leaf;
    } catch (err) {
      if (canonErrorBanner && canonErrorMsg) {
        canonErrorMsg.textContent = err.message;
        canonErrorBanner.style.display = 'flex';
      }
      if (hashPreviewText) hashPreviewText.textContent = 'Invalid JSON or forbidden float';
      if (leafPreviewText) leafPreviewText.textContent = 'Validation error';
    }
  }

  if (jsonContent) {
    jsonContent.addEventListener('input', recalcJsonFingerprint);
  }

  if (btnLoadSample && jsonContent) {
    btnLoadSample.addEventListener('click', () => {
      jsonContent.value = JSON.stringify({
        record_id: "REC-2026-00891",
        issuer: "Global Enterprise Corp",
        amount_cents: 250000,
        currency: "USD",
        tags: ["compliance", "soc2"]
      }, null, 2);
      recalcJsonFingerprint();
      showToast('Loaded valid RFC 8785 JSON sample!', 'success');
    });
  }

  // File Dropzone & Real-time Hashing
  const dropzone = document.getElementById('file-dropzone');
  const fileInput = document.getElementById('record-file');
  const fileCard = document.getElementById('file-selected-card');
  const fileNameDisplay = document.getElementById('file-name-display');
  const fileSizeDisplay = document.getElementById('file-size-display');
  const removeFileBtn = document.getElementById('btn-remove-file');
  const recordIdInput = document.getElementById('record-id');
  const btnGenerateId = document.getElementById('btn-generate-id');

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('drag-over');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
      if (e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        handleFileSelect(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
      }
    });
  }

  async function handleFileSelect(file) {
    if (!file) return;
    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    if (fileSizeDisplay) fileSizeDisplay.textContent = `(${(file.size / 1024).toFixed(1)} KB)`;
    if (fileCard) fileCard.style.display = 'inline-flex';

    if (hashPreviewText) hashPreviewText.textContent = 'Computing raw SHA-256 fingerprint...';

    try {
      const arrayBuffer = await file.arrayBuffer();
      const fp = await computeSha256(arrayBuffer);
      const leaf = await computeLeafHash(fp);

      if (hashPreviewText) hashPreviewText.textContent = fp;
      if (leafPreviewText) leafPreviewText.textContent = leaf;
      showToast('Fingerprint & Merkle leaf generated!', 'success');
    } catch (err) {
      console.error(err);
      if (hashPreviewText) hashPreviewText.textContent = 'Error computing fingerprint';
    }
  }

  if (removeFileBtn && fileInput) {
    removeFileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.value = '';
      if (fileCard) fileCard.style.display = 'none';
      if (hashPreviewText) hashPreviewText.textContent = 'Awaiting file payload...';
      if (leafPreviewText) leafPreviewText.textContent = 'Awaiting fingerprint...';
    });
  }

  // Random ID Generator Button
  if (btnGenerateId && recordIdInput) {
    btnGenerateId.addEventListener('click', () => {
      const randNum = Math.floor(10000 + Math.random() * 90000);
      recordIdInput.value = `REC-2026-${randNum}`;
      showToast(`Generated Identifier: REC-2026-${randNum}`);
    });
  }

  // ─── Keyboard Shortcuts (Ctrl + K) ──────────────────────────────
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const searchBox = document.getElementById('search-records');
      if (searchBox) {
        searchBox.focus();
        searchBox.select();
      }
    }
  });

  // ─── Mobile Sidebar Toggle ──────────────────────────────────────
  const sidebar = document.getElementById('sidebar');
  const sidebarToggle = document.getElementById('sidebar-toggle');
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('sidebar--open');
    });

    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('sidebar--open') &&
          !sidebar.contains(e.target) &&
          !sidebarToggle.contains(e.target)) {
        sidebar.classList.remove('sidebar--open');
      }
    });
  }

  // Initial calculation on page load
  if (jsonContent && jsonContent.value) {
    recalcJsonFingerprint();
  }
})();
