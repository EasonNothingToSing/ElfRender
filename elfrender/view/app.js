// app.js - GUI logic for pywebview
// Note: Python calls window.updateProgress(percent, message)

(function () {
  'use strict';

  window.updateProgress = function (pct, message) {
    const barEl = document.getElementById('progressBar');
    const statusEl = document.getElementById('status');
    const p = Math.max(0, Math.min(100, Number(pct || 0)));
    barEl.style.width = p + '%';
    if (message) statusEl.textContent = message;
  };

  function setupUi() {
    const elfPathEl = document.getElementById('elfPath');
    const ignorePathsEl = document.getElementById('ignorePaths');
    const statusEl = document.getElementById('status');
    const btnAdd = document.getElementById('btnAdd');
    const btnGenerate = document.getElementById('btnGenerate');
    const btnView = document.getElementById('btnView');

    let lastReport = null;

    function setBusy(busy) {
      btnAdd.disabled = busy;
      btnGenerate.disabled = busy;
      if (busy) btnView.disabled = true;
    }

    function setStatus(text) {
      statusEl.textContent = text || '';
    }

    btnAdd.addEventListener('click', async () => {
      setStatus('Opening file dialog…');
      try {
        const res = await window.pywebview.api.pick_elf();
        if (res && res.ok) {
          elfPathEl.value = res.path || '';
          setStatus('ELF selected');
        } else if (res && res.cancelled) {
          setStatus('Cancelled');
        } else {
          setStatus(res && res.error ? res.error : 'Failed');
        }
      } catch (e) {
        setStatus(String(e));
      }
    });

    btnGenerate.addEventListener('click', async () => {
      if (!elfPathEl.value) {
        setStatus('Please click Add to select an ELF first');
        return;
      }

      setBusy(true);
      window.updateProgress(0, 'Starting…');
      try {
        const res = await window.pywebview.api.generate(elfPathEl.value, ignorePathsEl.value);
        if (res && res.ok) {
          lastReport = res;
          window.updateProgress(100, 'Done');
          btnView.disabled = false;
        } else {
          window.updateProgress(0, 'Failed');
          setStatus(res && res.error ? res.error : 'Generate failed');
        }
      } catch (e) {
        window.updateProgress(0, 'Failed');
        setStatus(String(e));
      } finally {
        setBusy(false);
      }
    });

    btnView.addEventListener('click', async () => {
      if (!lastReport) {
        setStatus('No report yet');
        return;
      }
      try {
        const res = await window.pywebview.api.open_view();
        if (res && res.ok) {
          setStatus('Report opened');
        } else {
          setStatus(res && res.error ? res.error : 'Open failed');
        }
      } catch (e) {
        setStatus(String(e));
      }
    });

    setStatus('Ready');
  }

  // Ensure the pywebview API is ready before wiring events.
  if (window.pywebview && window.pywebview.api) {
    setupUi();
  } else {
    window.addEventListener('pywebviewready', setupUi);
  }
})();
