/* Sentinel-API Dashboard — client-side utilities */
/* Intentionally minimal: HTMX handles all DOM updates.              */
/* This file provides: tab routing, Alpine.js collapse plugin, and   */
/* a thin WebSocket helper consumed by scan_progress.html.           */

'use strict';

// ── Alpine.js x-collapse plugin ──────────────────────────────────────
// Minimal collapse implementation — avoids loading a separate CDN bundle.
document.addEventListener('alpine:init', () => {
  Alpine.directive('collapse', (el, { modifiers }, { cleanup }) => {
    let open = false;
    const getHeight = () => el.scrollHeight;

    Object.defineProperty(el, '_x_isShown', {
      get: () => open,
      set: (val) => {
        open = val;
        if (val) {
          el.style.overflow = 'hidden';
          el.style.height = '0px';
          requestAnimationFrame(() => {
            el.style.transition = 'height 0.25s ease, opacity 0.25s ease';
            el.style.height = getHeight() + 'px';
            el.style.opacity = '1';
            el.addEventListener('transitionend', () => {
              el.style.height = 'auto';
              el.style.overflow = '';
            }, { once: true });
          });
        } else {
          el.style.overflow = 'hidden';
          el.style.height = getHeight() + 'px';
          requestAnimationFrame(() => {
            el.style.transition = 'height 0.25s ease, opacity 0.25s ease';
            el.style.height = '0px';
            el.style.opacity = '0';
          });
        }
      }
    });
  });
});

// ── Tab switching ─────────────────────────────────────────────────────
// All result panels are managed here. The active tab ID is persisted in
// sessionStorage so refreshing the page restores the open tab.

const TABS = ['findings', 'endpoints', 'owasp', 'shadow', 'cves', 'ratelimit', 'directory'];

function showTab(id) {
  TABS.forEach(t => {
    const panel = document.getElementById('panel-' + t);
    const tabBtn = document.getElementById('tab-' + t);
    const navBtn = document.getElementById('nav-' + t);

    if (panel) panel.classList.toggle('hidden', t !== id);
    if (tabBtn) {
      tabBtn.classList.toggle('tab-active', t === id);
      tabBtn.classList.toggle('border-blue-500', t === id);
      tabBtn.classList.toggle('text-blue-400', t === id);
      tabBtn.classList.toggle('border-transparent', t !== id);
      tabBtn.classList.toggle('text-sentinel-muted', t !== id);
    }
    if (navBtn) navBtn.classList.toggle('nav-active', t === id);
  });

  // Trigger HTMX lazy-load on first reveal
  const panel = document.getElementById('panel-' + id);
  if (panel) {
    panel.classList.remove('hidden');
    // Fire htmx:revealed so hx-trigger="revealed" picks it up
    panel.dispatchEvent(new Event('revealed', { bubbles: true }));
  }

  try { sessionStorage.setItem('sentinel_tab', id); } catch(e) {}
}

// Restore tab on load
document.addEventListener('DOMContentLoaded', () => {
  try {
    const saved = sessionStorage.getItem('sentinel_tab');
    if (saved && TABS.includes(saved)) { showTab(saved); return; }
  } catch(e) {}
  if (TABS.length) showTab(TABS[0]);
});

// ── HTMX configuration ────────────────────────────────────────────────
document.addEventListener('htmx:configRequest', (ev) => {
  // Forward the scan_id from the URL path to all partial requests
  ev.detail.headers['X-Sentinel-Version'] = '2.4.1';
});

document.addEventListener('htmx:responseError', (ev) => {
  console.warn('HTMX error', ev.detail.xhr.status, ev.detail.pathInfo.requestPath);
});

// ── Scan form helpers ─────────────────────────────────────────────────
function updateConcurrencyLabel(val) {
  const el = document.getElementById('concurrency-val');
  if (el) el.textContent = val;
}

// ── Utility: format duration from seconds ────────────────────────────
function formatUptime(s) {
  s = Math.floor(s);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

// ── Copy-to-clipboard for finding IDs / CVE IDs ──────────────────────
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 1500);
    }
  });
}
