const form = document.getElementById('scan-form');
const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const errorBox = document.getElementById('error-box');
const resultBox = document.getElementById('result');
const targetUrlEl = document.getElementById('target-url');
const verdictEl = document.getElementById('verdict-text');
const scoreNumberEl = document.getElementById('score-number');
const scoreBarFillEl = document.getElementById('score-bar-fill');
const checklistEl = document.getElementById('checklist');
const downloadBtn = document.getElementById('download-btn');

let lastScannedUrl = null;

function showError(message) {
  errorBox.textContent = message;
  errorBox.style.display = 'block';
}

function clearError() {
  errorBox.style.display = 'none';
  errorBox.textContent = '';
}

function setLoading(isLoading) {
  scanBtn.disabled = isLoading;
  scanBtn.textContent = isLoading ? 'סורק…' : 'סרוק';
}

function renderResult(data) {
  resultBox.className = 'risk-' + data.risk_level;
  resultBox.style.display = 'block';
  targetUrlEl.textContent = data.url;
  verdictEl.textContent = {
    Low: 'סיכון נמוך',
    Medium: 'סיכון בינוני',
    High: 'סיכון גבוה'
  }[data.risk_level] || data.risk_level;

  scoreNumberEl.textContent = data.score;
  scoreBarFillEl.style.width = '0%';
  requestAnimationFrame(() => {
    scoreBarFillEl.style.width = Math.min(data.score, 100) + '%';
  });

  checklistEl.innerHTML = '';
  data.checks.forEach((check, i) => {
    const row = document.createElement('div');
    row.className = 'check-row ' + (check.flagged ? 'flagged' : 'clear');
    row.style.animationDelay = (i * 60) + 'ms';

    const icon = check.flagged
      ? '<svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
      : '<svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>';

    row.innerHTML = `
      ${icon}
      <div class="check-body">
        <div class="check-name">${check.name}</div>
        <div class="check-detail">${check.detail}</div>
      </div>
    `;
    checklistEl.appendChild(row);
  });

  downloadBtn.style.display = 'flex';
  lastScannedUrl = data.url;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  clearError();
  resultBox.style.display = 'none';
  downloadBtn.style.display = 'none';
  setLoading(true);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!res.ok) {
      showError(data.error || 'אירעה שגיאה בסריקה.');
      return;
    }
    renderResult(data);
  } catch (err) {
    showError('לא ניתן להתחבר לשרת. ודאו ש-app.py רץ בכתובת http://localhost:5000');
  } finally {
    setLoading(false);
  }
});

downloadBtn.addEventListener('click', async () => {
  if (!lastScannedUrl) return;
  downloadBtn.disabled = true;
  try {
    const res = await fetch('/api/scan/csv', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: lastScannedUrl })
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showError(data.error || 'לא ניתן היה להוריד את הדוח.');
      return;
    }
    const blob = await res.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'phishing-report.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
  } catch (err) {
    showError('לא ניתן להתחבר לשרת בזמן ההורדה.');
  } finally {
    downloadBtn.disabled = false;
  }
});