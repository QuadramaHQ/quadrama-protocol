// i18n.js – Quadrama Deutsch / Englisch
const I18N = {
  de: {
    e2ee: 'Ende\u2011zu\u2011Ende verschlüsselt',
    chat: 'Chat',
    room: 'Raum',
    verify: 'Verifizieren',
    delete: 'Löschen',
    showSafety: 'Safety zeigen',
    send: 'Senden',
    msgPlaceholder: 'Nachricht schreiben … (Enter = senden)',
    controlStatus: 'Steuerung & Status',
    step0: 'Factory Reset (optional)',
    step1: 'Identity laden/erz.',
    step2: 'Connect',
    step3: 'Raum joinen',
    step4: 'Zweiter Client verbunden',
    step5: 'Safety vergleichen + verifizieren',
    step6: '✅ Chatten',
    step0desc: 'Löscht alle lokalen Daten — nur bei Problemen nötig',
    step1desc: 'Erzeugt deinen einzigartigen Schlüssel (nur in diesem Tab)',
    step2desc: 'Verbindet mit dem Quadrama-Server',
    step3desc: 'Erstelle oder teile einen 8-stelligen Raumcode',
    step4desc: 'Warte bis der zweite Client denselben Code eingibt',
    step5desc: 'Vergleiche den Safety-Code mit deinem Gesprächspartner',
    step6desc: 'Kanal gesichert — du kannst jetzt sicher chatten',
    myFp: 'Mein FP',
    peerFp: 'Peer FP',
    securityCode: 'Sicherheitscode',
    connect: 'Connect',
    disconnect: 'Disconnect',
    roomCode: 'Raumcode',
    join: 'Join',
    new: 'Neu',
    leave: 'Leave',
    identity: 'Identity laden/erz.',
    backup: 'Backup (deaktiviert)',
    restore: 'Restore (deaktiviert)',
    factoryReset: 'Factory Reset',
    debugLog: 'Debug-Log',
    contacts: 'Kontakte (Primary)',
    status: 'Status',
    firstSeen: 'First seen',
    lastSeen: 'Last seen',
    verifiedAt: 'Verified at',
    keyHistory: 'Key-History',
    imprint: 'Impressum',
    privacy: 'Datenschutz',
    trustNotConfirmed: 'nicht bestätigt',
    disconnected: 'getrennt',
    ready: 'bereit',
  },
  en: {
    e2ee: 'End\u2011to\u2011End Encrypted',
    chat: 'Chat',
    room: 'Room',
    verify: 'Verify',
    delete: 'Remove',
    showSafety: 'Show Safety',
    send: 'Send',
    msgPlaceholder: 'Write a message … (Enter = send)',
    controlStatus: 'Controls & Status',
    step0: 'Factory Reset (optional)',
    step1: 'Load/create Identity',
    step2: 'Connect',
    step3: 'Join Room',
    step4: 'Second client connected',
    step5: 'Compare Safety + verify',
    step6: '✅ Chat',
    step0desc: 'Clears all local data — only needed if something is wrong',
    step1desc: 'Creates your unique key (this tab only)',
    step2desc: 'Connects to the Quadrama server',
    step3desc: 'Create or share an 8-digit room code',
    step4desc: 'Wait for the second client to enter the same code',
    step5desc: 'Compare the Safety Code with your contact out-of-band',
    step6desc: 'Channel secured — you can now chat safely',
    myFp: 'My FP',
    peerFp: 'Peer FP',
    securityCode: 'Security Code',
    connect: 'Connect',
    disconnect: 'Disconnect',
    roomCode: 'Room code',
    join: 'Join',
    new: 'New',
    leave: 'Leave',
    identity: 'Load/create Identity',
    backup: 'Backup (disabled)',
    restore: 'Restore (disabled)',
    factoryReset: 'Factory Reset',
    debugLog: 'Debug Log',
    contacts: 'Contacts (Primary)',
    status: 'Status',
    firstSeen: 'First seen',
    lastSeen: 'Last seen',
    verifiedAt: 'Verified at',
    keyHistory: 'Key History',
    imprint: 'Imprint',
    privacy: 'Privacy Policy',
    trustNotConfirmed: 'not confirmed',
    disconnected: 'disconnected',
    ready: 'ready',
  }
};

let currentLang = localStorage.getItem('mm3_lang') || 'de';

function applyLang(lang) {
  currentLang = lang;
  localStorage.setItem('mm3_lang', lang);

  const t = I18N[lang];

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (t[key] !== undefined) el.textContent = t[key];
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (t[key] !== undefined) el.placeholder = t[key];
  });

  document.getElementById('langDe').classList.toggle('active', lang === 'de');
  document.getElementById('langEn').classList.toggle('active', lang === 'en');

  document.documentElement.lang = lang;
}

function setLang(lang) {
  applyLang(lang);
}

applyLang(currentLang);

// Fix: Event Listeners statt onclick (Mobile-kompatibel)
document.addEventListener('DOMContentLoaded', function() {
  var btnDe = document.getElementById('langDe');
  var btnEn = document.getElementById('langEn');
  if (btnDe) btnDe.addEventListener('click', function() { applyLang('de'); });
  if (btnEn) btnEn.addEventListener('click', function() { applyLang('en'); });
});
