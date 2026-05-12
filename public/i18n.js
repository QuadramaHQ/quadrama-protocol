// i18n.js – Quadrama Deutsch / Englisch
const I18N = {
  de: {
    e2ee: 'Ende‑zu‑Ende verschlüsselt',
    heroClaim: 'Privater 1:1 Chat ohne Konto.',
    heroSub: 'Nachrichten werden im Browser Ende‑zu‑Ende verschlüsselt. Der Relay leitet nur verschlüsselte Daten weiter und speichert keine Chatverläufe.',
    trustNoAccount: 'Kein Konto',
    trustNoPhone: 'Keine Telefonnummer',
    trustNoCookies: 'Keine Cookies',
    trustE2EE: 'Browser‑E2EE',
    trustRelay: 'Server leitet nur weiter',
    trustOpenSource: 'Open Source',
    chat: 'Chat',
    room: 'Raum',
    wsLabel: 'WebSocket',
    verify: 'Verifizieren',
    delete: 'Löschen',
    showSafety: 'Safety',
    send: 'Senden',
    msgPlaceholder: 'Nachricht schreiben … (Enter zum Senden)',
    controlStatus: 'Status & Aktionen',
    step1: 'Identität erstellen',
    step2: 'Verbinden',
    step3: 'Raum erstellen oder beitreten',
    step4: 'Zweiter Kontakt verbindet sich',
    step5: 'Sicherheitscode vergleichen + verifizieren',
    step6: 'Chatten',
    step1desc: 'Erzeugt deinen einzigartigen Schlüssel — nur in diesem Tab.',
    step2desc: 'Verbindet mit dem Quadrama‑Relay.',
    step3desc: 'Erstelle einen 8‑stelligen Raumcode oder gib einen geteilten Code ein.',
    step4desc: 'Warte, bis der zweite Kontakt denselben Raumcode eingibt.',
    step5desc: 'Vergleiche den Sicherheitscode ausserhalb dieses Chats — z. B. per Anruf oder persönlich.',
    step6desc: 'Kanal verifiziert. Verschlüsselte Nachrichten können gesendet werden.',
    myFp: 'Mein FP',
    peerFp: 'Peer FP',
    securityCode: 'Sicherheitscode',
    safetyHint: 'Vergleicht diese 8 Wörter über einen zweiten Kanal — z. B. per Anruf oder persönlich. Stimmen sie exakt überein, sprecht ihr direkt mit derselben Person.',
    chatEmpty: 'Lade einen Kontakt ein, indem du einen 8‑stelligen Raumcode erstellst und teilst. Sobald beide im selben Raum sind, könnt ihr verschlüsselt chatten.',
    footerTagline: 'Open Source. Kein Konto. Keine Cookies. Keine Chatverläufe auf dem Server.',
    footerOpenSource: 'Open Source',
    connect: 'Verbinden',
    disconnect: 'Trennen',
    roomCode: 'Raumcode',
    join: 'Beitreten',
    new: 'Neu',
    leave: 'Verlassen',
    identity: 'Identität erstellen',
    factoryReset: 'Alles zurücksetzen',
    imprint: 'Impressum',
    privacy: 'Datenschutz',
    trustNotConfirmed: 'nicht bestätigt',
    disconnected: 'getrennt',
    ready: 'bereit',
  },
  en: {
    e2ee: 'End‑to‑End Encrypted',
    heroClaim: 'Private 1:1 chat without an account.',
    heroSub: 'Messages are end‑to‑end encrypted in your browser. The relay only forwards ciphertext and stores no chat history.',
    trustNoAccount: 'No account',
    trustNoPhone: 'No phone number',
    trustNoCookies: 'No cookies',
    trustE2EE: 'Browser E2EE',
    trustRelay: 'Server only forwards',
    trustOpenSource: 'Open source',
    chat: 'Chat',
    room: 'Room',
    wsLabel: 'WebSocket',
    verify: 'Verify',
    delete: 'Remove',
    showSafety: 'Safety',
    send: 'Send',
    msgPlaceholder: 'Write a message … (Enter to send)',
    controlStatus: 'Status & actions',
    step1: 'Create identity',
    step2: 'Connect',
    step3: 'Create or join a room',
    step4: 'Second contact connects',
    step5: 'Compare Safety Code + verify',
    step6: 'Chat',
    step1desc: 'Generates your unique key — in this tab only.',
    step2desc: 'Connects to the Quadrama relay.',
    step3desc: 'Create an 8‑digit room code or enter one shared with you.',
    step4desc: 'Wait for the second contact to enter the same room code.',
    step5desc: 'Compare the Safety Code out‑of‑band — e.g. by phone or in person.',
    step6desc: 'Channel verified. Encrypted messages can be sent.',
    myFp: 'My FP',
    peerFp: 'Peer FP',
    securityCode: 'Security Code',
    safetyHint: 'Compare these 8 words over a second channel — e.g. by phone or in person. If they match exactly, you are talking directly to the same person.',
    chatEmpty: 'Invite a contact by creating and sharing an 8‑digit room code. Once you are both in the same room, you can chat encrypted.',
    footerTagline: 'Open source. No account. No cookies. No chat history on the server.',
    footerOpenSource: 'Open source',
    connect: 'Connect',
    disconnect: 'Disconnect',
    roomCode: 'Room code',
    join: 'Join',
    new: 'New',
    leave: 'Leave',
    identity: 'Create identity',
    factoryReset: 'Factory reset',
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
