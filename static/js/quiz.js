// Quiz logic. All URLs are fictional. Text is inserted with textContent (never innerHTML) to avoid XSS.
const QUESTIONS = [
  { q: "Which URL requires the most caution?",
    o: ["https://www.example.com/support", "https://example.com/login", "http://192.0.2.1/verify-account", "https://docs.example.com"], a: 2,
    e: "It uses HTTP instead of HTTPS, uses an IP address rather than a recognizable domain name, and includes a verification-related path. These signals do not prove it is malicious, but they justify caution." },
  { q: "A message says 'Your account is locked! Verify within 1 hour' and links to http://mybank-security.example/verify. What is the best action?",
    o: ["Click quickly before the deadline", "Open your bank's official app or type its known address yourself", "Reply with your OTP to the sender", "Forward it to friends as a warning"], a: 1,
    e: "Urgency is a classic pressure tactic. Go to the official app or website yourself instead of using the message link." },
  { q: "In https://example.com@secure-login.example/home, where does the browser actually go?",
    o: ["example.com", "secure-login.example", "home", "Nowhere, the URL is invalid"], a: 1,
    e: "Text before the '@' is treated as user information. The real host is the part after it: secure-login.example." },
  { q: "Someone on a call asks for the OTP 'to cancel a wrong transaction'. What should you do?",
    o: ["Share it, since they know your name", "Share only half of it", "Never share it and end the call", "Share it if they sound professional"], a: 2,
    e: "OTPs, UPI PINs, passwords and CVV must never be shared. Genuine organisations do not ask for them." },
  { q: "Which hostname looks most like a disguised domain?",
    o: ["docs.example.com", "xn--example-test.example", "www.example.com", "mail.example.com"], a: 1,
    e: "'xn--' marks punycode, which can be used to display look-alike characters. It is not always malicious, but it deserves caution." },
  { q: "A QR code sticker on a parking meter asks you to pay via a link. What is a sensible step?",
    o: ["Scan and pay immediately", "Check the link preview, look for tampering, and prefer the official app", "Ignore the preview", "Share your card details by chat"], a: 1,
    e: "Quishing uses fake or overlaid QR codes. Check the shown address and prefer official channels." },
  { q: "What does a short link such as https://bit.ly/example hide?",
    o: ["Nothing", "The final destination", "The sender's name", "The page colours"], a: 1,
    e: "Shorteners hide where the link really leads, so be extra careful and use a safe checker or the sender's official channel." },
  { q: "You clicked a suspicious link and typed your password. What should you do first?",
    o: ["Do nothing", "Change that password (and any reused ones) and enable multi-factor authentication", "Delete your browser", "Wait a week"], a: 1,
    e: "Change the password quickly, enable MFA, and contact your bank if payments may be involved." },
  { q: "Which is the strongest sign a link is genuinely from your service?",
    o: ["It uses HTTPS", "It has a padlock icon", "You reached it by typing the official address or using the official app", "It has the logo"], a: 2,
    e: "HTTPS and padlocks only mean the connection is encrypted; phishing sites can have them. Reaching the site yourself is the safest habit." },
  { q: "Which of these is NOT a common phishing red flag?",
    o: ["Unexpected prize or refund", "Misspelled domain name", "A message you were expecting from a contact you can verify", "Threatening language"], a: 2,
    e: "A verified, expected message is less suspicious, though it is still good practice to double-check the sender." }
];
let index = 0, score = 0, answered = false;
const el = id => document.getElementById(id);

function render() {
  answered = false;
  const item = QUESTIONS[index];
  el("quiz-progress").textContent = "Question " + (index + 1) + " of " + QUESTIONS.length;
  el("quiz-question").textContent = item.q;
  const box = el("quiz-options"); box.innerHTML = "";
  item.o.forEach(function (text, i) {
    const b = document.createElement("button");
    b.className = "btn btn-outline-primary quiz-option";
    b.textContent = String.fromCharCode(65 + i) + ". " + text;
    b.addEventListener("click", function () { choose(i, b); });
    box.appendChild(b);
  });
  el("quiz-feedback").className = "alert d-none";
  el("quiz-next").classList.add("d-none");
}
function choose(i, btn) {
  if (answered) return; answered = true;
  const item = QUESTIONS[index];
  const buttons = el("quiz-options").querySelectorAll("button");
  buttons.forEach(function (b) { b.disabled = true; });
  buttons[item.a].classList.add("correct");
  if (i === item.a) { score++; } else { btn.classList.add("wrong"); }
  const fb = el("quiz-feedback");
  fb.className = "alert " + (i === item.a ? "alert-success" : "alert-danger");
  fb.textContent = (i === item.a ? "Correct! " : "Not quite. ") + item.e;
  const next = el("quiz-next");
  next.textContent = index === QUESTIONS.length - 1 ? "See score" : "Next";
  next.classList.remove("d-none");
}
el("quiz-next").addEventListener("click", function () {
  index++;
  if (index >= QUESTIONS.length) {
    el("quiz").classList.add("d-none");
    el("quiz-result").classList.remove("d-none");
    el("quiz-score").textContent = "You scored " + score + " / " + QUESTIONS.length;
  } else { render(); }
});
el("quiz-restart").addEventListener("click", function () {
  index = 0; score = 0;
  el("quiz-result").classList.add("d-none");
  el("quiz").classList.remove("d-none");
  render();
});
render();
