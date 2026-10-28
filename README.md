# OfferShield

> **In-browser job & internship scam checker designed for students in India.**

OfferShield allows students to paste suspicious employment, internship, or job-offer messages received via WhatsApp, Telegram, email, or direct messaging and evaluate them for common fraud patterns. 

All evaluations run **100% locally in your browser**. No text, phone numbers, or candidate details are ever stored, logged, or transmitted across the network.

---

## Key Features

- **Strict Client-Side Privacy**: Runs purely in the browser. Zero server calls, zero database storage, zero analytics.
- **Rule-Based Forensic Evaluation**: Evaluates messages against 9 verified scam rules (both strong and weak signals) with transparent scoring criteria.
  - **Strong Rules**: OTP/password/PIN/CVV requests, Upfront registration/training fees, Sensitive document demands (Aadhaar, PAN, passport) over chat/email without interview.
  - **Weak Rules**: Urgency/cancellation threats, Free-email domains claiming corporate status, Obscure/shortened links, Unrealistic pay rates for zero skill, Telegram/WhatsApp-only contact, Direct selection without interview.
- **Three Transparent Verdicts**:
  - `LIKELY SCAM`: High-confidence indicator of fraudulent recruitment activity.
  - `SUSPICIOUS`: Presence of warning signs that warrant independent verification.
  - `CAN'T TELL`: No known red flags detected (not a guarantee of legitimacy).
- **Inline Highlighting**: Highlighted phrases in the original text corresponding to flagged rules, with solid underlines for strong rules and dashed underlines for weak rules.
- **Bidirectional Exploration**: Click any mark in the message to expand the corresponding explanation in the accordion, or click an accordion item to highlight the phrase in the text.
- **Safe Next Steps & Safe Reply Generator**: Generates polite, neutral reply templates asking for official verification channels without accusatory language.
- **Test Mode Suite**: Built-in test suite evaluating standard benchmark sample messages with real-time pass/fail validation.
- **Accessible & Responsive**: High-contrast WCAG AA styling, keyboard-navigable (`:focus-visible`), `prefers-reduced-motion` compliance, and mobile responsive design.

---

## Tech Stack

- **Framework**: React 18 + TypeScript
- **Bundler & Dev Server**: Vite
- **Typography**: `@fontsource-variable/inter` (self-hosted, zero external requests)
- **Icons**: Lucide React
- **Testing**: Vitest

---

## Getting Started

### Prerequisites

- Node.js (v18 or higher recommended)
- npm or pnpm

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Droquix/offershield.git
cd offershield
npm install
```

### Running Locally

Start the Vite development server:

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Running Tests

Execute the Vitest test suite:

```bash
npm test
```

### Building for Production

Compile TypeScript and build the production bundle:

```bash
npm run build
```

Preview the production build:

```bash
npm run preview
```

---

## Disclaimers & Helplines

OfferShield is a heuristic pattern-recognition tool. Legitimate employers occasionally have unconventional wording, and sophisticated scams may appear professional. Always verify hiring opportunities with your university placement cell or directly via official company career portals.

If you suspect financial fraud or identity theft in India:
- **National Cyber Crime Reporting Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)
- **Cyber Crime National Helpline**: `1930`

---

## License

MIT
