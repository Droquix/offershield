# OfferShield

> A job and internship scam checker for students in India. Paste a suspicious message, see the warning signs, and learn what to do next.

**Live demo:** FILL: your Vercel link
**GitHub:** https://github.com/Droquix/offershield
**Built by:** Vedant Halse
**Event:** PromptWars × Kick To Tech 2026, Cybersecurity & Digital Safety track

FILL: add one desktop screenshot and one mobile screenshot here

---

## The problem

Students and first-time job seekers in India often get fake internship and job offers on WhatsApp, Telegram, SMS, and email. These messages ask for a "registration fee," an OTP, or documents like Aadhaar before any real hiring process. In the moment, it is hard to tell a real offer from a fake one.

## What it does

1. You paste a message.
2. It checks the message against fixed rules.
3. It shows one result: **LIKELY SCAM**, **SUSPICIOUS**, or **CAN'T TELL**.
4. It highlights the exact phrases that triggered the warning and explains why each one matters.
5. It gives safe next steps and a polite reply you can copy, asking the sender for official verification.

OfferShield never says a message is "safe." If it finds nothing, the result is "can't tell," which does not mean the offer is genuine.

## Features

- **Pasted text stays in your browser:** it is not stored or sent to any server or API.
- **Transparent rules:** every result lists which rules fired and why. There is no black box.
- **Inline highlighting:** solid underline for strong signals, dashed underline for weak signals, and numbered notes linked to the explanations. Click a highlight to jump to its explanation.
- **Observed red flags and conclusion are shown separately**, so facts and judgment don't mix.
- **Safe reply:** a neutral, non-accusing message you can send to ask for an official email, offer letter, and interview process.
- **Test mode:** runs the sample messages and shows expected vs. actual results.
- **Accessible and responsive:** keyboard navigation, text labels instead of color alone, designed for good contrast, and works on mobile.

## How it decides

There is no AI model and no internet connection. Fixed rules (in `src/rules.ts`) and a scoring function (in `src/analyzer.ts`) produce the result, so the same message always gives the same answer.

**Strong signals** (serious on their own): FILL: copy the exact list from rules.ts, for example asking for an OTP/password/PIN/CVV, asking for a fee or deposit, asking for Aadhaar/PAN/bank details over chat, remote-access app install requests, pay-to-receive tricks.

**Weak signals** (only meaningful in combination): FILL: copy the exact list from rules.ts, for example urgency, free-email sender claiming to be a company, shortened links, unrealistic pay, Telegram-only contact, "selected without interview."

**Scoring** (FILL: confirm this matches analyzer.ts):
- Asking for an OTP, password, or PIN → LIKELY SCAM
- Two or more strong signals → LIKELY SCAM
- One strong signal plus two or more weak signals → LIKELY SCAM
- One strong signal with fewer weak signals → SUSPICIOUS
- No strong signals but three or more weak signals → SUSPICIOUS
- Anything else, including no flags → CAN'T TELL

A single weak signal can never produce LIKELY SCAM.

**Context handling:** a rule does not fire when the phrase appears in a warning or negated sentence, such as "we never charge any fee" or "do not share your OTP." This helps with genuine messages but is not perfect.

## Test results

I wrote 10 fictional sample messages (fictional companies only) and ran them with Test mode.

**Passed: FILL: for example 9 out of 10**

**What it got wrong:** FILL: write each failure honestly, for example "A professionally written scam with no warning phrases was missed. This is a known limitation."

**Extra check:** FILL: after writing the rules, I wrote X new messages in my own words, including Y genuine ones. Results: FILL.

These sets are small and written by me, so they do not measure real-world accuracy.

## Limitations

- It can miss scams written in polished language that avoid the known phrases.
- It can wrongly flag a genuine message with unusual wording.
- It does not check whether a company, email domain, or link is real.
- It supports English and some common Hinglish phrases only.
- The rules come from commonly reported scam patterns and general knowledge, not from a validated dataset, and the scoring thresholds were not statistically tuned.
- A result is a reason to verify through official channels, not a guarantee either way.

## Privacy

- The analysis runs entirely in your browser. Pasted text is not stored, logged, or sent anywhere by the app.
- The app has no login, database, or analytics. FILL: confirm this in the browser's Network tab on the live site before keeping this line.
- Fonts are self-hosted, so the page makes no calls to font services.
- Pasted text is shown as plain text, and links in it are never clickable or opened.
- All sample messages and company names are fictional.
- The hosting provider may keep ordinary website visit logs, but those do not include what you paste.

## AI tools used

This project was built during the hackathon with AI assistance.

- **Google Antigravity:** generated and refactored the React/TypeScript code from my prompts.
- **Google Stitch:** UI layout reference.
- **Claude (Anthropic):** planning, feedback on my prompts and rules, and test-case ideas.

I defined the problem, chose the rule categories and scoring logic, reviewed the generated code, and tested the results myself. FILL: edit this if anything above isn't accurate.

## Tech stack

React 18, TypeScript, Vite, Vitest, Lucide React icons, Inter font (self-hosted). FILL: check versions in package.json.

## Run it on your computer

```bash
git clone https://github.com/Droquix/offershield.git
cd offershield
npm install
npm run dev      # open http://localhost:5173
npm test         # run tests
npm run build    # production build
```

## If you think you were scammed

- National Cyber Crime Reporting Portal: [cybercrime.gov.in](https://cybercrime.gov.in)
- Cyber Crime Helpline: 1930

FILL: confirm both are still correct before submitting.

## Disclaimer

OfferShield is an educational prototype. It cannot guarantee that a message is a scam or that it is genuine. Always verify opportunities with your college placement cell and the company's official website, and never share OTPs, passwords, or payment details.

## License

MIT. FILL: add a LICENSE file to the repo, or delete this section.
