export type RuleStrength = 'strong' | 'weak';
export type RiskLevel = 'LIKELY SCAM' | 'SUSPICIOUS' | "CAN'T TELL";

export interface TriggeredRule {
  id: string;
  name: string;
  strength: RuleStrength;
  matcher: string;
  matchedText: string;
  whyItMatters: string;
  startIndex?: number;
  endIndex?: number;
}

export interface AnalysisResult {
  level: RiskLevel;
  triggeredRules: TriggeredRule[];
  scoreExplanation: string;
  scoreFormula: string;
}

interface RuleDefinition {
  id: string;
  name: string;
  strength: RuleStrength;
  matcherDescription: string;
  whyItMatters: string;
  evaluate: (text: string) => { matched: boolean; matchedText: string; startIndex?: number; endIndex?: number };
}

// Helper to extract a clean snippet around a match
function extractSnippet(text: string, matchIndex: number, matchLength: number, context = 15): string {
  const start = Math.max(0, matchIndex - context);
  const end = Math.min(text.length, matchIndex + matchLength + context);
  let snippet = text.slice(start, end).trim();
  if (start > 0) snippet = '...' + snippet;
  if (end < text.length) snippet = snippet + '...';
  return snippet;
}

export const RULES: RuleDefinition[] = [
  // -------------------------------------------------------------
  // STRONG RULES
  // -------------------------------------------------------------
  {
    id: 'rule_1_otp_pin',
    name: 'OTP, Password, PIN, or CVV Request',
    strength: 'strong',
    matcherDescription: 'Regex matching requests for OTP, login password, UPI/ATM PIN, CVV, or Hinglish equivalents like "OTP batao", "OTP share karo".',
    whyItMatters: 'Legitimate employers, recruiters, and HR teams will never ask for your OTP, PIN, password, or CVV under any circumstances.',
    evaluate: (text: string) => {
      const patterns = [
        // Hinglish & English OTP sharing requests
        /(?:otp|one[\s-]?time[\s-]?password)\s*(?:batao|bataiye|share\s*karo|send\s*karo|bhejo|bhejiye|de\s*do|dedo|enter\s*karo|forward\s*karo|bhejna)/i,
        /(?:share|send|provide|tell|give|enter|forward|batao|bataiye|bhejo|de\s*do)\s*(?:your\s*|the\s*|apna\s*|apni\s*)?(?:otp|one[\s-]?time[\s-]?password)/i,
        // Password / PIN / CVV requests
        /(?:share|send|provide|tell|give|enter|batao|bataiye|bhejo)\s*(?:your\s*|apna\s*)?(?:password|login\s*password|atm\s*pin|upi\s*pin|security\s*pin|cvv(?:\s*code)?|mpin)/i,
        /(?:password|atm\s*pin|upi\s*pin|cvv)\s*(?:batao|bataiye|bhejo|share\s*karo|send\s*karo)/i,
        // Standalone explicit demands
        /(?:tell\s+me|send\s+me|forward\s+me)\s+(?:the|your)?\s*(?:otp|pin|cvv|password)/i,
        /\b(?:need\s+your\s+otp|otp\s+is\s+required\s+for\s+verification|share\s+the\s+6[\s-]?digit\s+code)\b/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_2_upfront_fee',
    name: 'Upfront Fee, Training Charge, or Security Deposit',
    strength: 'strong',
    matcherDescription: 'Regex/keyword matching upfront fees, training charges, security deposits, Hinglish fee demands, or specific monetary amounts with ₹/Rs.',
    whyItMatters: 'Legitimate companies never demand money, deposits, or training fees from candidates or interns before or during hiring.',
    evaluate: (text: string) => {
      const patterns = [
        // Fee and deposit keywords
        /\b(?:registration\s+fee[s]?|registration\s+charge[s]?|registration\s+amount)\b/i,
        /\b(?:training\s+fee[s]?|training\s+charge[s]?|training\s+cost)\b/i,
        /\b(?:security\s+deposit|refundable\s+deposit|refundable\s+amount|refundable\s+fee[s]?)\b/i,
        /\b(?:processing\s+fee[s]?|processing\s+charge[s]?|documentation\s+charge[s]?|documentation\s+fee[s]?)\b/i,
        /\b(?:seat\s+booking\s+fee|laptop\s+deposit|uniform\s+fee|badge\s+fee)\b/i,
        // Hinglish fee demands
        /(?:fee|fees|charges?)\s+(?:jama\s+karo|jama\s+karein|bharo|dena\s+hoga|pay\s+karo|lagti\s+hai)/i,
        /(?:registration\s+charges?|registration\s+fees?)\s+(?:jama|pay|dena|karo|bharo)/i,
        /(?:paisa|paise|rupaye|rupees?|amount)\s+(?:bhejo|bhejiye|transfer\s+karo|jama\s+karo|pay\s+karo|deposit\s+karo)/i,
        /(?:advance\s+fee|advance\s+payment|security\s+amount)\s*(?:jama|pay|dena|karo)?/i,
        // Amounts with ₹/Rs alongside payment or charge words
        /(?:pay|deposit|transfer|send|charges?|fees?|cost|invest)\s*(?:of)?\s*(?:₹|rs\.?|inr)\s*[\d,]+/i,
        /(?:₹|rs\.?|inr)\s*[\d,]+\s*(?:pay|deposit|transfer|charges?|fee[s]?|refundable|registration|security|advance)/i,
        /(?:deposit|pay|transfer)\s+(?:₹|rs\.?|inr)?\s*[\d,]+\s*(?:for\s+training|for\s+registration|for\s+laptop|as\s+security|as\s+deposit)/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_3_sensitive_documents',
    name: 'Sensitive Documents Requested Over Chat/Email Without Formal Process',
    strength: 'strong',
    matcherDescription: 'Regex matching requests for Aadhaar, PAN, bank details, or passport when no interview, assessment, or formal process is mentioned.',
    whyItMatters: 'Authentic employers only collect sensitive identity and financial documents through official onboarding portals after formal interviews and selection.',
    evaluate: (text: string) => {
      // Check if sensitive documents are mentioned
      const docPatterns = [
        /\b(?:aadhaar|aadhar|adhar)\s*(?:card|number|copy|photo)?\b/i,
        /\b(?:pan\s*card|pan\s*number|pan\s*copy)\b/i,
        /(?:send|share|submit|upload|provide)\s*(?:your\s*)?\bpan\b/i,
        /\b(?:bank\s*(?:account|details|statement|passbook)|cancelled\s*cheque|account\s*number|ifsc(?:\s*code)?)\b/i,
        /\b(?:passport\s*(?:copy|photo|details|number))\b/i,
        /(?:send|share|submit|upload|provide)\s*(?:your\s*)?\bpassport\b/i
      ];

      let foundDocMatch: RegExpMatchArray | null = null;
      for (const pattern of docPatterns) {
        const match = text.match(pattern);
        if (match) {
          foundDocMatch = match;
          break;
        }
      }

      if (!foundDocMatch || foundDocMatch.index === undefined) {
        return { matched: false, matchedText: '' };
      }

      // Check if formal interview or process is mentioned in the message
      const formalProcessPatterns = [
        /\b(?:interview|interviewed|technical\s+round|assessment|screening|evaluated|selection\s+process|cleared\s+the\s+rounds|hiring\s+manager\s+call)\b/i
      ];

      const hasFormalProcess = formalProcessPatterns.some(p => p.test(text));

      // Also check if requested directly over informal channels (chat, email, whatsapp)
      const directSubmissionRequest = /(?:send|share|upload|submit|forward|whatsapp|mail)\s*(?:me|us|your)?\s*.*?(?:aadhaar|aadhar|pan|bank|passport|cheque)/i.test(text);

      if (!hasFormalProcess || directSubmissionRequest) {
        return {
          matched: true,
          matchedText: extractSnippet(text, foundDocMatch.index, foundDocMatch[0].length),
          startIndex: foundDocMatch.index,
          endIndex: foundDocMatch.index + foundDocMatch[0].length
        };
      }

      return { matched: false, matchedText: '' };
    }
  },

  // -------------------------------------------------------------
  // WEAK RULES
  // -------------------------------------------------------------
  {
    id: 'rule_4_urgency_threats',
    name: 'Artificial Urgency or Threats of Offer Cancellation',
    strength: 'weak',
    matcherDescription: 'Regex matching artificial urgency, countdowns, or threats like "within 2 hours", "last chance", or "offer will be cancelled".',
    whyItMatters: 'Scammers use artificial urgency and short deadlines to pressure candidates into reacting before they can verify the offer.',
    evaluate: (text: string) => {
      const patterns = [
        /\bwithin\s+(?:\d+|two|three|four|24|12|2|1)\s*(?:hours?|hrs?|minutes?|mins?)\b/i,
        /\blast\s+chance\b/i,
        /\boffer\s+will\s+be\s+cancelled\b/i,
        /\boffer\s+(?:expires?|cancels?|voids?)\s+(?:in|within|today|soon)\b/i,
        /\bimmediate\s+joining\s+only\b/i,
        /\burgent\s+(?:requirement|hiring|opening)\s+today\b/i,
        /\bvalid\s+only\s+(?:for\s+)?today\b/i,
        /\bact\s+(?:fast|now)\s+or\s+lose\b/i,
        /\bhurry\s+up\b/i,
        /\bseat\s+will\s+be\s+(?:given|allotted|transferred)\s+to\s+(?:someone|another)\b/i,
        /\blose\s+this\s+opportunity\b/i,
        /\blimited\s+seats\s+remaining\b/i,
        /\bconfirm\s+(?:within|before)\s+(?:\d+|today|tonight)\b/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_5_free_email',
    name: 'Free Webmail Address Used for Corporate Hiring',
    strength: 'weak',
    matcherDescription: 'Regex detecting public webmail domains (@gmail, @yahoo, @outlook, @hotmail) when representing corporate recruitment.',
    whyItMatters: 'Legitimate corporate recruiters use verified corporate domains (e.g. name@company.com) rather than free public email providers.',
    evaluate: (text: string) => {
      const emailPattern = /\b([a-zA-Z0-9._%+-]+@(gmail|yahoo|outlook|hotmail|rediffmail|live|icloud)\.com)\b/i;
      const match = text.match(emailPattern);
      if (match && match.index !== undefined) {
        return {
          matched: true,
          matchedText: extractSnippet(text, match.index, match[0].length)
        };
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_6_shortened_links',
    name: 'Shortened or Obscure Web Links',
    strength: 'weak',
    matcherDescription: 'Regex identifying URL shorteners (bit.ly, tinyurl, cutt.ly, etc.) or suspicious external link redirects.',
    whyItMatters: 'Shortened or obscure links conceal the actual destination URL, often masking credential phishing forms or malicious websites.',
    evaluate: (text: string) => {
      const patterns = [
        /(?:https?:\/\/)?(?:www\.)?(?:bit\.ly|tinyurl\.com|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|rebrand\.ly|t\.co|ow\.ly|bl\.ink|trib\.al)\/[a-zA-Z0-9_\-]+/i,
        /(?:https?:\/\/)?(?:www\.)?forms\.gle\/[a-zA-Z0-9_\-]+/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_7_unrealistic_pay',
    name: 'Unrealistic Pay for Minimal or No Experience',
    strength: 'weak',
    matcherDescription: 'Regex identifying outsized salary or daily earning promises with no experience or qualifications required.',
    whyItMatters: 'Exaggerated pay promises for simple tasks or zero qualifications are classic bait to lure students into deceptive schemes.',
    evaluate: (text: string) => {
      const patterns = [
        /(?:earn|salary|stipend|income|payout)\s*(?:of|up\s*to)?\s*(?:₹|rs\.?|inr)?\s*\d+[\d,]*\s*(?:daily|per\s*day|\/day|per\s*hour|\/hr)/i,
        /(?:earn|salary|stipend)\s*(?:₹|rs\.?|inr)?\s*(?:[3-9]\d{4}|\d{6,})\s*(?:per\s*month|\/month|monthly)?\s*(?:without|no\s*skill|no\s*experience|from\s*mobile|typing\s*work)/i,
        /no\s*(?:prior\s*)?(?:experience|skills?|qualification)\s*(?:needed|required)?\s*.*?(?:earn|salary|stipend|₹|rs\.?)/i,
        /(?:simple|easy)\s*(?:typing|data\s*entry|copy\s*paste|sms\s*sending|video\s*watching|ad\s*clicking)\s*(?:job|work)?\s*.*?(?:₹|rs\.?|earn|\d{3,})/i,
        /daily\s*(?:income|payout|earnings?)\s*(?:₹|rs\.?|inr)?\s*\d+/i,
        /(?:earn|kamaye|kamao)\s*(?:₹|rs\.?|inr)?\s*\d+\s*(?:roj|daily|per\s*day)/i,
        /(?:earn|get\s*paid)\s*(?:₹|rs\.?|inr)?\s*\d+[\d,]*\s*(?:just\s+by\s+|by\s+just\s+)(?:typing|clicking|reviewing|liking)/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_8_telegram_whatsapp_only',
    name: 'Contact Restricted Exclusively to Telegram or WhatsApp',
    strength: 'weak',
    matcherDescription: 'Regex detecting instructions to contact recruiters solely via Telegram or WhatsApp channels.',
    whyItMatters: 'Insisting on Telegram or WhatsApp channels avoids verified corporate communication channels and makes perpetrators harder to trace.',
    evaluate: (text: string) => {
      const patterns = [
        /(?:contact|message|reach|connect|ping|chat|apply)\s*(?:us|me|hr)?\s*(?:only|strictly|direct|directly)?\s*(?:on|via|through)?\s*(?:whatsapp|telegram)/i,
        /(?:whatsapp|telegram)\s*(?:only|par\s*message\s*karo|pe\s*message\s*karo|pe\s*contact\s*karo|number\s*only)/i,
        /(?:https?:\/\/)?(?:t\.me|wa\.me)\/[a-zA-Z0-9_+]+/i,
        /telegram\s*(?:username|id|handle|channel|group)\s*[:@-]?\s*@?[a-zA-Z0-9_]+/i,
        /\binbox\s*(?:me\s*)?on\s*telegram\b/i,
        /\bconnect\s*(?:with\s*hr\s*)?on\s*whatsapp\b/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  },

  {
    id: 'rule_9_no_interview_direct_selection',
    name: '"No Interview Needed" or "Selected Directly" Claim',
    strength: 'weak',
    matcherDescription: 'Regex identifying promises of employment or internship offers with no interview or assessment required.',
    whyItMatters: 'Genuine organizations evaluate qualifications through interviews or technical assessments before extending employment offers.',
    evaluate: (text: string) => {
      const patterns = [
        /\bno\s*interview\s*(?:needed|required|conducted|necessary|round)\b/i,
        /\bdirect\s*(?:selection|joining|hiring|placement|offer|appointment)\b/i,
        /\bselected\s*directly\b/i,
        /\bhired\s*directly\b/i,
        /\bshortlisted\s*without\s*(?:any\s*)?interview\b/i,
        /\bbina\s*interview\s*(?:ke\s*)?(?:selection|job|joining)\b/i,
        /\bcongratulations!?\s*(?:you\s*are|you've\s*been|you\s*have\s*been)?\s*selected\s*directly\b/i,
        /\binstant\s*offer\s*letter\s*without\s*interview\b/i,
        /\bdirect\s*job\s*offer\s*without\s*interview\b/i
      ];

      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match && match.index !== undefined) {
          return {
            matched: true,
            matchedText: extractSnippet(text, match.index, match[0].length),
            startIndex: match.index,
            endIndex: match.index + match[0].length
          };
        }
      }
      return { matched: false, matchedText: '' };
    }
  }
];

/**
 * Pure function to evaluate a message against all rules and compute the risk level.
 * Follows the scoring specification strictly:
 * - Rule 1 triggered alone -> LIKELY SCAM
 * - 2 or more strong rules -> LIKELY SCAM
 * - exactly 1 strong rule (fee or documents) plus 2 or more weak -> LIKELY SCAM
 * - exactly 1 strong rule plus fewer than 2 weak -> SUSPICIOUS
 * - no strong rules, 3 or more weak -> SUSPICIOUS
 * - everything else, including zero flags -> CAN'T TELL
 * Never output "safe" or "legitimate". A single weak signal must never produce LIKELY SCAM.
 */
export function analyzeMessage(text: string): AnalysisResult {
  if (!text || text.trim().length === 0) {
    return {
      level: "CAN'T TELL",
      triggeredRules: [],
      scoreExplanation: 'No text provided to evaluate.',
      scoreFormula: '0 strong + 0 weak'
    };
  }

  const triggeredRules: TriggeredRule[] = [];

  for (const rule of RULES) {
    const result = rule.evaluate(text);
    if (result.matched) {
      triggeredRules.push({
        id: rule.id,
        name: rule.name,
        strength: rule.strength,
        matcher: rule.matcherDescription,
        matchedText: result.matchedText,
        whyItMatters: rule.whyItMatters,
        startIndex: result.startIndex,
        endIndex: result.endIndex
      });
    }
  }

  const strongRules = triggeredRules.filter(r => r.strength === 'strong');
  const weakRules = triggeredRules.filter(r => r.strength === 'weak');
  const strongCount = strongRules.length;
  const weakCount = weakRules.length;
  const hasRule1 = strongRules.some(r => r.id === 'rule_1_otp_pin');

  let level: RiskLevel = "CAN'T TELL";
  let scoreExplanation = '';
  const scoreFormula = hasRule1 && strongCount === 1 && weakCount === 0
    ? '1 strong (Rule 1: OTP/Credentials) alone'
    : `${strongCount} strong + ${weakCount} weak`;

  // Rule 1: OTP/Password/PIN/CVV triggered alone -> LIKELY SCAM
  // Note: If Rule 1 is triggered with any other rules, it also meets LIKELY SCAM criteria
  if (hasRule1) {
    level = 'LIKELY SCAM';
    if (strongCount === 1 && weakCount === 0) {
      scoreExplanation = 'Rule 1 (OTP/password/PIN/CVV request) triggered alone. Asking for one-time passwords or security credentials is an unequivocal fraud indicator.';
    } else {
      scoreExplanation = `Rule 1 (OTP/password/PIN/CVV request) triggered alongside ${strongCount - 1} other strong flag(s) and ${weakCount} weak flag(s). Requesting authentication credentials is an immediate scam indicator.`;
    }
  }
  // 2 or more strong rules -> LIKELY SCAM
  else if (strongCount >= 2) {
    level = 'LIKELY SCAM';
    scoreExplanation = `Triggered ${strongCount} strong red flags (${strongRules.map(r => r.name).join(' and ')}). Multiple strong signals establish a severe likelihood of fraud.`;
  }
  // Exactly 1 strong rule (fee or documents) plus 2 or more weak -> LIKELY SCAM
  else if (strongCount === 1 && weakCount >= 2) {
    level = 'LIKELY SCAM';
    scoreExplanation = `Triggered 1 strong red flag (${strongRules[0].name}) combined with ${weakCount} weak red flags (${weakRules.map(r => r.name).join(', ')}). The combination of a major demand with supporting pressure or suspicious patterns warrants a likely scam classification.`;
  }
  // Exactly 1 strong rule plus fewer than 2 weak -> SUSPICIOUS
  else if (strongCount === 1 && weakCount < 2) {
    level = 'SUSPICIOUS';
    scoreExplanation = `Triggered 1 strong red flag (${strongRules[0].name}) alongside ${weakCount} weak flag(s). While highly abnormal for legitimate hiring, single demands require caution and independent verification before declaring definitive fraud.`;
  }
  // No strong rules, 3 or more weak -> SUSPICIOUS
  else if (strongCount === 0 && weakCount >= 3) {
    level = 'SUSPICIOUS';
    scoreExplanation = `Triggered 0 strong flags but ${weakCount} weak red flags (${weakRules.map(r => r.name).join(', ')}). The compounding presence of multiple irregular recruitment signals indicates high suspicion.`;
  }
  // Everything else, including zero flags -> CAN'T TELL
  else {
    level = "CAN'T TELL";
    if (weakCount > 0) {
      scoreExplanation = `Triggered ${weakCount} weak flag(s) (${weakRules.map(r => r.name).join(', ')}), with 0 strong flags. Per strict scoring criteria, a single or minor pair of weak signals is inconclusive. Further verification is recommended.`;
    } else {
      scoreExplanation = 'No recognized red flag patterns were detected in the analyzed message. Inconclusive result; vigilance is still recommended.';
    }
  }

  return {
    level,
    triggeredRules,
    scoreExplanation,
    scoreFormula
  };
}
