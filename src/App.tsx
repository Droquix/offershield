import { useState } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  HelpCircle, 
  Trash2, 
  Search, 
  ShieldCheck, 
  CheckCircle2, 
  Lock, 
  Copy, 
  Check, 
  Play, 
  ChevronDown, 
  ChevronUp 
} from 'lucide-react';
import { analyzeMessage, AnalysisResult, TriggeredRule } from './analyzer';

interface SampleMessage {
  id: string;
  name: string;
  company: string;
  expected: 'LIKELY SCAM' | 'SUSPICIOUS' | "CAN'T TELL";
  text: string;
}

const SAMPLE_DATASET: SampleMessage[] = [
  {
    id: 'sample-1',
    name: 'Direct selection with laptop fee and OTP request',
    company: 'Apex Global Logistics (Fictional)',
    expected: 'LIKELY SCAM',
    text: 'Dear candidate, you have been selected directly for the Apex Global Logistics Data Entry remote internship. Joining is immediate with stipend Rs 25,000/month. No interview required. Kindly transfer 1500 registration fee immediately to activate your company laptop kit and share your Aadhaar card copy with OTP to verify your candidate profile on WhatsApp right now.'
  },
  {
    id: 'sample-2',
    name: 'Unsolicited WhatsApp part-time product review offer',
    company: 'NovaRetail Solutions (Fictional)',
    expected: 'SUSPICIOUS',
    text: 'Hi! I am Priya from HR. Earn ₹3,000 daily by simply reviewing products for NovaRetail Solutions online. Immediate joining only! Valid only for today. No interview needed. Connect with HR on WhatsApp: https://wa.me/919876543210 or visit https://bit.ly/novaretail-apply'
  },
  {
    id: 'sample-3',
    name: 'Shortlisting notice demanding urgent training fee via free email',
    company: 'CloudSprint Systems (Fictional)',
    expected: 'LIKELY SCAM',
    text: 'Dear applicant, you are shortlisted for CloudSprint Systems technical internship. Please deposit registration fee of ₹1500 within 2 hours or your offer will be cancelled. Forward payment screenshot to careers.cloudsprint@gmail.com immediately.'
  },
  {
    id: 'sample-4',
    name: 'Campus placement drive interview invite with venue details',
    company: 'Nexus Innovations (Fictional)',
    expected: "CAN'T TELL",
    text: 'Dear student, thank you for participating in the campus placement drive for Nexus Innovations. You have been shortlisted for the Round 2 Technical Assessment and interview scheduled for tomorrow at 10:00 AM in the placement seminar hall.'
  },
  {
    id: 'sample-5',
    name: 'Offer letter confirmation asking for OTP verification',
    company: 'Zenith Tech Labs (Fictional)',
    expected: 'LIKELY SCAM',
    text: 'Congratulations! Your offer letter for the Junior Web Developer position at Zenith Tech Labs is ready. Please share your OTP received on your mobile to confirm your joining date and activate your employee portal.'
  },
  {
    id: 'sample-6',
    name: 'Mandatory training kit security deposit before joining',
    company: 'Starlight Media Group (Fictional)',
    expected: 'SUSPICIOUS',
    text: 'Dear candidate, we are pleased to offer you the Content Writer role at Starlight Media Group. Before your start date, you are required to submit a refundable security deposit of ₹2,500 for the company resource pack.'
  },
  {
    id: 'sample-7',
    name: 'Remote data specialist demanding Aadhaar card over Telegram',
    company: 'Vanguard Analytics (Fictional)',
    expected: 'LIKELY SCAM',
    text: 'You have been selected directly for Vanguard Analytics remote research trainee role. Please send your Aadhaar card and bank details immediately on Telegram @vanguard_hr to process your first stipend.'
  },
  {
    id: 'sample-8',
    name: 'High daily payout work-from-home typing task via Telegram',
    company: 'QuickTask Solutions (Fictional)',
    expected: 'SUSPICIOUS',
    text: 'Work from home opportunity! Earn ₹5,000 per day with simple typing tasks. No interview needed. Hurry, offer will be cancelled soon! Join our official Telegram channel now: https://t.me/quicktask_jobs'
  },
  {
    id: 'sample-9',
    name: 'Shortened application link with urgent joining deadline',
    company: 'Horizon Digital Services (Fictional)',
    expected: "CAN'T TELL",
    text: 'Horizon Digital Services is hiring summer marketing interns. Apply within 2 hours to be considered for this cycle: https://tinyurl.com/horizon-interns'
  },
  {
    id: 'sample-10',
    name: 'Formal off-campus internship assessment notification',
    company: 'Aether Software Systems (Fictional)',
    expected: "CAN'T TELL",
    text: 'Dear applicant, thank you for applying for the Software Engineering Internship at Aether Software Systems. We would like to invite you for a 45-minute technical interview with our engineering panel next Tuesday at 2:00 PM via Google Meet. Please review the interview guidelines attached.'
  }
];

interface TextSegment {
  text: string;
  isMatch: boolean;
  strength?: 'strong' | 'weak';
  ruleIndices?: number[];
  ruleNames?: string[];
}

function buildHighlightedSegments(
  text: string, 
  triggeredRules: TriggeredRule[]
): TextSegment[] {
  if (!text || triggeredRules.length === 0) {
    return [{ text, isMatch: false }];
  }

  interface RawInterval {
    start: number;
    end: number;
    strength: 'strong' | 'weak';
    ruleName: string;
    ruleIndex: number;
  }

  const raw: RawInterval[] = [];
  triggeredRules.forEach((rule, idx) => {
    if (
      rule.startIndex !== undefined &&
      rule.endIndex !== undefined &&
      rule.startIndex >= 0 &&
      rule.endIndex <= text.length &&
      rule.startIndex < rule.endIndex
    ) {
      raw.push({
        start: rule.startIndex,
        end: rule.endIndex,
        strength: rule.strength,
        ruleName: rule.name,
        ruleIndex: idx + 1
      });
    }
  });

  if (raw.length === 0) {
    return [{ text, isMatch: false }];
  }

  // Sort by start position, then by end position
  raw.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return a.end - b.end;
  });

  interface MergedInterval {
    start: number;
    end: number;
    strength: 'strong' | 'weak';
    ruleIndices: number[];
    ruleNames: string[];
  }

  // Merge overlapping or adjacent matches (start <= last.end)
  // Strong rule style takes precedence when merged
  const merged: MergedInterval[] = [];
  for (const current of raw) {
    if (merged.length === 0) {
      merged.push({
        start: current.start,
        end: current.end,
        strength: current.strength,
        ruleIndices: [current.ruleIndex],
        ruleNames: [current.ruleName]
      });
      continue;
    }

    const last = merged[merged.length - 1];
    if (current.start <= last.end) {
      last.end = Math.max(last.end, current.end);
      if (current.strength === 'strong') {
        last.strength = 'strong';
      }
      if (!last.ruleIndices.includes(current.ruleIndex)) {
        last.ruleIndices.push(current.ruleIndex);
        last.ruleIndices.sort((a, b) => a - b);
      }
      if (!last.ruleNames.includes(current.ruleName)) {
        last.ruleNames.push(current.ruleName);
      }
    } else {
      merged.push({
        start: current.start,
        end: current.end,
        strength: current.strength,
        ruleIndices: [current.ruleIndex],
        ruleNames: [current.ruleName]
      });
    }
  }

  const segments: TextSegment[] = [];
  let cursor = 0;
  for (const interval of merged) {
    if (interval.start > cursor) {
      segments.push({
        text: text.slice(cursor, interval.start),
        isMatch: false
      });
    }
    segments.push({
      text: text.slice(interval.start, interval.end),
      isMatch: true,
      strength: interval.strength,
      ruleIndices: interval.ruleIndices,
      ruleNames: interval.ruleNames
    });
    cursor = interval.end;
  }
  if (cursor < text.length) {
    segments.push({
      text: text.slice(cursor),
      isMatch: false
    });
  }

  return segments;
}

function generateSafeReplyText(): string {
  return `Dear Hiring Team,

Thank you for reaching out regarding this opportunity.

To ensure I have all necessary documentation and follow standard verification procedures, could you please provide:
1. Your official corporate email address originating from the company's verified domain (e.g., name@company.com)
2. A formal written offer/internship letter with the official job requisition or reference ID
3. The details and schedule for the standard interview and evaluation process

As a standard precaution, I will be independently verifying the opportunity and contact details through the company's official careers portal before proceeding.

Thank you for your understanding.

Sincerely,
[Your Name]`;
}

function buildVerdictDescription(analysis: AnalysisResult): string {
  if (analysis.triggeredRules.length === 0) {
    return "No known warning signs were found. This does not mean the offer is genuine.";
  }

  const signalLabels: Record<string, string> = {
    'rule_1_otp_pin': 'OTP/password/PIN/CVV request',
    'rule_2_upfront_fee': 'upfront fee request',
    'rule_3_sensitive_documents': 'sensitive documents requested over chat/email',
    'rule_4_urgency_threats': 'urgency or cancellation threats',
    'rule_5_free_email': 'free-email sender claiming to be a company',
    'rule_6_shortened_links': 'shortened or odd links',
    'rule_7_unrealistic_pay': 'unrealistic pay for no skills/experience',
    'rule_8_telegram_whatsapp': 'Telegram/WhatsApp-only contact required',
    'rule_9_no_interview': '"no interview needed" or "selected directly" claim'
  };

  const signals = analysis.triggeredRules.map(
    rule => signalLabels[rule.id] || rule.name.toLowerCase()
  );

  const uniqueSignals = Array.from(new Set(signals));

  return `Found: ${uniqueSignals.join(', ')}.`;
}

export default function App() {
  const [inputText, setInputText] = useState(SAMPLE_DATASET[0].text);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(() => analyzeMessage(SAMPLE_DATASET[0].text));
  const [hasAnalyzed, setHasAnalyzed] = useState(true);
  const [copyReplyState, setCopyReplyState] = useState<'idle' | 'copied' | 'failed'>('idle');

  // Accordion state for observed red flags: first flag expanded by default
  const [expandedIndices, setExpandedIndices] = useState<number[]>([0]);

  // Active highlighted rule from accordion or mark click
  const [activeHighlightedRule, setActiveHighlightedRule] = useState<number | null>(null);

  // Tab state: only one tab visible at a time
  const [activeTab, setActiveTab] = useState<'samples' | 'test' | 'limitations'>('samples');

  // Test mode state and results across all 10 sample messages
  const [testSuiteRan, setTestSuiteRan] = useState(false);
  const [testResults, setTestResults] = useState<{
    id: string;
    name: string;
    expected: 'LIKELY SCAM' | 'SUSPICIOUS' | "CAN'T TELL";
    actual: 'LIKELY SCAM' | 'SUSPICIOUS' | "CAN'T TELL";
    pass: boolean;
  }[]>(() => {
    return SAMPLE_DATASET.map(sample => {
      const res = analyzeMessage(sample.text);
      return {
        id: sample.id,
        name: sample.name,
        expected: sample.expected,
        actual: res.level,
        pass: res.level === sample.expected
      };
    });
  });

  const handleAnalyze = () => {
    if (!inputText.trim()) return;
    const result = analyzeMessage(inputText);
    setAnalysis(result);
    setHasAnalyzed(true);
    setExpandedIndices([0]); // Expand first flag by default
    setActiveHighlightedRule(null);
    setCopyReplyState('idle');
  };

  const handleClear = () => {
    setInputText('');
    setAnalysis(null);
    setHasAnalyzed(false);
    setActiveHighlightedRule(null);
    setCopyReplyState('idle');
  };

  const loadSample = (sample: SampleMessage) => {
    setInputText(sample.text);
    const result = analyzeMessage(sample.text);
    setAnalysis(result);
    setHasAnalyzed(true);
    setExpandedIndices([0]);
    setActiveHighlightedRule(null);
    setCopyReplyState('idle');
  };

  const toggleAccordion = (index: number) => {
    setExpandedIndices(prev => 
      prev.includes(index) 
        ? prev.filter(i => i !== index)
        : [...prev, index]
    );
  };

  const handleMarkClick = (ruleIndices: number[]) => {
    if (!ruleIndices || ruleIndices.length === 0) return;
    const flagZeroIndices = ruleIndices.map(r => r - 1);
    setExpandedIndices(prev => Array.from(new Set([...prev, ...flagZeroIndices])));
    setActiveHighlightedRule(ruleIndices[0]);

    const targetId = `flag-accordion-${ruleIndices[0] - 1}`;
    const el = document.getElementById(targetId);
    if (el) {
      const prefersReducedMotion = typeof window !== 'undefined' && 
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      el.scrollIntoView({
        behavior: prefersReducedMotion ? 'auto' : 'smooth',
        block: 'nearest'
      });
    }
  };

  const handleFlagClick = (ruleZeroIdx: number) => {
    toggleAccordion(ruleZeroIdx);
    const ruleNum = ruleZeroIdx + 1;
    setActiveHighlightedRule(prev => (prev === ruleNum ? null : ruleNum));

    const markEl = document.getElementById(`mark-rule-${ruleNum}`);
    if (markEl) {
      const prefersReducedMotion = typeof window !== 'undefined' && 
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      markEl.scrollIntoView({
        behavior: prefersReducedMotion ? 'auto' : 'smooth',
        block: 'nearest'
      });
    }
  };

  const handleRunTestMode = () => {
    const results = SAMPLE_DATASET.map(sample => {
      const res = analyzeMessage(sample.text);
      return {
        id: sample.id,
        name: sample.name,
        expected: sample.expected,
        actual: res.level,
        pass: res.level === sample.expected
      };
    });
    setTestResults(results);
    setTestSuiteRan(true);
  };

  const handleCopySafeReply = async () => {
    const replyText = generateSafeReplyText();
    let succeeded = false;

    if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(replyText);
        succeeded = true;
      } catch {
        succeeded = false;
      }
    }

    if (!succeeded && typeof document !== 'undefined') {
      try {
        const textArea = document.createElement('textarea');
        textArea.value = replyText;
        textArea.setAttribute('readonly', '');
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        succeeded = document.execCommand('copy');
        document.body.removeChild(textArea);
      } catch {
        succeeded = false;
      }
    }

    if (succeeded) {
      setCopyReplyState('copied');
      setTimeout(() => {
        setCopyReplyState('idle');
      }, 2000);
    } else {
      setCopyReplyState('failed');
      setTimeout(() => {
        setCopyReplyState('idle');
      }, 4000);
    }
  };

  const getVerdictPresentation = (level: 'LIKELY SCAM' | 'SUSPICIOUS' | "CAN'T TELL") => {
    switch (level) {
      case 'LIKELY SCAM':
        return {
          title: 'Likely scam',
          badgeText: 'LIKELY SCAM',
          badgeClass: 'badge-scam',
          cardClass: 'verdict-scam',
          icon: <AlertTriangle size={22} aria-hidden="true" />
        };
      case 'SUSPICIOUS':
        return {
          title: 'Suspicious',
          badgeText: 'SUSPICIOUS',
          badgeClass: 'badge-suspicious',
          cardClass: 'verdict-suspicious',
          icon: <ShieldAlert size={22} aria-hidden="true" />
        };
      case "CAN'T TELL":
      default:
        return {
          title: "Can't tell",
          badgeText: "CAN'T TELL",
          badgeClass: 'badge-canttell',
          cardClass: 'verdict-canttell',
          icon: <HelpCircle size={22} aria-hidden="true" />
        };
    }
  };

  const highlightedSegments = analysis 
    ? buildHighlightedSegments(inputText, analysis.triggeredRules)
    : [];

  const passedTestCount = testResults.filter(t => t.pass).length;

  return (
    <div className="page-wrapper">
      {/* Top Banner Navigation: Consolidated Single Privacy Line */}
      <header className="site-header">
        <div className="header-inner">
          <div className="brand-group">
            <span className="brand-mark" aria-hidden="true">
              <ShieldCheck size={18} />
            </span>
            <div className="brand-copy">
              <span className="brand-title">OfferShield</span>
              <span className="brand-subtitle">Job &amp; internship scam checker for Indian students</span>
            </div>
          </div>

          <div className="header-privacy-notice" role="status">
            <Lock size={13} aria-hidden="true" />
            <span>Runs 100% in-browser &bull; Pasted text never leaves your device</span>
          </div>
        </div>
      </header>

      <main className="main-content" id="main-content">
        {/* Compact Hero Intro */}
        <section className="intro-section" aria-labelledby="intro-heading">
          <h1 id="intro-heading" className="intro-title">
            Check a suspicious job or internship offer
          </h1>
          <p className="intro-description">
            Paste any email, WhatsApp message, or direct message you received to review marked phrases and examine why they are unusual before you reply or transfer money.
          </p>
        </section>

        {/* Two-Column Tool Section */}
        <div className="tool-grid">
          {/* Left Column: Input on top (shorter ~5 rows) + Marked message under it */}
          <div className="tool-column left-column">
            {/* Input Panel */}
            <section className="panel input-panel" aria-labelledby="input-heading">
              <div className="panel-bar-compact">
                <h2 id="input-heading" className="panel-heading-compact">
                  Paste the message you received
                </h2>
                <div className="char-count-badge" id="char-count" aria-live="polite">
                  {inputText.length.toLocaleString()} characters
                </div>
              </div>

              <div className="textarea-container">
                <label htmlFor="message-input" className="sr-only">
                  Offer message text
                </label>
                <textarea
                  id="message-input"
                  className="compact-textarea"
                  rows={5}
                  placeholder="Paste the suspicious message here..."
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  aria-describedby="char-count"
                />
              </div>

              <div className="input-panel-footer">
                <div className="button-group">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={handleAnalyze}
                    disabled={!inputText.trim()}
                  >
                    <Search size={16} aria-hidden="true" />
                    Analyze message
                  </button>

                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={handleClear}
                    disabled={!inputText && !hasAnalyzed}
                  >
                    <Trash2 size={16} aria-hidden="true" />
                    Clear
                  </button>
                </div>

                <div className="input-status-note">
                  <ShieldCheck size={15} aria-hidden="true" />
                  <span>Evaluated against 9 rule checks</span>
                </div>
              </div>
            </section>

            {/* Marked Message Directly Under Input */}
            {hasAnalyzed && analysis && (
              <section className="panel markup-panel" aria-labelledby="markup-heading">
                <div className="panel-bar-compact">
                  <h3 id="markup-heading" className="panel-heading-compact">
                    Marked message text
                  </h3>
                  <span className="panel-meta-label">
                    {analysis.triggeredRules.length} flagged phrase{analysis.triggeredRules.length === 1 ? '' : 's'}
                  </span>
                </div>

                <div 
                  className="markup-content-box" 
                  tabIndex={0}
                  role="region" 
                  aria-label="Pasted message with highlighted red flags"
                >
                  {highlightedSegments.map((seg, idx) => {
                    if (!seg.isMatch) {
                      return <span key={idx} className="plain-text-node">{seg.text}</span>;
                    }
                    const isStrong = seg.strength === 'strong';
                    const isSelected = seg.ruleIndices?.some(ri => ri === activeHighlightedRule);
                    return (
                      <mark
                        key={idx}
                        id={seg.ruleIndices?.[0] ? `mark-rule-${seg.ruleIndices[0]}` : undefined}
                        tabIndex={0}
                        role="button"
                        className={`highlighter-mark ${isStrong ? 'mark-strong' : 'mark-weak'} ${isSelected ? 'mark-selected' : ''}`}
                        title={seg.ruleNames?.join(' & ')}
                        aria-label={`Flag ${seg.ruleIndices?.join(', ')}: ${seg.ruleNames?.join(' and ')} (${isStrong ? 'Strong red flag' : 'Weak signal'})`}
                        onClick={() => handleMarkClick(seg.ruleIndices || [])}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleMarkClick(seg.ruleIndices || []);
                          }
                        }}
                      >
                        <span className="mark-text">{seg.text}</span>
                        <sup 
                          className={`mark-indicator ${isStrong ? 'indicator-strong' : 'indicator-weak'}`}
                          aria-hidden="true"
                        >
                          [{seg.ruleIndices?.join(', ')}]
                        </sup>
                      </mark>
                    );
                  })}
                </div>

                {/* Highlight Key: Single compact legend line under marked message */}
                <div className="highlight-legend-inline" aria-label="Highlight key">
                  <span className="legend-lead">Key:</span>
                  <span className="legend-chip">
                    <span className="legend-swatch swatch-solid" aria-hidden="true"></span>
                    <span>Solid = Strong flag</span>
                  </span>
                  <span className="legend-chip">
                    <span className="legend-swatch swatch-dashed" aria-hidden="true"></span>
                    <span>Dashed = Weak flag</span>
                  </span>
                  <span className="legend-chip-hint">(click mark to view red flag)</span>
                </div>
              </section>
            )}
          </div>

          {/* Right Column: Verdict, Observed Red Flags (Accordion), Conclusion, Safe Next Steps */}
          {hasAnalyzed && analysis && (
            <div className="tool-column right-column" aria-live="polite">
              {/* Verdict Card */}
              <section className={`panel verdict-card ${getVerdictPresentation(analysis.level).cardClass}`} aria-labelledby="verdict-heading">
                <div className="verdict-header">
                  <span className="verdict-label">Verdict</span>
                  <div className={`verdict-pill ${getVerdictPresentation(analysis.level).badgeClass}`}>
                    {getVerdictPresentation(analysis.level).icon}
                    <span>{getVerdictPresentation(analysis.level).badgeText}</span>
                  </div>
                </div>

                <div className="verdict-body">
                  <h3 id="verdict-heading" className="verdict-title">
                    {getVerdictPresentation(analysis.level).title}
                  </h3>
                  <p className="verdict-summary">
                    {buildVerdictDescription(analysis)}
                  </p>
                </div>
              </section>

              {/* Observed Red Flags as Accordion */}
              <section className="panel flags-panel" aria-labelledby="flags-heading">
                <div className="panel-bar-compact">
                  <h3 id="flags-heading" className="panel-heading-compact">
                    Observed red flags
                  </h3>
                  <span className="panel-meta-label">
                    {analysis.triggeredRules.length} rule{analysis.triggeredRules.length === 1 ? '' : 's'} triggered
                  </span>
                </div>

                {analysis.triggeredRules.length === 0 ? (
                  <div className="empty-flags-box">
                    <CheckCircle2 size={18} aria-hidden="true" />
                    <span>No predefined red flag patterns were observed in this text.</span>
                  </div>
                ) : (
                  <div className="accordion-stack">
                    {analysis.triggeredRules.map((rule, idx) => {
                      const isStrong = rule.strength === 'strong';
                      const isExpanded = expandedIndices.includes(idx);
                      const isRuleActive = activeHighlightedRule === idx + 1;
                      return (
                        <div 
                          key={idx} 
                          id={`flag-accordion-${idx}`}
                          className={`accordion-item ${isRuleActive ? 'accordion-item-active' : ''}`}
                        >
                          <button
                            type="button"
                            className={`accordion-trigger ${isRuleActive ? 'trigger-active' : ''}`}
                            onClick={() => handleFlagClick(idx)}
                            aria-expanded={isExpanded}
                            aria-controls={`flag-content-${idx}`}
                          >
                            <span className="accordion-title">
                              [{idx + 1}] {rule.name}
                            </span>
                            <div className="accordion-meta">
                              <span className={`flag-item-tag ${isStrong ? 'tag-strong' : 'tag-weak'}`}>
                                {isStrong ? 'Strong rule' : 'Weak rule'}
                              </span>
                              {isExpanded ? (
                                <ChevronUp size={16} aria-hidden="true" />
                              ) : (
                                <ChevronDown size={16} aria-hidden="true" />
                              )}
                            </div>
                          </button>

                          {isExpanded && (
                            <div 
                              id={`flag-content-${idx}`} 
                              className="accordion-content"
                            >
                              <div className="flag-quote-line">
                                <span className="flag-quote-label">Matched text:</span>
                                <span className="flag-quote-value">&ldquo;{rule.matchedText}&rdquo;</span>
                              </div>
                              <p className="flag-item-why">
                                {rule.whyItMatters}
                              </p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* Our Conclusion */}
              <section className="panel conclusion-panel" aria-labelledby="conclusion-heading">
                <h3 id="conclusion-heading" className="panel-heading-compact">
                  Our conclusion
                </h3>
                <p className="conclusion-text">
                  {analysis.scoreExplanation}
                </p>
              </section>

              {/* Safe Next Steps (Compact) */}
              <section className="panel next-steps-panel" aria-labelledby="steps-heading">
                <h3 id="steps-heading" className="panel-heading-compact">
                  Safe next steps
                </h3>
                <ol className="safe-steps-list-compact">
                  <li className="safe-step-item">
                    <span className="step-badge" aria-hidden="true">1</span>
                    <span><strong>Never share OTPs or transfer money:</strong> Authentic recruiters never charge fees or ask for PINs.</span>
                  </li>
                  <li className="safe-step-item">
                    <span className="step-badge" aria-hidden="true">2</span>
                    <span><strong>Verify openings directly:</strong> Manually search official careers portals (e.g. https://company.com/careers).</span>
                  </li>
                  <li className="safe-step-item">
                    <span className="step-badge" aria-hidden="true">3</span>
                    <span><strong>Check sender domain:</strong> Look for company domains rather than free webmail (@gmail.com).</span>
                  </li>
                  <li className="safe-step-item">
                    <span className="step-badge" aria-hidden="true">4</span>
                    <span><strong>Ask your placement cell:</strong> Consult your college placement officer (TPO) before sharing documents.</span>
                  </li>
                </ol>

                <div className="action-buttons-row">
                  <button
                    type="button"
                    className={`btn-action ${copyReplyState === 'copied' ? 'btn-action-active' : ''} ${copyReplyState === 'failed' ? 'btn-action-failed' : ''}`}
                    onClick={handleCopySafeReply}
                    aria-label="Copy polite safe reply to clipboard"
                  >
                    {copyReplyState === 'copied' ? (
                      <>
                        <Check size={15} aria-hidden="true" />
                        <span>Copied</span>
                      </>
                    ) : copyReplyState === 'failed' ? (
                      <span>Copy failed, select the text manually</span>
                    ) : (
                      <>
                        <Copy size={15} aria-hidden="true" />
                        <span>Copy safe reply</span>
                      </>
                    )}
                  </button>
                </div>
              </section>
            </div>
          )}
        </div>

        {/* Tabs Below the Main Tool (Samples | Test mode | Limitations) */}
        <section className="tabs-container" aria-label="Reference sections">
          <div className="tab-nav" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'samples'}
              aria-controls="tab-samples-panel"
              id="tab-samples"
              className={`tab-btn ${activeTab === 'samples' ? 'tab-btn-active' : ''}`}
              onClick={() => setActiveTab('samples')}
            >
              Try sample messages
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'test'}
              aria-controls="tab-test-panel"
              id="tab-test"
              className={`tab-btn ${activeTab === 'test' ? 'tab-btn-active' : ''}`}
              onClick={() => setActiveTab('test')}
            >
              Run test mode
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'limitations'}
              aria-controls="tab-limitations-panel"
              id="tab-limitations"
              className={`tab-btn ${activeTab === 'limitations' ? 'tab-btn-active' : ''}`}
              onClick={() => setActiveTab('limitations')}
            >
              Limitations &amp; privacy
            </button>
          </div>

          {/* Tab 1: Samples */}
          {activeTab === 'samples' && (
            <div 
              id="tab-samples-panel" 
              role="tabpanel" 
              aria-labelledby="tab-samples"
              className="panel tab-panel"
            >
              <div className="tab-panel-intro">
                <h3 className="tab-panel-title">Try sample messages</h3>
                <p className="tab-panel-desc">
                  Select standard sample messages encountered by university students across India to preview rule evaluations.
                </p>
              </div>

              <div className="samples-list">
                {SAMPLE_DATASET.map((sample) => (
                  <div key={sample.id} className="sample-card">
                    <div className="sample-card-main">
                      <div className="sample-name-row">
                        <strong className="sample-name">{sample.name}</strong>
                        <span className="sample-company-tag">{sample.company}</span>
                      </div>
                      <p className="sample-excerpt">
                        &ldquo;{sample.text.slice(0, 130)}...&rdquo;
                      </p>
                    </div>

                    <div className="sample-card-side">
                      <div className={`verdict-pill ${getVerdictPresentation(sample.expected).badgeClass}`}>
                        {getVerdictPresentation(sample.expected).icon}
                        <span>{sample.expected}</span>
                      </div>

                      <button
                        type="button"
                        className="btn btn-sample-load"
                        onClick={() => loadSample(sample)}
                        aria-label={`Load ${sample.name} into message input`}
                      >
                        Load into parser
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 2: Test Mode */}
          {activeTab === 'test' && (
            <div 
              id="tab-test-panel" 
              role="tabpanel" 
              aria-labelledby="tab-test"
              className="panel tab-panel"
            >
              <div className="test-section-header">
                <div>
                  <h3 className="tab-panel-title">Run test mode</h3>
                  <p className="tab-panel-desc">
                    Verify parser evaluations across standard test cases and inspect pass/fail outcomes.
                  </p>
                </div>

                <button
                  type="button"
                  className="btn btn-run-tests"
                  onClick={handleRunTestMode}
                >
                  <Play size={15} aria-hidden="true" />
                  <span>Run test mode</span>
                </button>
              </div>

              <div className="test-table-wrapper" role="region" aria-label="Test suite results table">
                <table className="test-table">
                  <thead>
                    <tr>
                      <th scope="col">Sample name</th>
                      <th scope="col">Expected</th>
                      <th scope="col">Actual</th>
                      <th scope="col">Pass / Fail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {testResults.map((t) => (
                      <tr key={t.id}>
                        <td className="table-cell-name">
                          <strong>{t.name}</strong>
                        </td>
                        <td>
                          <span className={`table-badge ${getVerdictPresentation(t.expected).badgeClass}`}>
                            {t.expected}
                          </span>
                        </td>
                        <td>
                          <span className={`table-badge ${getVerdictPresentation(t.actual).badgeClass}`}>
                            {t.actual}
                          </span>
                        </td>
                        <td>
                          {t.pass ? (
                            <span className="pass-status pass-ok">
                              <Check size={16} aria-hidden="true" />
                              <span>Pass</span>
                            </span>
                          ) : (
                            <span className="pass-status pass-fail">
                              <AlertTriangle size={15} aria-hidden="true" />
                              <span>Fail</span>
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="test-summary-footer">
                <span className="test-pass-count">
                  <strong>{passedTestCount} of {testResults.length} passed</strong>
                </span>
                {testSuiteRan && (
                  <span className="test-suite-status-tag">Test suite re-evaluated</span>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Limitations & Privacy */}
          {activeTab === 'limitations' && (
            <div 
              id="tab-limitations-panel" 
              role="tabpanel" 
              aria-labelledby="tab-limitations"
              className="panel tab-panel"
            >
              <h3 className="tab-panel-title">Limitations and privacy</h3>
              <p className="limitations-body">
                OfferShield operates strictly on heuristic pattern analysis of written text. It does not authenticate corporate domains or connect to external databases. Always verify hiring opportunities with your university placement cell or directly via official company careers portals.
              </p>
              <p className="limitations-body limitations-body-follow">
                All text analysis is performed entirely inside your local browser session. No pasted communications, phone numbers, or candidate identification tokens are recorded, archived, or transmitted over network sockets.
              </p>
            </div>
          )}
        </section>
      </main>

      {/* Footer: Exactly Two Lines */}
      <footer className="site-footer">
        <div className="footer-inner">
          <p className="footer-line-1">
            This is a rule-based checker and can be wrong. Real offers can have odd wording; clever scams can look professional. Nothing you paste is stored or sent anywhere.
          </p>
          <p className="footer-line-2">
            National Cyber Crime Reporting Portal: cybercrime.gov.in | Cyber Crime Helpline: 1930
          </p>
        </div>
      </footer>
    </div>
  );
}
