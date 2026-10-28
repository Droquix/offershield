import { describe, it, expect } from 'vitest';
import { analyzeMessage, RULES } from './analyzer';

describe('OfferShield Analyzer Rules & Scoring', () => {
  // Test Rule 1: OTP / PIN / CVV
  it('triggers Rule 1 alone and scores as LIKELY SCAM (English)', () => {
    const text = 'Hello candidate, please share your OTP to confirm your offer letter.';
    const result = analyzeMessage(text);
    expect(result.level).toBe('LIKELY SCAM');
    const rule1 = result.triggeredRules.find(r => r.id === 'rule_1_otp_pin');
    expect(rule1).toBeDefined();
    expect(rule1?.strength).toBe('strong');
  });

  it('triggers Rule 1 with Hinglish like "OTP batao" or "OTP share karo"', () => {
    const text1 = 'Offer letter generate ho gaya hai, apna OTP batao jaldi.';
    const result1 = analyzeMessage(text1);
    expect(result1.level).toBe('LIKELY SCAM');
    expect(result1.triggeredRules.some(r => r.id === 'rule_1_otp_pin')).toBe(true);

    const text2 = 'Sir verification ke liye OTP share karo.';
    const result2 = analyzeMessage(text2);
    expect(result2.level).toBe('LIKELY SCAM');
    expect(result2.triggeredRules.some(r => r.id === 'rule_1_otp_pin')).toBe(true);
  });

  // Test Rule 2: Upfront fees / deposits
  it('triggers Rule 2 for registration fee and security deposit', () => {
    const text = 'You are selected! Please pay refundable security deposit of ₹2500 for company laptop.';
    const result = analyzeMessage(text);
    expect(result.triggeredRules.some(r => r.id === 'rule_2_upfront_fee')).toBe(true);
  });

  it('triggers Rule 2 for Hinglish fee demands like "fee jama karo" or "paisa bhejo"', () => {
    const text1 = 'Training ke liye registration fee jama karo turant.';
    const result1 = analyzeMessage(text1);
    expect(result1.triggeredRules.some(r => r.id === 'rule_2_upfront_fee')).toBe(true);

    const text2 = 'Laptop security ke liye paisa bhejo ₹1500.';
    const result2 = analyzeMessage(text2);
    expect(result2.triggeredRules.some(r => r.id === 'rule_2_upfront_fee')).toBe(true);
  });

  // Test Rule 3: Sensitive documents requested over chat/email without interview
  it('triggers Rule 3 for Aadhaar and PAN requests without interview', () => {
    const text = 'Send your Aadhaar card and PAN card copy for verification.';
    const result = analyzeMessage(text);
    expect(result.triggeredRules.some(r => r.id === 'rule_3_sensitive_documents')).toBe(true);
  });

  // Test Scoring: 2 or more strong rules -> LIKELY SCAM
  it('scores LIKELY SCAM when 2 strong rules are triggered', () => {
    const text = 'Pay registration fee of ₹1000 and send your Aadhaar card copy.';
    const result = analyzeMessage(text);
    expect(result.level).toBe('LIKELY SCAM');
    const strongRules = result.triggeredRules.filter(r => r.strength === 'strong');
    expect(strongRules.length).toBeGreaterThanOrEqual(2);
  });

  // Test Scoring: 1 strong rule (fee/docs) + 2 or more weak -> LIKELY SCAM
  it('scores LIKELY SCAM when 1 strong rule (fee) is paired with 2 or more weak rules', () => {
    // Strong: registration fee
    // Weak 1: urgency ("within 2 hours")
    // Weak 2: free email (@gmail.com)
    const text = 'You must deposit registration fee of ₹1500 within 2 hours or offer will be cancelled. Email us at recruiter@gmail.com';
    const result = analyzeMessage(text);
    expect(result.level).toBe('LIKELY SCAM');
  });

  // Test Scoring: 1 strong rule + fewer than 2 weak -> SUSPICIOUS
  it('scores SUSPICIOUS when exactly 1 strong rule is present with 0 or 1 weak rule', () => {
    // Exactly 1 strong rule (registration fee), 0 weak
    const text1 = 'Please submit your registration fee for the company portal setup.';
    const result1 = analyzeMessage(text1);
    expect(result1.level).toBe('SUSPICIOUS');

    // Exactly 1 strong rule (registration fee) + 1 weak rule (urgency)
    const text2 = 'Please submit your registration fee within 24 hours.';
    const result2 = analyzeMessage(text2);
    expect(result2.level).toBe('SUSPICIOUS');
  });

  // Test Scoring: No strong rules, 3 or more weak -> SUSPICIOUS
  it('scores SUSPICIOUS when 0 strong rules and 3 or more weak rules are present', () => {
    // Weak 1: urgency ("last chance")
    // Weak 2: WhatsApp only ("contact on WhatsApp")
    // Weak 3: shortened link ("bit.ly/job-test")
    const text = 'Last chance for direct joining! Contact on WhatsApp: https://bit.ly/job-test';
    const result = analyzeMessage(text);
    const strongCount = result.triggeredRules.filter(r => r.strength === 'strong').length;
    const weakCount = result.triggeredRules.filter(r => r.strength === 'weak').length;
    expect(strongCount).toBe(0);
    expect(weakCount).toBeGreaterThanOrEqual(3);
    expect(result.level).toBe('SUSPICIOUS');
  });

  // Test Scoring: everything else -> CAN'T TELL
  it('scores CAN\'T TELL for 0 strong rules and 1 or 2 weak rules', () => {
    // Only 1 weak rule (shortened link)
    const text1 = 'Check the job overview at https://bit.ly/sample-job-spec';
    const result1 = analyzeMessage(text1);
    expect(result1.level).toBe("CAN'T TELL");

    // Only 2 weak rules (urgency + shortened link)
    const text2 = 'Hurry up! Check the details at https://bit.ly/job';
    const result2 = analyzeMessage(text2);
    expect(result2.level).toBe("CAN'T TELL");
  });

  it('scores CAN\'T TELL for zero red flags or empty input', () => {
    const text = 'We invite you to attend an on-campus placement presentation by Tata Consultancy Services tomorrow at 10 AM in the auditorium.';
    const result = analyzeMessage(text);
    expect(result.level).toBe("CAN'T TELL");
    expect(result.triggeredRules.length).toBe(0);

    const emptyResult = analyzeMessage('');
    expect(emptyResult.level).toBe("CAN'T TELL");
  });

  it('never outputs "safe" or "legitimate"', () => {
    const benignText = 'Dear student, your resume has been received for the summer internship.';
    const result = analyzeMessage(benignText);
    expect(result.level).not.toBe('SAFE');
    expect(result.level).not.toBe('LEGITIMATE');
    expect(result.level).toBe("CAN'T TELL");
  });

  it('verifies all 9 required rules exist in catalog', () => {
    expect(RULES.length).toBe(9);
    const strongRules = RULES.filter(r => r.strength === 'strong');
    const weakRules = RULES.filter(r => r.strength === 'weak');
    expect(strongRules.length).toBe(3);
    expect(weakRules.length).toBe(6);
  });

  it('correctly provides scoreFormula and match indices for inline highlighting', () => {
    const text = 'Pay registration fee of ₹1500 within 2 hours or cancel offer.';
    const result = analyzeMessage(text);
    expect(result.scoreFormula).toBe('1 strong + 1 weak');
    expect(result.level).toBe('SUSPICIOUS');

    const feeRule = result.triggeredRules.find(r => r.id === 'rule_2_upfront_fee');
    expect(feeRule).toBeDefined();
    expect(feeRule?.startIndex).toBeDefined();
    expect(feeRule?.endIndex).toBeDefined();
    expect(feeRule!.endIndex!).toBeGreaterThan(feeRule!.startIndex!);
  });
});
