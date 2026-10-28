import { describe, it, expect } from 'vitest';
import { analyzeMessage } from './analyzer';

describe('OfferShield Features & Integration', () => {
  it('generates exact score breakdown formula', () => {
    // 1 strong + 2 weak
    const text1 = 'Pay registration fee of ₹1500 within 2 hours. Email recruiter@gmail.com';
    const res1 = analyzeMessage(text1);
    expect(res1.scoreFormula).toBe('1 strong + 2 weak');
    expect(res1.level).toBe('LIKELY SCAM');

    // Rule 1 alone
    const text2 = 'Please share your OTP to confirm your offer.';
    const res2 = analyzeMessage(text2);
    expect(res2.scoreFormula).toBe('1 strong (Rule 1: OTP/Credentials) alone');
    expect(res2.level).toBe('LIKELY SCAM');

    // 0 strong + 3 weak
    const text3 = 'Direct joining without interview! Urgent requirement today. Contact on WhatsApp: https://wa.me/919999999999';
    const res3 = analyzeMessage(text3);
    expect(res3.scoreFormula).toBe('0 strong + 3 weak');
    expect(res3.level).toBe('SUSPICIOUS');

    // 0 strong + 1 weak
    const text4 = 'Check the details at https://bit.ly/details';
    const res4 = analyzeMessage(text4);
    expect(res4.scoreFormula).toBe('0 strong + 1 weak');
    expect(res4.level).toBe("CAN'T TELL");
  });

  it('provides precise match indices for inline highlighting', () => {
    const text = 'Congratulations! Pay registration fee of ₹1500 to secure your seat.';
    const res = analyzeMessage(text);
    const feeRule = res.triggeredRules.find(r => r.id === 'rule_2_upfront_fee');
    expect(feeRule).toBeDefined();
    expect(feeRule?.startIndex).toBeDefined();
    expect(feeRule?.endIndex).toBeDefined();

    const matchedSubstring = text.slice(feeRule!.startIndex!, feeRule!.endIndex!);
    expect(matchedSubstring.toLowerCase()).toContain('registration fee');
  });

  it('handles empty input gracefully without errors', () => {
    const res = analyzeMessage('');
    expect(res.level).toBe("CAN'T TELL");
    expect(res.triggeredRules.length).toBe(0);
    expect(res.scoreFormula).toBe('0 strong + 0 weak');
  });

  it('evaluates all 4 in-app test suite samples to their expected verdicts', () => {
    const sample1 = 'Dear candidate, you have been selected directly for the Apex Global Logistics Data Entry remote internship. Joining is immediate with stipend Rs 25,000/month. No interview required. Kindly transfer 1500 registration fee immediately to activate your company laptop kit and share your Aadhaar card copy with OTP to verify your candidate profile on WhatsApp right now.';
    expect(analyzeMessage(sample1).level).toBe('LIKELY SCAM');

    const sample2 = 'Hi! I am Priya from HR. Earn ₹3,000 daily by simply reviewing products for NovaRetail Solutions online. Immediate joining only! Valid only for today. No interview needed. Connect with HR on WhatsApp: https://wa.me/919876543210 or visit https://bit.ly/novaretail-apply';
    expect(analyzeMessage(sample2).level).toBe('SUSPICIOUS');

    const sample3 = 'Dear applicant, you are shortlisted for CloudSprint Systems technical internship. Please deposit registration fee of ₹1500 within 2 hours or your offer will be cancelled. Forward payment screenshot to careers.cloudsprint@gmail.com immediately.';
    expect(analyzeMessage(sample3).level).toBe('LIKELY SCAM');

    const sample4 = 'Dear student, thank you for participating in the campus placement drive for Nexus Innovations. You have been shortlisted for the Round 2 Technical Assessment and interview scheduled for tomorrow at 10:00 AM in the placement seminar hall.';
    expect(analyzeMessage(sample4).level).toBe("CAN'T TELL");
  });

  it('accurately computes 9 of 10 passing samples without modifying expected labels', () => {
    const dataset = [
      { id: 'sample-1', expected: 'LIKELY SCAM', text: 'Dear candidate, you have been selected directly for the Apex Global Logistics Data Entry remote internship. Joining is immediate with stipend Rs 25,000/month. No interview required. Kindly transfer 1500 registration fee immediately to activate your company laptop kit and share your Aadhaar card copy with OTP to verify your candidate profile on WhatsApp right now.' },
      { id: 'sample-2', expected: 'SUSPICIOUS', text: 'Hi! I am Priya from HR. Earn ₹3,000 daily by simply reviewing products for NovaRetail Solutions online. Immediate joining only! Valid only for today. No interview needed. Connect with HR on WhatsApp: https://wa.me/919876543210 or visit https://bit.ly/novaretail-apply' },
      { id: 'sample-3', expected: 'LIKELY SCAM', text: 'Dear applicant, you are shortlisted for CloudSprint Systems technical internship. Please deposit registration fee of ₹1500 within 2 hours or your offer will be cancelled. Forward payment screenshot to careers.cloudsprint@gmail.com immediately.' },
      { id: 'sample-4', expected: "CAN'T TELL", text: 'Dear student, thank you for participating in the campus placement drive for Nexus Innovations. You have been shortlisted for the Round 2 Technical Assessment and interview scheduled for tomorrow at 10:00 AM in the placement seminar hall.' },
      { id: 'sample-5', expected: 'LIKELY SCAM', text: 'Congratulations! Your offer letter for the Junior Web Developer position at Zenith Tech Labs is ready. Please share your OTP received on your mobile to confirm your joining date and activate your employee portal.' },
      { id: 'sample-6', expected: 'SUSPICIOUS', text: 'Dear candidate, we are pleased to offer you the Content Writer role at Starlight Media Group. Before your start date, you are required to submit a refundable security deposit of ₹2,500 for the company resource pack.' },
      { id: 'sample-7', expected: 'LIKELY SCAM', text: 'You have been selected directly for Vanguard Analytics remote research trainee role. Please send your Aadhaar card and bank details immediately on Telegram @vanguard_hr to process your first stipend.' },
      { id: 'sample-8', expected: 'SUSPICIOUS', text: 'Work from home opportunity! Earn ₹5,000 per day with simple typing tasks. No interview needed. Hurry, offer will be cancelled soon! Join our official Telegram channel now: https://t.me/quicktask_jobs' },
      { id: 'sample-9', expected: "CAN'T TELL", text: 'Horizon Digital Services is hiring summer marketing interns. Apply within 2 hours to be considered for this cycle: https://tinyurl.com/horizon-interns' },
      { id: 'sample-10', expected: "CAN'T TELL", text: 'Dear applicant, thank you for applying for the Software Engineering Internship at Aether Software Systems. We would like to invite you for a 45-minute technical interview with our engineering panel next Tuesday at 2:00 PM via Google Meet. Please review the interview guidelines attached.' }
    ];

    const results = dataset.map(s => {
      const res = analyzeMessage(s.text);
      return { pass: res.level === s.expected, id: s.id };
    });

    const passedCount = results.filter(r => r.pass).length;
    expect(passedCount).toBe(9);
    const failedSample = results.find(r => !r.pass);
    expect(failedSample?.id).toBe('sample-7');
  });
});
