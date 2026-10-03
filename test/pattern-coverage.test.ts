import { describe, expect, it } from 'vitest';

import { buildContext } from '../src/analysis/context.js';
import { __testables } from '../src/analysis/rules/content.js';
import { normalizeForMatching } from '../src/shared/text.js';
import { loadAllFixtures } from './fixtures/load.js';

/**
 * Every wording pattern, and every word in its alternations, must be reachable from natural text.
 *
 * A pattern can be valid, compile, sit inside a theme that fires on its fixture, and still contain words
 * that never match anything: `\b(terminat|deactivat)\b` reads as covering "terminated" and matches
 * neither, and `i (have|'ve)` reads as covering "I've" and needs a space before the apostrophe. Both
 * can sit behind live alternatives that keep every other test green. The only check that sees this
 * is one that asks for each alternative to appear, as itself, inside a real match of its own pattern.
 *
 * So the corpus is deliberately prose a sender would write, not strings built from the regex: a
 * constructed "your account will be terminat" would match and prove nothing. Examples are added here only
 * where no fixture already supplies the wording.
 */
const EXAMPLES: readonly string[] = [
  // urgency
  'Please send it today or the order will be cancelled.',
  'Failure to comply will result in a penalty.',
  'Failure to do so will close the case.',
  // credential_verification
  'Update your account info using the form below.',
  'Submit your KYC documents to keep trading.',
  'Sign in to reactivate your membership.',
  'Tap the button below to sign in.',
  'Your password must be updated before Friday.',
  'Please confirm this is really you.',
  'Confirm you are the account holder before we continue.',
  'Confirm that you are the owner of this mailbox.',
  'Confirm you are the intended recipient of these files.',
  'Confirm you are the registered user of the device.',
  // password_reset_pressure
  'Your password has been changed.',
  // account_threat
  'Your billing profile will be restricted tomorrow.',
  'Your account is pending deactivation.',
  'Your mailbox is set for deletion.',
  'Your account will soon be terminated.',
  'Your account will be closed if you do not respond.',
  'We will close your account at the end of the month.',
  'Act today to prevent suspension of your service.',
  'Sign in to avoid deletion of your files.',
  'Respond now to prevent termination of the service.',
  'Verify now to avoid loss of access.',
  'We will permanently delete the mailbox.',
  // mfa_request
  'Approve the sign-in request on your phone when you see it.',
  'Enter the OTP on the next screen.',
  'Enter your one-time code below.',
  'Enter the one-time password from the text message.',
  'Enter the one-time passcode we sent.',
  'Enter your one-time pin to continue.',
  'Enter the verification code on the page.',
  'Enter the security code from the app.',
  'Enter the authentication code from your authenticator.',
  'Enter your 2fa code now.',
  'Enter the mfa code on the portal.',
  'Enter the sms code we sent you.',
  'Enter the access code to join.',
  'Enter your upi pin to approve the request.',
  // wire_transfer
  'The bank transfer is ready.',
  'The payment transmission failed overnight.',
  'Please release USD 48,500 to the supplier this morning.',
  'The SWIFT code is on the attached letter.',
  'Use BIC code: NWBKGB2L for the payment.',
  'The beneficiary bank has been updated.',
  // payment_detail_change
  'Please update our banking instructions on file.',
  'Our banking details have changed.',
  'The account information has been updated.',
  'Please use the following payment instructions from now on.',
  'Note the new remittance details below.',
  'This is a change of banking details for our firm.',
  'Notice of change to payment instructions.',
  // billing_update
  'Update your billing info to keep your plan.',
  // payroll_change
  'Please change the bank account for my pay this month.',
  'I opened a bank account for my wages.',
  'I need a new bank account for my paycheck.',
  'My new account at the credit union is for payroll.',
  'Can you change where my salary goes from next month?',
  'I would like to update where my pay is sent.',
  'Please change where my wages go.',
  'I need to update where my salary is deposited.',
  // gift_card
  'Can you buy 5 gift vouchers for the team?',
  'I need you to order several gift certificates today.',
  'Pick up prepaid vouchers worth $100 each.',
  'Scratch the back to reveal the codes on the cards.',
  'Send me the codes on the back of the cards.',
  'The cards have a code on the back, photograph the codes.',
  'Get the gift cards today and send them.',
  // invoice_fraud: fixtures cover it
  // secrecy
  'Keep this between us for now.',
  'Do not discuss this with anyone.',
  "Don't mention this to the others.",
  'Do not inform the finance team yet.',
  "Don't tell anyone about the acquisition.",
  'This is a confidential matter.',
  'It is a private arrangement with the vendor.',
  'This is a discreet deal I am handling.',
  'No one else needs to know about this.',
  'Keep it quiet until we go public next week.',
  'Wait until I tell the board.',
  'Hold off until we inform the partners.',
  'This is strictly confidential.',
  // process_bypass
  'Please email me instead, I cannot take calls.',
  'I need you to handle this for me quickly.',
  // unusual_request_shape
  'Can you help me with something?',
  'Hi, can you assist me with a task?',
  'Are you around this afternoon?',
  'Are you busy right now?',
  'I have an urgent task for you.',
  'I have a small favour to ask.',
  // crypto_demand: fixtures cover it
  // sextortion
  "I've recorded you through your webcam.",
  'I have filmed you without your knowledge.',
  'I have captured your screen and your camera.',
  "I've installed malware on your computer.",
  'I have installed a program on your laptop.',
  'I have installed software on your pc.',
  'I have installed a tool in your webcam driver.',
  'I have access to your device.',
  'I have control of your accounts.',
  'I have full control over your computer.',
  'The webcam recording will be sent to your contacts.',
  'The camera footage will go to your contacts.',
  'The screen video will be shared with your contacts.',
  'I know your passphrase and much more.',
  "Pay within two days or I'll expose everything.",
  'Pay now or we will publish the video.',
  // prize_lure
  "You've won a prize in our draw.",
  'Claim your prize before Friday.',
  'Collect your reward today.',
  'Claim the winnings from your account.',
  'Receive the inheritance left to you.',
  'Collect your funds from the agent.',
  'There are unclaimed funds in your name.',
  'We hold an unclaimed inheritance for you.',
  'There is unclaimed money waiting for you.',
  'You have an unclaimed balance.',
  // mixed themes: alternatives nothing above reaches
  'If you do not act, the case will close.',
  "If you don't reply, we will proceed.",
  'Confirm it was you who signed in.',
  'Confirm you were the user who made this change.',
  'Your password is about to expire.',
  'Your password was reset by an administrator.',
  'Your password will be changed tonight.',
  'Your email access has been disabled.',
  'Your shared mailbox and account have been terminated.',
  'Your profile and account are disabled.',
  'Your account was deactivated yesterday.',
  'Your mailbox is now restricted.',
  'There was an unusual sign-in on your account.',
  'There has been a problem with your payment.',
  'Act now to avoid deactivation of your mailbox.',
  'Reply to prevent closure of your account.',
  'Please read us the verification code from the text.',
  'Approve the request when it receives the code.',
  'Your MFA app requires you to re-register now.',
  'Send the SWIFT number with the invoice.',
  'The recipient account is new.',
  'Add the beneficiary details below.',
  'Beneficiary information is attached.',
  'Please update the payee details on the invoice.',
  'Use the new deposit account from today.',
  'Our bank details have changed.',
  'Please use the updated payment details.',
  'Note the new payment account for future invoices.',
  'Change of remittance details effective today.',
  'Here is my payroll information.',
  'I opened my salary account at a new bank.',
  'Please process my direct deposit change.',
  'This is my paycheck update.',
  'Please use the bank account for my salary.',
  'My updated bank details are for salary.',
  'Please change where my wages are paid.',
  'Payment is required by Friday.',
  'The amount is pending.',
  'Payment is now outstanding.',
  'Your order of 3 items has shipped.',
  'Your purchase for $49.99 is complete.',
  'Your payment of $20 failed.',
  'You have been charged $99.',
  'You were charged twice.',
  'This is a confidential request.',
  'It is a private transaction.',
  'Nobody should know about this yet.',
  'No one must know.',
  'Hold it until we announce the deal.',
  'This is strictly between us.',
  'We can skip the usual approval this time.',
  'Do it yourself today please.',
  'I have a quick request.',
  'Send 0.05 bitcoin to the wallet below.',
  'The bitcoin wallet address for payment is below.',
  'Pay to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within two days.',
  'I have installed a keylogger on your device.',
  'I have installed a script into your system.',
  'I have installed an app on your phone.',
  'I have installed an extension in your browser.',
  'I know your password.',
  'This is one of your passwords: hunter2.',
  'Pay now or I will send the video to everyone.',
  'Send it or we will release the footage.',
  'Pay or I will share the clip with your family.',
  'Pay 0.1 BTC or I will publish the photos.',
  'Pay today or I will send it to all your contacts.',
  'Pay now or we will share it with your friends.',
  'Pay this week or I will send it to your colleagues.',
  'Reply today, otherwise the offer lapses.',
  'Complete your KYC now.',
  'Update your KYC details.',
  'Verify your KYC today.',
  'Click here to sign in.',
  'Use the link we sent to log in.',
  'Follow the link to sign in.',
  'Change your password every 90 days.',
  'Your access is suspended.',
  'Your profile is locked.',
  'Your mailbox is on hold.',
  'Your subscription is blocked.',
  'Your access will close at midnight.',
  'Your profile is closing.',
  'Your mailbox will be closed.',
  'Your subscription is closing soon.',
  'We are closing your access.',
  'Closure of your profile is scheduled.',
  'We will close your mailbox.',
  'We are closing your subscription.',
  'We will immediately suspend the service.',
  'Respond with the code we sent.',
  'Get back to me with the code.',
  'Transfer the funds today.',
  'Remit the amount by Friday.',
  'Wire the payment to the account.',
  'Please amend the bank details on file.',
  'Revise the remittance information.',
  'We use a different bank account now.',
  'My bank details have changed.',
  'Update your card details.',
  'Can you switch my direct deposit?',
  'Please redirect my salary.',
  'Please amend my payroll details.',
  'My new account is for direct deposit.',
  'My new bank will receive my pay.',
  'Could you get some gift cards for the clients?',
  'Would you pick up a few prepaid cards?',
  'I want you to obtain e-gift cards for the staff.',
  'Please grab two steam cards on the way.',
  'Kindly acquire itunes vouchers for the event.',
  'Get 4 gift cards from the store.',
  'Pick up some prepaid cards.',
  'Obtain several itunes cards.',
  'Grab a few steam cards.',
  'Acquire multiple gift cards.',
  'I need 10 gift cards.',
  'Photograph the codes on each card.',
  'Scan the pins from the cards.',
  'Share the codes from the vouchers.',
  'Forward the codes on the cards.',
  'Snap the pins on the back of the cards.',
  'On the cards, scratch off the codes.',
  'The vouchers have a strip behind which the codes sit.',
  'The cards have a panel at the back with the code.',
  'I need prepaid cards urgently.',
  'Gift cards asap please.',
  'Buy the gift cards right away.',
  'Gift vouchers immediately please.',
  'Get the gift cards before noon.',
  'Kindly find invoice attach for your payment.',
  'The bill is outstanding.',
  'The receipt shows the amount unpaid.',
  'The invoice is due tomorrow.',
  'The invoice is past due.',
  'The invoice is ready, please settle it today.',
  'This is an overdue invoice.',
  'There is an unpaid balance.',
  'A past due amount remains.',
  'Final demand for the account.',
  'Outstanding payment reminder.',
  'Keep this quiet before we announce it.',
  'Bypass the approval for this one.',
  'Do it without approval.',
  'There is no need for verification.',
  'Forget the usual procedure.',
  'Ignore the process this time.',
  'Override the authorization step.',
  'Circumvent the paperwork.',
  'Buy bitcoin and send it to me.',
  'Use ethereum to transfer the fee.',
  'Use usdt to pay the fee.',
  'Use crypto to deposit the amount.',
  'Send the bitcoin today.',
  'Transfer the btc now.',
  'Pay in ethereum.',
  'Deposit the eth today.',
  'Pay with usdt.',
  'Send crypto only.',
  'The webcam recording I will send to everyone.',
  'The camera footage I will release.',
  'The screen recording I will publish.',
  'The webcam video I will share.',
  'I have your password and more.',
  'Congratulations, you are our winner.',
  'You have won the lottery.',
  'You have been selected for a reward.',
  'Congratulations on your award.',
  'You have qualified for a gift.',
  'Congratulations, you have been selected.',
  'A refund is owed to you.',
  'Your rebate is due.',
  'Compensation is waiting for you.',
  'The overpayment is pending.',
  'Your tax return was approved.',
  'Your refund is eligible for release.',
];

/** Alternations of plain words that the pattern bounds on both sides, the only place a dead stem hides. */
function boundedAlternations(source: string): string[][] {
  const groups: string[][] = [];
  for (const match of source.matchAll(/\((?:\?:)?([a-z' |-]+)\)/g)) {
    const body = match[1] ?? '';
    if (!body.includes('|')) continue;
    const before = source.slice(0, match.index);
    const after = source.slice(match.index + match[0].length);
    // A group glued to a letter is a suffix (`limit(ed|ation)`), and one with nothing bounding it after is
    // a deliberate stem (`(delet|remov)`); neither is meant to be a word.
    if (/(?<!\\)[a-z]$/.test(before)) continue;
    if (!/^(?:\\b| |\?? |\)\\b)/.test(after)) continue;
    groups.push(body.split('|').filter((alternative) => alternative.trim() !== ''));
  }
  return groups;
}

function containsWord(text: string, word: string): boolean {
  // A contraction or a space-led alternative (`(?: will|'ll)`) is joined to the word before it.
  const lead = /^[' ]/.test(word) ? '' : '(?<![\\p{L}\\p{N}])';
  return new RegExp(`${lead}${word}(?![\\p{L}\\p{N}])`, 'u').test(text);
}

describe('wording pattern coverage', () => {
  const corpus = [
    ...loadAllFixtures().map((fixture) => buildContext(fixture.email).matchText),
    ...EXAMPLES.map((example) => normalizeForMatching(example)),
  ];
  const matchesOf = (pattern: RegExp) =>
    corpus.flatMap((text) => {
      const found = pattern.exec(text);
      return found === null ? [] : [found[0]];
    });

  const cases = __testables.CONTENT_PATTERNS.flatMap((theme) => [
    ...theme.patterns.map((pattern, index) => ({ name: `${theme.id}[${String(index)}]`, pattern })),
    ...(theme.unlessDelivered?.patterns ?? []).map((pattern, index) => ({
      name: `${theme.id}.unlessDelivered[${String(index)}]`,
      pattern,
    })),
  ]);

  it.each(cases)('$name matches natural text', ({ pattern }) => {
    expect(matchesOf(pattern).length).toBeGreaterThan(0);
  });

  it.each(cases)('$name has no alternative that natural text cannot reach', ({ pattern }) => {
    const matched = matchesOf(pattern);
    const unreachable = boundedAlternations(pattern.source)
      .flat()
      .filter((alternative) => !matched.some((text) => containsWord(text, alternative)));
    expect(unreachable).toEqual([]);
  });

  it('keeps every example earning its place', () => {
    const idle = EXAMPLES.filter((example) => {
      const text = normalizeForMatching(example);
      return !__testables.CONTENT_PATTERNS.some((theme) =>
        [...theme.patterns, ...(theme.unlessDelivered?.patterns ?? [])].some((pattern) => pattern.test(text)),
      );
    });
    expect(idle).toEqual([]);
  });
});
