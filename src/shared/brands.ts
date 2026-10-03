/**
 * Brand identity table.
 *
 * Two jobs:
 *  1. Recognise a *claimed* identity from a display name, subject, or body ("Microsoft Account
 *     Team", "your PayPal account").
 *  2. Know which registrable domains legitimately belong to that brand, so a claim can be checked
 *     against the actual sender domain.
 *
 * `keywords` are matched against confusable-folded text, so `paypa1` and `pаypal` both hit `paypal`.
 * `lookalikeTargets` are the strings that typosquatting is measured against.
 */
export interface Brand {
  id: string;
  /** Display label used in explanations. */
  label: string;
  /** Folded tokens that indicate the message claims to be this brand. */
  keywords: readonly string[];
  /**
   * Names that claim the brand only when they are the whole display name, optionally followed by a
   * generic word such as "Team" or "Support".
   *
   * For a brand whose name is an ordinary word. As a keyword, `ledger` would make every accounting
   * subject a claim to be a hardware-wallet maker, which is why such brands carry only qualified
   * keywords (`ledger live`), and those miss the commonest phishing form of all, a sender called just
   * "Ledger". Nobody's display name is the bare word by accident, so the name alone is the claim there.
   */
  standaloneNames?: readonly string[];
  /** Registrable domains this brand legitimately sends from or links to. */
  domains: readonly string[];
  /**
   * Top-level domains the brand itself operates, under which *every* name is its own.
   *
   * ICANN's Specification 13 is what makes this a rule rather than a list of guesses: a brand TLD's string
   * must match the operator's registered trademark, and registrations are restricted to the operator, its
   * affiliates, and its trademark licensees. So any name under `.apple` is Apple's without an entry in
   * `domains`: nobody else can hold one at all. Without this, genuine mail sent from the brand's own TLD and
   * authenticated would be reported as brand impersonation whenever the domain was not one of the
   * handful this file happens to list.
   *
   * Only strings whose Specification 13 request ICANN records as granted belong here. `.office` is the
   * instructive omission: Microsoft's request for it was withdrawn, so it carries no such guarantee even
   * though Microsoft operates it. A TLD that is open to third parties must never appear: `.live` and
   * `.me` are Microsoft's and Apple's in `domains` only as `live.com` and `me.com`, and treating either as
   * a brand TLD would hand every registrant of a cheap name the brand's identity.
   */
  tlds?: readonly string[];
  /** Strings that a lookalike domain would be imitating (registrable-domain form). */
  lookalikeTargets: readonly string[];
}

export const BRANDS: readonly Brand[] = [
  {
    id: 'microsoft',
    label: 'Microsoft',
    keywords: ['microsoft', 'office365', 'office 365', 'onedrive', 'sharepoint', 'outlook', 'msteams', 'microsoftteams', 'windowsdefender', 'azuread', 'entraid'],
    domains: [
      'microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'live.com',
      'outlook.com', 'sharepoint.com', 'onedrive.com', 'azure.com', 'windows.com',
      'msn.com', 'microsoft365.com', 'skype.com', 'xbox.com', 'msftauth.net',
      'microsoftstream.com', 'office.net', 'msidentity.com', 'linkedin.com', 'github.com',
    ],
    tlds: ['microsoft', 'azure', 'bing', 'hotmail', 'skype', 'windows', 'xbox'],
    lookalikeTargets: ['microsoft.com', 'microsoftonline.com', 'office365.com', 'sharepoint.com', 'onedrive.com'],
  },
  {
    id: 'google',
    label: 'Google',
    keywords: ['google', 'gmail', 'googledrive', 'googleworkspace', 'gsuite', 'youtube', 'googlepay'],
    domains: [
      'google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googleapis.com',
      'withgoogle.com', 'google.co.uk', 'googleusercontent.com', 'goo.gl', 'gstatic.com',
      'chromium.org', 'android.com',
    ],
    tlds: ['google', 'gmail', 'youtube'],
    lookalikeTargets: ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
  },
  {
    id: 'paypal',
    label: 'PayPal',
    keywords: ['paypal', 'paypalcredit', 'venmo'],
    domains: ['paypal.com', 'paypal.co.uk', 'paypal.me', 'paypalobjects.com', 'venmo.com', 'paypal-communication.com', 'paypal.de', 'paypal.fr'],
    lookalikeTargets: ['paypal.com', 'paypal.co.uk', 'venmo.com'],
  },
  {
    id: 'apple',
    label: 'Apple',
    keywords: ['apple', 'appleid', 'icloud', 'itunes', 'appstore', 'applepay'],
    domains: ['apple.com', 'icloud.com', 'itunes.com', 'me.com', 'mac.com', 'apple.co', 'apple.news'],
    tlds: ['apple'],
    lookalikeTargets: ['apple.com', 'icloud.com', 'appleid.apple.com'],
  },
  {
    id: 'amazon',
    label: 'Amazon',
    keywords: ['amazon', 'amazonprime', 'aws', 'amazonwebservices', 'kindle', 'audible'],
    domains: [
      'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.in',
      'amazon.co.jp', 'amazon.com.au', 'amazonaws.com', 'audible.com',
      'primevideo.com', 'amazonses.com', 'kindle.com', 'amazon.jobs',
    ],
    tlds: ['amazon', 'aws', 'audible', 'kindle', 'prime'],
    lookalikeTargets: ['amazon.com', 'amazon.co.uk', 'amazonaws.com'],
  },
  {
    id: 'netflix',
    label: 'Netflix',
    keywords: ['netflix'],
    domains: ['netflix.com', 'nflxext.com', 'netflix.net'],
    tlds: ['netflix'],
    lookalikeTargets: ['netflix.com'],
  },
  {
    id: 'docusign',
    label: 'DocuSign',
    keywords: ['docusign', 'docu sign', 'adobesign', 'echosign', 'hellosign', 'dropboxsign'],
    domains: ['docusign.com', 'docusign.net', 'adobesign.com', 'echosign.com', 'hellosign.com', 'dropboxsign.com'],
    lookalikeTargets: ['docusign.com', 'docusign.net'],
  },
  {
    id: 'dropbox',
    label: 'Dropbox',
    keywords: ['dropbox'],
    domains: ['dropbox.com', 'dropboxusercontent.com', 'dropboxstatic.com'],
    lookalikeTargets: ['dropbox.com'],
  },
  {
    id: 'adobe',
    label: 'Adobe',
    keywords: ['adobe', 'acrobat', 'creativecloud'],
    domains: ['adobe.com', 'adobe.io', 'adobelogin.com', 'acrobat.com'],
    lookalikeTargets: ['adobe.com', 'acrobat.com'],
  },
  {
    id: 'linkedin',
    label: 'LinkedIn',
    keywords: ['linkedin'],
    domains: ['linkedin.com', 'licdn.com', 'lnkd.in'],
    lookalikeTargets: ['linkedin.com'],
  },
  {
    id: 'meta',
    label: 'Meta / Facebook',
    keywords: ['facebook', 'instagram', 'whatsapp', 'metabusiness', 'meta platforms'],
    domains: ['facebook.com', 'facebookmail.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fb.com', 'fb.me'],
    lookalikeTargets: ['facebook.com', 'instagram.com', 'whatsapp.com'],
  },
  {
    id: 'dhl',
    label: 'DHL',
    keywords: ['dhl'],
    domains: ['dhl.com', 'dhl.de', 'dhlparcel.com', 'dhlexpress.com', 'dhl.co.uk'],
    tlds: ['dhl'],
    lookalikeTargets: ['dhl.com'],
  },
  {
    id: 'fedex',
    label: 'FedEx',
    keywords: ['fedex'],
    domains: ['fedex.com', 'fedex.co.uk', 'fedexoffice.com'],
    tlds: ['fedex'],
    lookalikeTargets: ['fedex.com'],
  },
  {
    id: 'ups',
    label: 'UPS',
    keywords: ['ups package', 'united parcel'],
    domains: ['ups.com', 'ups.co.uk'],
    tlds: ['ups'],
    lookalikeTargets: ['ups.com'],
  },
  {
    id: 'usps',
    label: 'USPS',
    keywords: ['usps', 'united states postal'],
    domains: ['usps.com', 'usps.gov', 'uspis.gov'],
    lookalikeTargets: ['usps.com'],
  },
  {
    id: 'chase',
    label: 'Chase',
    keywords: ['chase bank', 'jpmorgan', 'chase online'],
    domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com', 'chasepaymentech.com'],
    tlds: ['chase', 'jpmorgan'],
    lookalikeTargets: ['chase.com'],
  },
  {
    id: 'bankofamerica',
    label: 'Bank of America',
    keywords: ['bank of america', 'bankofamerica', 'bofa'],
    domains: ['bankofamerica.com', 'bofa.com', 'merrilledge.com', 'ml.com'],
    tlds: ['bofa'],
    lookalikeTargets: ['bankofamerica.com'],
  },
  {
    id: 'wellsfargo',
    label: 'Wells Fargo',
    keywords: ['wells fargo', 'wellsfargo'],
    domains: ['wellsfargo.com', 'wf.com', 'wellsfargoadvisors.com'],
    lookalikeTargets: ['wellsfargo.com'],
  },
  {
    id: 'hsbc',
    label: 'HSBC',
    keywords: ['hsbc'],
    domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.ca', 'hsbcnet.com'],
    tlds: ['hsbc'],
    lookalikeTargets: ['hsbc.com', 'hsbc.co.uk'],
  },
  {
    id: 'amex',
    label: 'American Express',
    keywords: ['american express', 'americanexpress', 'amex'],
    domains: ['americanexpress.com', 'aexp.com', 'amex.com', 'americanexpress.co.uk'],
    tlds: ['amex', 'americanexpress'],
    lookalikeTargets: ['americanexpress.com'],
  },
  {
    id: 'intuit',
    label: 'Intuit / QuickBooks',
    keywords: ['intuit', 'quickbooks', 'turbotax'],
    domains: ['intuit.com', 'quickbooks.com', 'turbotax.com', 'intuit.ca', 'mint.com'],
    tlds: ['intuit'],
    lookalikeTargets: ['intuit.com', 'quickbooks.com'],
  },
  {
    id: 'irs',
    label: 'IRS',
    keywords: ['irs', 'internal revenue'],
    // `govdelivery.com` is the platform the IRS sends its public newsletters through. It is shared, but
    // only with government bodies, which is the one reason a shared sending platform may stand for a
    // brand here; a general-purpose mailer (anyone can open an account) must never be listed.
    domains: ['irs.gov', 'treasury.gov', 'eftps.gov', 'govdelivery.com'],
    lookalikeTargets: ['irs.gov'],
  },
  {
    id: 'hmrc',
    label: 'HMRC',
    keywords: ['hmrc', 'hm revenue'],
    domains: ['hmrc.gov.uk', 'gov.uk'],
    lookalikeTargets: ['hmrc.gov.uk'],
  },
  {
    id: 'coinbase',
    label: 'Coinbase',
    keywords: ['coinbase'],
    domains: ['coinbase.com', 'coinbase.email'],
    lookalikeTargets: ['coinbase.com'],
  },
  {
    id: 'binance',
    label: 'Binance',
    keywords: ['binance'],
    domains: ['binance.com', 'binance.us'],
    lookalikeTargets: ['binance.com'],
  },
  // Self-custody wallets are phished for the recovery phrase, which moves the funds for good. Ledger and
  // Exodus have no lookalike targets: both cores are ordinary six-letter words, and a word that long is
  // matched anywhere in a link's subdomain, so an accounting vendor's `general-ledger.` host would read
  // as a disguised brand at `critical`.
  {
    id: 'ledger',
    label: 'Ledger',
    keywords: ['ledger live', 'ledger nano', 'ledger wallet', 'ledger stax', 'ledger flex', 'ledger recover', 'ledger device'],
    standaloneNames: ['ledger'],
    domains: ['ledger.com', 'ledgerwallet.com'],
    lookalikeTargets: [],
  },
  {
    id: 'trezor',
    label: 'Trezor',
    keywords: ['trezor'],
    domains: ['trezor.io'],
    lookalikeTargets: ['trezor.io'],
  },
  {
    id: 'exodus',
    label: 'Exodus',
    keywords: ['exodus wallet', 'exodus app'],
    standaloneNames: ['exodus'],
    domains: ['exodus.com', 'exodus.io'],
    lookalikeTargets: [],
  },
  {
    id: 'metamask',
    label: 'MetaMask',
    keywords: ['metamask'],
    domains: ['metamask.io', 'consensys.io', 'consensys.net'],
    lookalikeTargets: ['metamask.io'],
  },
  {
    id: 'trustwallet',
    label: 'Trust Wallet',
    keywords: ['trust wallet', 'trustwallet'],
    domains: ['trustwallet.com'],
    lookalikeTargets: ['trustwallet.com'],
  },
  // Security-software renewals are the most common English lure in public phishing corpora: a lapsed
  // subscription, a failed payment, a link to "update billing". Norton is also a surname and a law firm's
  // name, so it claims the brand only in a product name or as the whole display name, and has no lookalike
  // target for the reason given for Ledger above.
  {
    id: 'mcafee',
    label: 'McAfee',
    keywords: ['mcafee'],
    domains: ['mcafee.com'],
    lookalikeTargets: ['mcafee.com'],
  },
  {
    id: 'norton',
    label: 'Norton',
    keywords: ['norton 360', 'norton antivirus', 'norton security', 'norton lifelock', 'nortonlifelock', 'norton internet security'],
    standaloneNames: ['norton'],
    domains: ['norton.com', 'nortonlifelock.com', 'lifelock.com', 'gendigital.com'],
    lookalikeTargets: [],
  },
  {
    id: 'avast',
    label: 'Avast',
    keywords: ['avast'],
    domains: ['avast.com', 'avg.com', 'gendigital.com'],
    lookalikeTargets: ['avast.com'],
  },
  {
    id: 'kaspersky',
    label: 'Kaspersky',
    keywords: ['kaspersky'],
    domains: ['kaspersky.com'],
    lookalikeTargets: ['kaspersky.com'],
  },
  {
    id: 'okta',
    label: 'Okta',
    keywords: ['okta'],
    domains: ['okta.com', 'oktapreview.com', 'okta-emea.com'],
    lookalikeTargets: ['okta.com'],
  },
  {
    id: 'zoom',
    label: 'Zoom',
    keywords: ['zoom meeting', 'zoom video', 'zoom.us'],
    domains: ['zoom.us', 'zoom.com', 'zoomgov.com'],
    lookalikeTargets: ['zoom.us', 'zoom.com'],
  },
  {
    id: 'slack',
    label: 'Slack',
    keywords: ['slack'],
    domains: ['slack.com', 'slack-edge.com', 'slackhq.com'],
    lookalikeTargets: ['slack.com'],
  },
  {
    id: 'salesforce',
    label: 'Salesforce',
    keywords: ['salesforce'],
    domains: ['salesforce.com', 'force.com', 'salesforce-communications.com', 'pardot.com'],
    lookalikeTargets: ['salesforce.com'],
  },
  {
    id: 'wetransfer',
    label: 'WeTransfer',
    keywords: ['wetransfer'],
    domains: ['wetransfer.com', 'wetransfer.net'],
    lookalikeTargets: ['wetransfer.com'],
  },
  {
    id: 'stripe',
    label: 'Stripe',
    keywords: ['stripe payments', 'stripe dashboard'],
    domains: ['stripe.com', 'stripe.dev'],
    lookalikeTargets: ['stripe.com'],
  },
  {
    id: 'shopify',
    label: 'Shopify',
    keywords: ['shopify'],
    domains: ['shopify.com', 'myshopify.com', 'shopifyemail.com'],
    lookalikeTargets: ['shopify.com'],
  },
  {
    id: 'steam',
    label: 'Steam',
    keywords: ['steam community', 'steampowered', 'valve corporation'],
    domains: ['steampowered.com', 'steamcommunity.com', 'valvesoftware.com'],
    lookalikeTargets: ['steampowered.com', 'steamcommunity.com'],
  },
  {
    id: 'spotify',
    label: 'Spotify',
    keywords: ['spotify'],
    domains: ['spotify.com', 'spotifymail.com'],
    lookalikeTargets: ['spotify.com'],
  },
];

const BRAND_BY_DOMAIN = new Map<string, Brand>();
for (const brand of BRANDS) {
  for (const domain of brand.domains) {
    if (!BRAND_BY_DOMAIN.has(domain)) BRAND_BY_DOMAIN.set(domain, brand);
  }
}

const BRAND_BY_TLD = new Map<string, Brand>();
for (const brand of BRANDS) {
  for (const tld of brand.tlds ?? []) {
    if (!BRAND_BY_TLD.has(tld)) BRAND_BY_TLD.set(tld, brand);
  }
}

export function brandOwningDomain(registrable: string): Brand | undefined {
  const named = BRAND_BY_DOMAIN.get(registrable);
  if (named !== undefined) return named;
  return BRAND_BY_TLD.get(lastLabel(registrable));
}

/**
 * Whether this particular brand owns the domain.
 *
 * The brand-scoped half of the same question, and the only form callers should use. Asking
 * `brand.domains.includes(registrable)` instead looks equivalent and is not: it cannot see a brand's own
 * top-level domain, so a rule asking it that way disagrees with `brandOwningDomain` about who owns a name
 * under `.apple`. The brand's genuine mail is then excluded from the alignment that dampens content
 * heuristics, and its own links read as pointing somewhere else, a disagreement that shows up as
 * unrelated symptoms in unrelated files, which is what having one question answered in several places buys.
 */
export function brandOwns(brand: Brand, registrable: string): boolean {
  if (registrable === '') return false;
  if (brand.domains.includes(registrable)) return true;
  return (brand.tlds ?? []).includes(lastLabel(registrable));
}

/**
 * The TLD of a registrable domain, computed here rather than imported.
 *
 * This file is data and has no imports, which is what lets the brand table be read by anything without
 * dragging the URL helpers behind it. The input is already a registrable domain, so its last label is its
 * TLD whether or not the suffix has several labels: `hsbc.co.uk` gives `uk`, which no brand claims.
 */
function lastLabel(registrable: string): string {
  const trimmed = registrable.toLowerCase().replace(/\.+$/u, '');
  return trimmed.slice(trimmed.lastIndexOf('.') + 1);
}
