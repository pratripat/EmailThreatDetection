import { InvestigationData, EmailAnalysisRequest } from '../types/threat';

// Default Investigation based on the judge-ready scenario
export const DEFAULT_INVESTIGATION: InvestigationData = {
  id: 'EML-2026-00421',
  subject: 'URGENT: Your account requires verification',
  from: 'security@paypa1-support.com',
  to: 'victim-analyst@enterprise-corp.in',
  receivedDate: '05 Sep 2026, 01:42 IST',
  threatScore: 94,
  threatLevel: 'HIGH',
  threatType: 'PHISHING',
  confidence: 94.7,
  authStatus: 'FAILED',

  breakdown: {
    headerAnomalies: 91,
    authentication: 98,
    urlRisk: 97,
    contentNlp: 84,
    senderReputation: 72,
  },

  suspiciousReasons: [
    'DKIM verification failed (signature absent / invalid hash)',
    'SPF alignment mismatch (header From: paypa1-support.com != envelope Return-Path)',
    'Sender domain resembles a trusted brand domain (Typosquatting: "paypa1")',
    'URL redirects to suspicious external domain (paypal-secure-login.xyz)',
    'Urgency & credential-harvesting language detected by ML NLP model',
    'Originating IP (185.220.101.5) has negative reputation on AbuseIPDB & VirusTotal',
  ],

  headerHops: [
    {
      hopNumber: 1,
      ip: 'Client Direct',
      hostname: 'user-origin.desktop.node',
      country: 'Attacker Machine',
      city: 'Unknown Tor Client',
      asn: 'AS-TOR-EXIT',
      isp: 'Privacy Relay',
      reputation: 'MALICIOUS',
      firstSeen: '2026-08-14',
      threatFeeds: {
        abuseIpDb: 'HIGH RISK',
        virusTotal: '14 / 92 engines',
        spamhausListed: true,
      },
    },
    {
      hopNumber: 2,
      ip: '185.220.101.5',
      hostname: 'mail-relay-sg01.hosting-cloud.net',
      country: 'Singapore (SG)',
      city: 'Singapore Central',
      asn: 'AS49505',
      isp: 'Severel LLC Hosting',
      reputation: 'MALICIOUS',
      firstSeen: '2026-07-12',
      threatFeeds: {
        abuseIpDb: 'HIGH RISK',
        virusTotal: '8 / 92 engines',
        spamhausListed: true,
      },
    },
    {
      hopNumber: 3,
      ip: '194.38.20.12',
      hostname: 'mail.smtp-inbound-relay.nl',
      country: 'Netherlands (NL)',
      city: 'Amsterdam',
      asn: 'AS202425',
      isp: 'Cloud Transit Backbone',
      reputation: 'SUSPICIOUS',
      firstSeen: '2026-08-01',
      threatFeeds: {
        abuseIpDb: 'MEDIUM RISK',
        virusTotal: '2 / 92 engines',
        spamhausListed: false,
      },
    },
    {
      hopNumber: 4,
      ip: '10.24.8.100',
      hostname: 'mx-gateway.enterprise-corp.in',
      country: 'India (IN)',
      city: 'Bengaluru Gateway',
      asn: 'AS-CORP-INT',
      isp: 'Corporate Perimeter MX',
      reputation: 'CLEAN',
      firstSeen: 'Internal Ingress',
      threatFeeds: {
        abuseIpDb: 'CLEAN',
        virusTotal: '0 / 92 engines',
        spamhausListed: false,
      },
    },
  ],

  authentication: {
    spf: 'FAILED',
    dkim: 'FAILED',
    dmarc: 'FAILED',
    fromDomain: 'paypa1-support.com',
    returnPathDomain: 'bounce-collector.suspicious-relay.net',
    alignmentMatched: false,
    notes: [
      'SPF Check: IP 185.220.101.5 is not in SPF record for paypa1-support.com',
      'DKIM Check: Invalid cryptographic signature block or missing public key in DNS TXT',
      'DMARC Check: Action policy rejected due to SPF and DKIM alignment failure',
      'Domain Mismatch: Header From domain does not match envelope return-path domain',
    ],
  },

  urls: [
    {
      url: 'https://paypal-secure-login.xyz/auth/verify?session=9942a',
      domain: 'paypal-secure-login.xyz',
      registeredAgeDays: 4,
      reputation: 'MALICIOUS',
      threatScore: 97,
      flags: ['Typosquatting', 'Newly registered domain (4 days)', 'Credential harvesting form'],
      redirectChain: [
        'https://bit.ly/3xSecLogin',
        'https://paypal-secure-login.xyz/auth/verify?session=9942a',
      ],
    },
    {
      url: 'https://paypa1-support.com/terms',
      domain: 'paypa1-support.com',
      registeredAgeDays: 6,
      reputation: 'SUSPICIOUS',
      threatScore: 82,
      flags: ['Lookalike character replacement (1 vs l)', 'Unverified SSL Issuer'],
    },
  ],

  contentAi: {
    classification: 'PHISHING',
    confidence: 96.2,
    intents: ['Credential harvesting', 'Account takeover', 'Urgency manipulation'],
    suspiciousPhrases: [
      {
        phrase: 'Your account will be suspended within 2 hours',
        signalType: 'Urgency signal',
      },
      {
        phrase: 'Verify your identity immediately to restore access',
        signalType: 'Credential request',
      },
      {
        phrase: 'Failure to comply will result in permanent termination of services',
        signalType: 'Security impersonation',
      },
    ],
    featureContributions: [
      { feature: 'Urgency / Time Coercion Tokens', weight: 88, impact: 'positive' },
      { feature: 'Credential Verification Verbs', weight: 94, impact: 'positive' },
      { feature: 'Financial Institution Brand Mentions', weight: 76, impact: 'positive' },
      { feature: 'Clean Grammatical Syntax', weight: 15, impact: 'negative' },
    ],
  },

  iocs: {
    ipAddresses: ['185.220.101.5', '194.38.20.12', '91.240.118.5'],
    domains: ['paypa1-support.com', 'paypal-secure-login.xyz', 'suspicious-relay.net', 'bit.ly'],
    urls: [
      'https://paypal-secure-login.xyz/auth/verify?session=9942a',
      'https://paypa1-support.com/terms',
      'https://bit.ly/3xSecLogin',
      'http://185.220.101.5/c2/gate.php',
      'https://paypal-secure-login.xyz/favicon.ico',
      'https://paypal-secure-login.xyz/assets/app.js',
    ],
    emailAddresses: ['security@paypa1-support.com', 'bounce-collector@suspicious-relay.net'],
    hashes: ['sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  },

  attackGraph: {
    nodes: [
      { id: 'n1', label: 'EMAIL INGRESS', sublabel: 'PHISHING ATTEMPT', type: 'email', status: 'critical' },
      { id: 'n2', label: 'paypa1-support.com', sublabel: 'Spoofed Domain', type: 'domain', status: 'critical' },
      { id: 'n3', label: '185.220.101.5', sublabel: 'Singapore (Tor Exit)', type: 'ip', status: 'critical' },
      { id: 'n4', label: 'paypal-secure-login.xyz', sublabel: 'Credential Harvester', type: 'page', status: 'critical' },
      { id: 'n5', label: 'Credential Theft C2', sublabel: 'Exfiltration Destination', type: 'action', status: 'critical' },
    ],
    edges: [
      { from: 'n1', to: 'n2', label: 'Sent From' },
      { from: 'n1', to: 'n3', label: 'Relayed Via' },
      { from: 'n2', to: 'n4', label: 'Embedded Link' },
      { from: 'n4', to: 'n5', label: 'Submits To' },
    ],
  },

  rawHeaders: `Received: from mail-relay-sg01.hosting-cloud.net (185.220.101.5)
 by mx-gateway.enterprise-corp.in (10.24.8.100) with ESMTP id m9921
 for <victim-analyst@enterprise-corp.in>; 05 Sep 2026 01:42:15 +0530
From: "Security Center" <security@paypa1-support.com>
To: <victim-analyst@enterprise-corp.in>
Subject: URGENT: Your account requires verification
Date: 05 Sep 2026 01:42:00 +0530
Authentication-Results: mx-gateway.enterprise-corp.in;
 dkim=fail (bad sig);
 spf=fail (185.220.101.5 is not permitted sender);
 dmarc=fail (p=reject sp=reject)
Return-Path: <bounce-collector@suspicious-relay.net>`,

  rawBody: `Dear Customer,

We detected unauthorized sign-in attempts on your PayPal corporate account from IP 185.220.101.5 (Singapore).

Your account will be suspended within 2 hours unless you confirm your identity.

Verify your identity immediately to restore access:
https://paypal-secure-login.xyz/auth/verify?session=9942a

Failure to comply will result in permanent termination of services.

Sincerely,
PayPal Security & Fraud Defense Team`,
};

// Function to generate investigation data from custom email inputs
export const createInvestigationFromInput = (req: EmailAnalysisRequest): InvestigationData => {
  const email = req.senderEmail.toLowerCase();
  const domain = email.split('@')[1] || 'domain.com';

  const isSafe = domain.endsWith('.org') || domain.endsWith('.edu') || domain === 'github.com' || domain === 'google.com';
  const isUrgent = req.subject?.toLowerCase().includes('urgent') || req.subject?.toLowerCase().includes('wire') || req.subject?.toLowerCase().includes('password');

  const threatScore = isSafe ? 6 : isUrgent || domain.includes('xyz') || domain.includes('top') ? 92 : 68;
  const threatLevel = threatScore > 85 ? 'HIGH' : threatScore > 40 ? 'SUSPICIOUS' : 'CLEAN';

  const caseId = `EML-2026-${Math.floor(10000 + Math.random() * 90000).toString().substring(1)}`;

  return {
    id: caseId,
    subject: req.subject || 'Email Security Assessment',
    from: req.senderEmail,
    to: 'target-analyst@organization.internal',
    receivedDate: new Date().toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }),
    threatScore,
    threatLevel,
    threatType: threatScore > 85 ? 'PHISHING / SPOOFING' : threatScore > 40 ? 'SUSPICIOUS DOMAIN' : 'BENIGN',
    confidence: threatScore > 85 ? 95.3 : 92.1,
    authStatus: isSafe ? 'PASSED' : 'FAILED',

    breakdown: {
      headerAnomalies: isSafe ? 4 : 89,
      authentication: isSafe ? 2 : 96,
      urlRisk: isSafe ? 5 : 94,
      contentNlp: isSafe ? 8 : 82,
      senderReputation: isSafe ? 10 : 78,
    },

    suspiciousReasons: isSafe
      ? ['All cryptographic DKIM & SPF records match legitimate mail servers.', 'Sender domain has positive reputation.']
      : [
          'DKIM verification failed on incoming mail exchange node.',
          `Envelope domain mismatch detected for '${domain}'.`,
          'Suspicious URL and redirect hops present in message headers.',
          'NLP heuristics detected high urgency manipulation patterns.',
        ],

    headerHops: [
      {
        hopNumber: 1,
        ip: isSafe ? '209.85.220.41' : '185.220.101.5',
        hostname: isSafe ? 'mail-sor-f41.google.com' : 'tor-exit-relay-04.net',
        country: isSafe ? 'United States (US)' : 'Singapore (SG)',
        city: isSafe ? 'Mountain View' : 'Singapore Central',
        asn: isSafe ? 'AS15169' : 'AS49505',
        isp: isSafe ? 'Google LLC' : 'HostRelay Inc',
        reputation: isSafe ? 'CLEAN' : 'MALICIOUS',
        firstSeen: '2026-07-12',
        threatFeeds: {
          abuseIpDb: isSafe ? 'CLEAN' : 'HIGH RISK',
          virusTotal: isSafe ? '0 / 92 engines' : '8 / 92 engines',
          spamhausListed: !isSafe,
        },
      },
      {
        hopNumber: 2,
        ip: '10.24.8.100',
        hostname: 'mx-gateway.corp.internal',
        country: 'India (IN)',
        city: 'Bengaluru',
        asn: 'AS-CORP',
        isp: 'Enterprise MX',
        reputation: 'CLEAN',
        firstSeen: 'Internal Ingress',
        threatFeeds: {
          abuseIpDb: 'CLEAN',
          virusTotal: '0 / 92 engines',
          spamhausListed: false,
        },
      },
    ],

    authentication: {
      spf: isSafe ? 'PASSED' : 'FAILED',
      dkim: isSafe ? 'PASSED' : 'FAILED',
      dmarc: isSafe ? 'PASSED' : 'FAILED',
      fromDomain: domain,
      returnPathDomain: isSafe ? domain : `relay-${domain}`,
      alignmentMatched: isSafe,
      notes: isSafe
        ? ['SPF and DKIM records successfully aligned with sender domain.']
        : ['SPF check failed: origin IP not authorized.', 'DKIM signature mismatch.'],
    },

    urls: isSafe
      ? []
      : [
          {
            url: `https://${domain}/secure/auth-session`,
            domain: domain,
            registeredAgeDays: 5,
            reputation: 'MALICIOUS',
            threatScore: 95,
            flags: ['Newly registered domain', 'Credential harvesting form'],
          },
        ],

    contentAi: {
      classification: isSafe ? 'BENIGN' : 'PHISHING',
      confidence: isSafe ? 98.1 : 94.4,
      intents: isSafe ? ['Standard Notification'] : ['Credential harvesting', 'Urgency manipulation'],
      suspiciousPhrases: isSafe
        ? []
        : [
            {
              phrase: req.subject || 'Action Required Immediately',
              signalType: 'Urgency signal',
            },
          ],
      featureContributions: [
        { feature: 'Domain Authenticity', weight: isSafe ? 90 : 20, impact: isSafe ? 'negative' : 'positive' },
        { feature: 'Urgency Tokens', weight: isSafe ? 5 : 85, impact: 'positive' },
      ],
    },

    iocs: {
      ipAddresses: isSafe ? ['209.85.220.41'] : ['185.220.101.5', '194.38.20.12'],
      domains: [domain],
      urls: isSafe ? [] : [`https://${domain}/secure/auth-session`],
      emailAddresses: [req.senderEmail],
      hashes: ['sha256: 8f4e24...'],
    },

    attackGraph: {
      nodes: [
        { id: 'n1', label: 'EMAIL INGRESS', sublabel: isSafe ? 'CLEAN MAIL' : 'PHISHING ATTEMPT', type: 'email', status: isSafe ? 'clean' : 'critical' },
        { id: 'n2', label: domain, sublabel: isSafe ? 'Verified Domain' : 'Suspicious Domain', type: 'domain', status: isSafe ? 'clean' : 'critical' },
        { id: 'n3', label: isSafe ? '209.85.220.41' : '185.220.101.5', sublabel: isSafe ? 'Google MTA' : 'Origin Tor Relay', type: 'ip', status: isSafe ? 'clean' : 'critical' },
      ],
      edges: [
        { from: 'n1', to: 'n2', label: 'Sent From' },
        { from: 'n1', to: 'n3', label: 'Relayed Via' },
      ],
    },

    rawHeaders: req.rawHeaders,
    rawBody: req.emailBody,
  };
};
