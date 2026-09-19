// FILE: src/types.ts  (FULL REPLACEMENT)

export type ScanStatus = "safe" | "suspicious" | "phishing";

export type PhishDNA = {
  fingerprint: string;
  brand: string;
  technique: string;
  tld: string;
  severity: string;
  canonical: string;
} | null;

export interface MitreMapping {
  tactic: string;
  technique: string;
}

export interface RemediationStep {
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  action: string;
}

export interface Remediation {
  severity: string;
  steps: RemediationStep[];
  compliance: string | null;
  reportLinks: { label: string; url: string }[];
  summary: string;
  priorityConfig: Record<string, { color: string; bg: string; border: string }>;
}

export type ScanResult = {
  status: ScanStatus;
  riskScore: number;
  issues: string[];
  inputType: "url" | "email" | "text";
  confidence: "low" | "medium" | "high";
  detectionVersion: string;
  // ML hybrid
  mlEnabled: boolean;
  mlScore: number | null;
  ruleScore: number;
  features?: Record<string, number>;
  // Attack classification
  attackTypes?: string[];
  mitre?: MitreMapping | null;
  mitreAttack?: MitreMapping[];
  cve?: string | null;
  // PhishDNA
  dna?: PhishDNA;
  // Remediation
  remediation?: Remediation;
  // Threat Intel
  threatIntel?: {
    found: boolean;
    sources: string[];
    domain: string;
    label: string | null;
  } | null;

  kitMatch?: {
    kitId: string;
    kitName: string;
    confidence: number;
    sophistication: "low" | "medium" | "high" | "expert";
    version?: string;
    targetBrands?: string[];
    description?: string;
  } | null;

  csvMatch?: {
    matched: boolean;
    matchLevel: "exact" | "domain+path" | "domain";
    label: "phishing" | "safe" | "suspicious";
    source: string;
    count: number;
  } | null;

  communityMatch?: {
    found: boolean;
    confidence: number;
    severity: number;
    technique: string | null;
    brand: string | null;
    reportCount: number;
    firstSeen: string;
    label: string;
    stixId: string;
  } | null;

  evasion?: {
    detected: boolean;
    level: "BASIC" | "MODERATE" | "SOPHISTICATED" | null;
    signals: number;
    techniques: string[];
  } | null;

  sourceGeo?: SourceGeo;
  sourceIP?: string | null;
  attributionConfidence?: number;
  hops?: number;
  relayChain?: RelayHop[];
  relayAnomalies?: RelayAnomaly[];
  relayRiskBoost?: number;
  domainIntel?: any;
  mxValidation?: {
    domain: string;
    hasMX: boolean;
    mxRecords: string[];
    mxProvider: string;
    mxProviderTier: "enterprise" | "consumer" | "unknown";
    spfRecord: string | null;
    spfLiveResult: "pass" | "fail" | "softfail" | "neutral" | "none" | null;
    mxMismatch: boolean;
    infrastructureAnomaly: boolean;
    anomalies: RelayAnomaly[];
  } | null;
};

export type RelayAnomaly = {
  type: string;
  label: string;
  detail: string;
  risk: number;
};

export type RelayHop = {
  hopNumber: number;
  raw: string;
  fromHost: string | null;
  fromIP: string | null;
  byHost: string | null;
  byIP: string | null;
  protocol: string | null;
  timestamp: string | null;
  timestampMs: number | null;
  delayMs: number | null;
  delayFormatted: string | null;
  isLocalhost: boolean;
  isPrivateIP: boolean;
  anomalies: RelayAnomaly[];
};

export interface HistoryItem {
  _id: string;
  input: string;
  status: "safe" | "suspicious" | "phishing";
  riskScore: number;
  issues: string[];
  createdAt: string;
  inputType?: "url" | "email" | "text";
  mlEnabled?: boolean;
  mlScore?: number | null;
  ruleScore?: number;
  confidence?: "low" | "medium" | "high";
  attackTypes?: string[];
  dna?: PhishDNA;
  tags?: string[];
  notes?: string;
  shareId?: string | null;
  sharedAt?: string | null;
}

export interface ThreatFeedItem {
  id: string;
  input: string;
  status: "phishing" | "suspicious";
  riskScore: number;
  inputType: string;
  createdAt: string;
  fingerprint: string | null;
  brand: string | null;
  technique: string | null;
  issue: string | null;
}

export interface ThreatFeedData {
  updatedAt: string;
  recentThreats: ThreatFeedItem[];
  trendingBrands: { brand: string; count: number; lastSeen: string }[];
  trendingTechniques: { technique: string; count: number }[];
  trendingTLDs: { tld: string; count: number }[];
  hourlySpike: { _id: string; total: number; phishing: number }[];
  summary: {
    totalToday: number;
    phishingToday: number;
    threatRate: number;
    activeCampaigns: number;
  };
}
export interface SourceGeo {
  ip: string | null;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  asnCode: string | null;
  isVPN: boolean;
  isTor: boolean;
  isDatacenter: boolean;
  isMobile: boolean;
  isProxy: boolean;
  isPrivate: boolean;
  abuseRisk: "none" | "low" | "medium" | "high" | "critical" | "unknown";
  geoSource: string;
  cachedAt?: string;
}

export interface EmailHeaderResult {
  status: ScanStatus;
  riskScore: number;
  issues: string[];
  signals: { label: string; value: string; color: string }[];
  sourceIP: string | null;
  sourceGeo: SourceGeo;
  originType:
    | "tor"
    | "vpn"
    | "datacenter"
    | "mobile"
    | "private_network"
    | "residential";
  attributionConfidence: number;
  fromDomain: string | null;
  replyToDomain: string | null;
  hops: number;
  relayChain?: RelayHop[];
  relayAnomalies?: RelayAnomaly[];
  relayRiskBoost?: number;
  headers: number;
  inputType: "email_header";
  confidence: "low" | "medium" | "high";
  detectionVersion: string;
  mlEnabled: boolean;
  mlScore: null;
  ruleScore: number;
}
export interface DomainIntel {
  domain: string;
  fetchedAt: string;
  age: {
    registeredAt: string | null;
    updatedAt: string | null;
    expiresAt: string | null;
    ageDays: number | null;
    ageLabel: string | null;
    isNew: boolean;
    isSuspicious: boolean;
    registrar: string | null;
  };
  ssl: {
    valid: boolean;
    daysLeft: number | null;
    expiresAt: string | null;
    issuer: string | null;
    selfSigned: boolean;
    error?: string;
  };
  dns: {
    ip: string | null;
    country: string | null;
    city: string | null;
    flag: string;
    hasMX: boolean;
  };
  blacklist: {
    results: Record<string, boolean>;
    found: boolean;
    count: number;
  };
  risk: {
    riskLevel: "low" | "medium" | "high" | "critical";
    riskSignals: string[];
    addScore: number;
  };
  geopoliticalContext?: {
    risk: "low" | "medium" | "high";
    label: string;
    source: string;
    note: string;
  } | null;
}
export interface URLPreview {
  url: string;
  domain: string;
  title: string | null;
  description: string | null;
  ogImage: string | null;
  favicon: string | null;
  generator: string | null;

  // Status
  statusCode: number | null;
  liveStatus: "LIVE" | "TAKEN_DOWN" | "ERROR" | "UNREACHABLE";
  isLive: boolean;
  isTakenDown: boolean;

  // Redirect chain
  redirectChain: {
    finalUrl: string;
    hops: number;
    hasRedirects: boolean;
    crossDomain: boolean;
    hasShortener: boolean;
    chain: {
      url: string;
      statusCode: number | null;
      hop: number;
      isShortener: boolean;
    }[];
  };

  // Form analysis
  forms: {
    count: number;
    hasCredentialForm: boolean;
    hasPasswordField: boolean;
    hasExternalAction: boolean;
    details: {
      hasPasswordField: boolean;
      hasEmailField: boolean;
      passwordFieldCount: number;
      inputFieldCount: number;
      formAction: string | null;
      formMethod: string;
      externalAction: string | null;
      isCredentialHarvester: boolean;
      suspicionScore: number;
    }[];
  };

  // Technology fingerprint
  technologies: {
    detected: {
      name: string;
      category: string;
      risk: string;
      kitId?: string;
    }[];
    hasPhishingKit: boolean;
    hasObfuscation: boolean;
    hasRedirectScript: boolean;
    hasEvasion: boolean;
    hasAiTMSignal: boolean;
  };

  // NEW — JS Entropy analysis
  jsEntropy: {
    maxEntropy: number;
    avgEntropy: number;
    highEntropyBlocks: number;
    totalScriptBlocks: number;
  } | null;

  // NEW — Link extraction
  linkAnalysis: {
    totalLinks: number;
    externalLinks: number;
    externalDomains: string[];
    suspiciousDomains: string[];
    hasShortenerLink: boolean;
  } | null;

  // NEW — TLS certificate
  tlsCertificate: {
    issuer: string;
    subject: string;
    daysOld: number;
    daysLeft: number;
    isLetEncrypt: boolean;
    isSelfSigned: boolean;
    isVeryNew: boolean;
    certMismatch: boolean;
    signals: string[];
  } | null;

  // NEW — IP geolocation
  ipGeolocation: {
    ip: string;
    country: string;
    city: string;
    isHighAbuseRegion: boolean;
    signal: string | null;
  } | null;

  // NEW — Domain analysis
  domainAnalysis: {
    score: number;
    signals: string[];
  } | null;

  // Risk
  brandMismatch: {
    found: boolean;
    urlBrand: string;
    claimedBrand: string;
    message: string;
    severity: "critical" | "high";
  } | null;

  sandboxRisk: {
    riskScore: number;
    riskLevel: "low" | "medium" | "high" | "critical";
    signals: string[];
  };

  fetchedAt: string;
  error?: string;
}

export interface AttachmentFinding {
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  detail: string;
  extractedUrls?: string[];
}

export interface VTResult {
  available?: boolean;
  reason?: string;
  found?: boolean;
  sha256?: string;
  detectionCount?: number;
  totalEngines?: number;
  cleanCount?: number;
  malwareFamily?: string | null;
  threatNames?: string[];
  verdict?: "malicious" | "suspicious" | "clean" | "unknown";
  vtLink?: string;
  lastAnalysisDate?: string | null;
  note?: string;
}

export interface OfficeIntel {
  hyperlinks: string[];
  templateUrl: string | null;
  macroEnabled: boolean;
  vbaDetected: boolean;
  metadata: {
    creator?: string;
    lastModifiedBy?: string;
    created?: string;
  };
  externalQueries: string[];
}

export interface PdfIntel {
  hasEmbeddedJS: boolean;
  hasLaunchAction: boolean;
  hasOpenAction: boolean;
  hasEmbeddedFiles: boolean;
  hasCredentialForm: boolean;
  embeddedUrls: string[];
}

export interface AttachmentResult {
  verdict: "malicious" | "suspicious" | "clean";
  score: number;
  filename: string;
  sizeKB: number;
  extension: string;
  mimetype?: string;
  actualType?: string;
  magicByte?: string;
  sha256?: string;
  categories?: string[];
  findings?: AttachmentFinding[];
  /** Legacy flat-string signals — present when backend returns old format */
  signals?: { severity: string; type: string; detail: string }[];
  /** Deep analysis results (static_v3_deep) */
  virustotal?: VTResult | null;
  officeIntel?: OfficeIntel | null;
  pdfIntel?: PdfIntel | null;
  analysisType?: string;
}
