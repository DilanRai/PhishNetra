// FILE: src/types.ts

export type ScanStatus = "safe" | "suspicious" | "phishing";

export type ScanResult = {
  status:           ScanStatus;
  riskScore:        number;
  issues:           string[];
  inputType:        "url" | "email" | "text";
  confidence:       "low" | "medium" | "high";
  detectionVersion: string;
  mlEnabled:        boolean;
  mlScore:          number | null;
  ruleScore:        number;
  features?:        Record<string, number>;
};

export interface HistoryItem {
  _id:         string;
  input:       string;
  status:      "safe" | "suspicious" | "phishing";
  riskScore:   number;
  issues:      string[];
  createdAt:   string;
  inputType?:  "url" | "email" | "text";
  mlEnabled?:  boolean;
  mlScore?:    number | null;
  ruleScore?:  number;
  confidence?: "low" | "medium" | "high";
}