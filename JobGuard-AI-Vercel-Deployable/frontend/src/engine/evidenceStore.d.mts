export interface EvidenceItem {
  saved_at?: string;
  result: {
    risk_category?: string;
    risk_percentage?: number;
    fraud_category?: string;
    evidence?: Array<{ category?: string; matched_text?: string; explanation?: string }>;
    recommended_next_steps?: string[];
    [key: string]: unknown;
  };
}

export interface EvidenceReadResult {
  items: EvidenceItem[];
  error: string | null;
}

export function readEvidence(storage?: Storage): EvidenceReadResult;
export function saveEvidence(item: EvidenceItem, storage?: Storage): EvidenceItem[];
export function removeEvidence(index: number, storage?: Storage): EvidenceItem[];
export function clearEvidence(storage?: Storage): void;
export function exportEvidenceAsJson(storage?: Storage): string;
export function importEvidenceFromJson(jsonString: string, storage?: Storage): EvidenceItem[];
