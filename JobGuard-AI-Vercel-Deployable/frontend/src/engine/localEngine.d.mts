export function redactSensitiveInfo(text: string): { redacted: string; counts: Record<string, number> };
export function detectLanguage(text: string, hint?: string): string;
export function extractUrlsFromText(text: string): string[];
export function extractRegistrableDomain(hostname: string): { regDomain: string; subdomains: string[] };
export function inspectUrlStructurally(rawUrl: string): any;
export function extractStructuredJobData(text: string, jobUrl?: string): any;
export function runLocalVerification(input: {
  text?: string;
  secondaryText?: string;
  jobUrl?: string;
  editedFields?: Record<string, string | null>;
  isDemo?: boolean;
}): any;
export function exportReportToMarkdown(report: any): string;
