import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { MessageSquare, Loader2 } from "lucide-react";
import API_URL from "../config";
import { useLanguage } from "../context/LanguageContext";
import type { SupportedLanguage } from "../lib/language";
import { translate } from "../lib/i18n";
import { loadAnalyzePayload, peekAnalyzePayload } from "../lib/analyzeCache";
import { PageHeader, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";

type AnalyzePayload = {
  target: string;
  type: string;
  summary?: {
    risk_sources: number;
    total_sources: number;
    verdict: string;
  };
  results?: Record<string, any>;
  analysis_report?: string;
  analysis_reports?: Partial<Record<"pt" | "en" | "es", string>>;
  analysis_sections?: AnalysisSection[];
  analysis_section_sets?: Partial<Record<"pt" | "en" | "es", AnalysisSection[]>>;
  geo_summary?: GeoSummary;
  analysis_meta?: {
    report_strategy?: string;
    future_enhancer?: {
      provider?: string;
      enabled?: boolean;
      surface?: string;
    };
  };
};

type AnalysisSection = {
  id: string;
  title: string;
  body: string[];
};

type GeoSummary = {
  available?: boolean;
  source?: string | null;
  resolution_path?: string[] | null;
  display_location?: string | null;
  display_entity?: string | null;
  country_code?: string | null;
  country?: string | null;
  city?: string | null;
  region?: string | null;
  isp?: string | null;
  org?: string | null;
  asn?: string | null;
  ip?: string | null;
};

type EvidenceIocType = "ip" | "domain" | "hash" | "url" | "target";

type EvidenceDetailField = {
  key: string;
  label: string;
  value: string;
};

type EvidenceRow = {
  source: string;
  signal: string;
  detailFields: EvidenceDetailField[];
  iocType: EvidenceIocType;
  riskLabel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  pivotValue: string;
};

const SOURCE_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  alienvault: "AlienVault OTX",
  shodan: "Shodan",
  greynoise: "GreyNoise",
  urlscan: "UrlScan.io",
  abusech: "Abuse.ch",
  urlhaus: "URLhaus",
  pulsedive: "Pulsedive",
  blacklistmaster: "BlacklistMaster",
};

function decodeTarget(target?: string) {
  return target ? decodeURIComponent(target) : "unknown";
}

function scoreToPercent(riskSources = 0, totalSources = 0) {
  if (!totalSources) return 0;
  return Math.round((riskSources / totalSources) * 100);
}

function verdictMeta(verdict?: string) {
  if (verdict === "HIGH RISK") {
    return {
      badgeKey: "analysis.badgeCriticalNode",
      colorClass: "bg-error/10 text-error",
      statusKey: "analysis.statusHighRisk",
    };
  }
  if (verdict === "SUSPICIOUS") {
    return {
      badgeKey: "analysis.badgeSuspicious",
      colorClass: "bg-amber-500/10 text-amber-600",
      statusKey: "analysis.statusSuspicious",
    };
  }
  return {
    badgeKey: "analysis.badgeClean",
    colorClass: "bg-emerald-500/10 text-emerald-700",
    statusKey: "analysis.statusSafe",
  };
}

function formatEvidenceSignal(
  language: SupportedLanguage,
  key:
    | "detections"
    | "reports"
    | "openPorts"
    | "noExposedPorts"
    | "pulseCount"
    | "noActivePulses"
    | "classification"
    | "indexedScans"
    | "noRelevantScans"
    | "malwareLinkage"
    | "noMalwareLinkage"
    | "riskLevel"
    | "listed"
    | "notListed"
    | "urlhausActive"
    | "urlhausClean",
  params: Record<string, string | number> = {},
) {
  if (key === "detections") {
    if (language === "pt") return `${params.malicious}/${params.total} detecções`;
    if (language === "es") return `${params.malicious}/${params.total} detecciones`;
    return `${params.malicious}/${params.total} detections`;
  }
  if (key === "reports") {
    if (language === "pt") return `${params.totalReports} relatos (${params.score}% de confiança)`;
    if (language === "es") return `${params.totalReports} reportes (${params.score}% de confianza)`;
    return `${params.totalReports} reports (${params.score}% confidence)`;
  }
  if (key === "openPorts") {
    if (language === "pt") return `Portas abertas: ${params.ports}`;
    if (language === "es") return `Puertos abiertos: ${params.ports}`;
    return `Open ports: ${params.ports}`;
  }
  if (key === "noExposedPorts") {
    if (language === "pt") return "Nenhuma porta exposta reportada";
    if (language === "es") return "No se reportaron puertos expuestos";
    return "No exposed ports reported";
  }
  if (key === "pulseCount") {
    if (language === "pt") return `Quantidade de pulses: ${params.count}`;
    if (language === "es") return `Cantidad de pulses: ${params.count}`;
    return `Pulse count: ${params.count}`;
  }
  if (key === "noActivePulses") {
    if (language === "pt") return "Nenhum pulse ativo";
    if (language === "es") return "Sin pulses activos";
    return "No active pulses";
  }
  if (key === "classification") {
    if (language === "pt") return `Classificação: ${params.classification}`;
    if (language === "es") return `Clasificación: ${params.classification}`;
    return `Classification: ${params.classification}`;
  }
  if (key === "indexedScans") {
    if (language === "pt") return `Varreduras indexadas: ${params.total}`;
    if (language === "es") return `Escaneos indexados: ${params.total}`;
    return `Indexed scans: ${params.total}`;
  }
  if (key === "noRelevantScans") {
    if (language === "pt") return "Nenhuma varredura relevante";
    if (language === "es") return "No hay escaneos relevantes";
    return "No relevant scans";
  }
  if (key === "malwareLinkage") {
    return `${params.threatType} (${params.confidence}%)`;
  }
  if (key === "noMalwareLinkage") {
    if (language === "pt") return "Sem vínculo com malware";
    if (language === "es") return "Sin vínculo con malware";
    return "No malware linkage";
  }
  if (key === "riskLevel") {
    if (language === "pt") return `Nível de risco: ${params.risk}`;
    if (language === "es") return `Nivel de riesgo: ${params.risk}`;
    return `Risk level: ${params.risk}`;
  }
  if (key === "listed") {
    if (language === "pt") return "Presente em fontes de blacklist";
    if (language === "es") return "Presente en fuentes de blacklist";
    return "Present on blacklist sources";
  }
  if (key === "urlhausActive") {
    if (language === "pt") return `${params.urlCount} URLs (${params.urlsOnline} online)`;
    if (language === "es") return `${params.urlCount} URLs (${params.urlsOnline} en línea)`;
    return `${params.urlCount} URLs (${params.urlsOnline} online)`;
  }
  if (key === "urlhausClean") {
    if (language === "pt") return "Sem URLs maliciosas conhecidas";
    if (language === "es") return "Sin URLs maliciosas conocidas";
    return "No known malicious URLs";
  }
  if (language === "pt") return "Não presente em fontes de blacklist";
  if (language === "es") return "No presente en fuentes de blacklist";
  return "Not present on blacklist sources";
}

function getPortTag(
  language: SupportedLanguage,
  port: number,
) {
  if (port === 3389) {
    if (language === "pt") return "Crítico";
    if (language === "es") return "Crítico";
    return "Critical";
  }
  if (port === 443) {
    if (language === "pt") return "Criptografado";
    if (language === "es") return "Cifrado";
    return "Encrypted";
  }
  if (language === "pt") return "Público";
  if (language === "es") return "Público";
  return "Public";
}

function detailLabel(
  language: SupportedLanguage,
  key:
    | "file"
    | "owner"
    | "network"
    | "categories"
    | "isp"
    | "usage"
    | "domain"
    | "org"
    | "os"
    | "location"
    | "asn"
    | "actor"
    | "noise"
    | "server"
    | "page"
    | "resolvedIp"
    | "feeds",
) {
  const labels: Record<string, Record<SupportedLanguage, string>> = {
    file: { pt: "Arquivo", en: "File", es: "Archivo" },
    owner: { pt: "Owner", en: "Owner", es: "Owner" },
    network: { pt: "Rede", en: "Network", es: "Red" },
    categories: { pt: "Categorias", en: "Categories", es: "Categorías" },
    isp: { pt: "ISP", en: "ISP", es: "ISP" },
    usage: { pt: "Uso", en: "Usage", es: "Uso" },
    domain: { pt: "Domínio", en: "Domain", es: "Dominio" },
    org: { pt: "Org", en: "Org", es: "Org" },
    os: { pt: "SO", en: "OS", es: "SO" },
    location: { pt: "Local", en: "Location", es: "Ubicación" },
    asn: { pt: "ASN", en: "ASN", es: "ASN" },
    actor: { pt: "Ator", en: "Actor", es: "Actor" },
    noise: { pt: "Ruído", en: "Noise", es: "Ruido" },
    server: { pt: "Server", en: "Server", es: "Server" },
    page: { pt: "Página", en: "Page", es: "Página" },
    resolvedIp: { pt: "IP", en: "IP", es: "IP" },
    feeds: { pt: "Feeds", en: "Feeds", es: "Feeds" },
  };

  return labels[key][language];
}

function compactDetail(parts: Array<string | undefined | null>) {
  return parts.filter(Boolean).join(" • ");
}

function buildDetailFields(
  fields: Array<EvidenceDetailField | null | undefined>,
) {
  return fields.filter(Boolean) as EvidenceDetailField[];
}

function getOpenPorts(results?: Record<string, any>, language: SupportedLanguage = "pt") {
  const ports: number[] = Array.isArray(results?.shodan?.ports) ? results?.shodan?.ports : [];
  return ports.slice(0, 6).map((port: number) => ({
    port,
    label:
      {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP",
        25: "SMTP",
        53: "DNS",
      }[port] || (language === "pt" ? "Serviço" : language === "es" ? "Servicio" : "Service"),
    tag: getPortTag(language, port),
    danger: port === 3389,
  }));
}

function buildEvidenceRows(
  results?: Record<string, any>,
  language: SupportedLanguage = "pt",
  fallbackPivotValue = "",
): EvidenceRow[] {
  if (!results) return [];
  const rows: EvidenceRow[] = [];

  for (const [service, data] of Object.entries(results)) {
    if (!data || typeof data !== "object" || data.error || data._meta_error) continue;

    if (service === "virustotal") {
      const malicious = data.data?.attributes?.last_analysis_stats?.malicious || 0;
      const total =
        (data.data?.attributes?.last_analysis_stats?.undetected || 0) + malicious;
      rows.push({
        source: SOURCE_LABELS[service],
        signal: formatEvidenceSignal(language, "detections", { malicious, total }),
        detailFields: buildDetailFields([
          data.data?.attributes?.meaningful_name
            ? {
                key: "file",
                label: detailLabel(language, "file"),
                value: data.data.attributes.meaningful_name,
              }
            : null,
          data.data?.attributes?.as_owner
            ? {
                key: "owner",
                label: detailLabel(language, "owner"),
                value: `${data.data.attributes.as_owner}${data.data?.attributes?.asn ? ` (AS${data.data.attributes.asn})` : ""}`,
              }
            : null,
          data.data?.attributes?.network
            ? {
                key: "network",
                label: detailLabel(language, "network"),
                value: data.data.attributes.network,
              }
            : null,
          data.data?.attributes?.categories && Object.keys(data.data.attributes.categories).length > 0
            ? {
                key: "categories",
                label: detailLabel(language, "categories"),
                value: [...new Set(Object.values(data.data.attributes.categories))].join(", "),
              }
            : null,
        ]),
        iocType: "hash",
        riskLabel: malicious >= 8 ? "CRITICAL" : malicious >= 3 ? "HIGH" : malicious >= 1 ? "MEDIUM" : "LOW",
        confidence: Math.min(100, malicious * 12 + 20),
        pivotValue: data.data?.attributes?.meaningful_name || data.data?.id || fallbackPivotValue,
      });
      continue;
    }

    if (service === "abuseipdb") {
      const score = data.data?.abuseConfidenceScore || 0;
      const totalReports = data.data?.totalReports || 0;
      rows.push({
        source: SOURCE_LABELS[service],
        signal: formatEvidenceSignal(language, "reports", { totalReports, score }),
        detailFields: buildDetailFields([
          data.data?.isp
            ? { key: "isp", label: detailLabel(language, "isp"), value: data.data.isp }
            : null,
          data.data?.usageType
            ? { key: "usage", label: detailLabel(language, "usage"), value: data.data.usageType }
            : null,
          data.data?.domain
            ? { key: "domain", label: detailLabel(language, "domain"), value: data.data.domain }
            : null,
        ]),
        iocType: "ip",
        riskLabel: score >= 75 ? "CRITICAL" : score >= 25 ? "HIGH" : score > 0 ? "MEDIUM" : "LOW",
        confidence: Math.min(100, score),
        pivotValue: data.data?.ipAddress || data.data?.domain || fallbackPivotValue,
      });
      continue;
    }

    if (service === "shodan") {
      const ports = Array.isArray(data.ports) ? data.ports : [];
      const hasRdp = ports.includes(3389);
      rows.push({
        source: SOURCE_LABELS[service],
        signal: ports.length
          ? formatEvidenceSignal(language, "openPorts", { ports: ports.slice(0, 5).join(", ") })
          : formatEvidenceSignal(language, "noExposedPorts"),
        detailFields: buildDetailFields([
          data.org ? { key: "org", label: detailLabel(language, "org"), value: data.org } : null,
          data.os ? { key: "os", label: detailLabel(language, "os"), value: data.os } : null,
        ]),
        iocType: "ip",
        riskLabel: hasRdp ? "CRITICAL" : ports.length >= 3 ? "MEDIUM" : "LOW",
        confidence: hasRdp ? 100 : Math.min(100, ports.length * 18 + 20),
        pivotValue: data.ip_str || fallbackPivotValue,
      });
      continue;
    }

    if (service === "alienvault") {
      const pulses = data.pulse_info?.count || 0;
      rows.push({
        source: SOURCE_LABELS[service],
        signal: pulses > 0
          ? formatEvidenceSignal(language, "pulseCount", { count: pulses })
          : formatEvidenceSignal(language, "noActivePulses"),
        detailFields: buildDetailFields([
          data.country_name || data.city
            ? {
                key: "location",
                label: detailLabel(language, "location"),
                value: [data.city, data.country_name].filter(Boolean).join(", "),
              }
            : null,
          data.asn ? { key: "asn", label: detailLabel(language, "asn"), value: data.asn } : null,
        ]),
        iocType: "domain",
        riskLabel: pulses >= 5 ? "CRITICAL" : pulses > 0 ? "HIGH" : "LOW",
        confidence: pulses >= 5 ? 92 : pulses > 0 ? 75 : 20,
        pivotValue: data.indicator || data.address || fallbackPivotValue,
      });
      continue;
    }

    if (service === "greynoise") {
      const classification = data.classification || "unknown";
      rows.push({
        source: SOURCE_LABELS[service],
        signal: formatEvidenceSignal(language, "classification", { classification }),
        detailFields: buildDetailFields([
          data.actor ? { key: "actor", label: detailLabel(language, "actor"), value: data.actor } : null,
          typeof data.noise === "boolean"
            ? { key: "noise", label: detailLabel(language, "noise"), value: String(data.noise) }
            : null,
        ]),
        iocType: "ip",
        riskLabel: classification === "malicious" ? "HIGH" : classification === "unknown" ? "LOW" : "MEDIUM",
        confidence: classification === "malicious" ? 82 : 40,
        pivotValue: data.ip || fallbackPivotValue,
      });
      continue;
    }

    if (service === "urlscan") {
      const total = data.total || 0;
      rows.push({
        source: SOURCE_LABELS[service],
        signal: total > 0
          ? formatEvidenceSignal(language, "indexedScans", { total })
          : formatEvidenceSignal(language, "noRelevantScans"),
        detailFields: buildDetailFields([
          data.results?.[0]?.page?.title
            ? { key: "page", label: detailLabel(language, "page"), value: data.results[0].page.title }
            : null,
          data.results?.[0]?.page?.server
            ? { key: "server", label: detailLabel(language, "server"), value: data.results[0].page.server }
            : null,
          data.results?.[0]?.page?.ip
            ? { key: "resolvedIp", label: detailLabel(language, "resolvedIp"), value: data.results[0].page.ip }
            : null,
        ]),
        iocType: "domain",
        riskLabel: total > 3 ? "HIGH" : total > 0 ? "MEDIUM" : "LOW",
        confidence: total > 0 ? 68 : 20,
        pivotValue: data.results?.[0]?.page?.domain || data.results?.[0]?.page?.ip || fallbackPivotValue,
      });
      continue;
    }

    if (service === "abusech") {
      const entry = Array.isArray(data.data) ? data.data[0] : null;
      rows.push({
        source: SOURCE_LABELS[service],
        signal: entry
          ? formatEvidenceSignal(language, "malwareLinkage", {
              threatType: entry.threat_type || "Malware",
              confidence: entry.confidence_level || 0,
            })
          : formatEvidenceSignal(language, "noMalwareLinkage"),
        detailFields: [],
        iocType: "hash",
        riskLabel: entry ? "CRITICAL" : "LOW",
        confidence: entry?.confidence_level || 15,
        pivotValue: entry?.ioc || entry?.md5_hash || entry?.sha256_hash || fallbackPivotValue,
      });
      continue;
    }

    if (service === "urlhaus") {
      const urlsOnline = Number(data.urls_online || 0);
      const urlCount = Number(data.url_count || 0);
      const hasUrls = urlsOnline > 0 || urlCount > 0;
      rows.push({
        source: SOURCE_LABELS[service],
        signal: hasUrls
          ? formatEvidenceSignal(language, "urlhausActive", {
              urlCount,
              urlsOnline,
            })
          : formatEvidenceSignal(language, "urlhausClean"),
        detailFields: [],
        iocType: "url",
        riskLabel: urlsOnline > 0 ? "HIGH" : urlCount > 0 ? "MEDIUM" : "LOW",
        confidence: urlsOnline > 0 ? 85 : urlCount > 0 ? 55 : 15,
        pivotValue: fallbackPivotValue,
      });
      continue;
    }

    if (service === "pulsedive") {
      const risk = data.risk || "none";
      rows.push({
        source: SOURCE_LABELS[service],
        signal: formatEvidenceSignal(language, "riskLevel", { risk }),
        detailFields: buildDetailFields([
          data.feeds
            ? {
                key: "feeds",
                label: detailLabel(language, "feeds"),
                value: String(Object.keys(data.feeds).length),
              }
            : null,
        ]),
        iocType: "target",
        riskLabel: risk === "critical" ? "CRITICAL" : risk === "high" ? "HIGH" : risk === "medium" ? "MEDIUM" : "LOW",
        confidence: risk === "critical" ? 95 : risk === "high" ? 86 : risk === "medium" ? 60 : 20,
        pivotValue: data.indicator || fallbackPivotValue,
      });
      continue;
    }

    if (service === "blacklistmaster") {
      const listed = data._meta_msg !== "No content returned";
      rows.push({
        source: SOURCE_LABELS[service],
        signal: formatEvidenceSignal(language, listed ? "listed" : "notListed"),
        detailFields: [],
        iocType: "target",
        riskLabel: listed ? "HIGH" : "LOW",
        confidence: listed ? 88 : 25,
        pivotValue: fallbackPivotValue,
      });
    }
  }

  return rows;
}

function riskBadgeClasses(level: EvidenceRow["riskLabel"]) {
  if (level === "CRITICAL") return "bg-error/10 text-error";
  if (level === "HIGH") return "bg-error-container/30 text-on-error-container";
  if (level === "MEDIUM") return "bg-amber-500/10 text-amber-600";
  return "bg-slate-500/10 text-slate-600";
}

function countryFlag(code?: string | null) {
  if (!code || code.length !== 2) return "";
  return code
    .toUpperCase()
    .replace(/./g, (char) => String.fromCodePoint(127397 + char.charCodeAt(0)));
}

function formatSummaryLocation(geo?: GeoSummary | null) {
  if (!geo?.available) return "";
  const parts = [geo.country, geo.region, geo.city].filter(Boolean);
  if (!parts.length) return "";
  return parts.join(", ");
}

function getArtifactLabel(type: string | undefined, t: (key: string, fallback?: string) => string) {
  if (type === "ip") return t("analysis.artifactIp", "IP");
  if (type === "domain") return t("analysis.artifactDomain", "domain");
  if (type === "hash") return t("analysis.artifactHash", "hash");
  if (type === "url") return t("analysis.artifactUrl", "URL");
  return t("analysis.artifactTarget", "target");
}

function getRiskLabel(level: EvidenceRow["riskLabel"], t: (key: string, fallback?: string) => string) {
  if (level === "CRITICAL") return t("analysis.riskCritical", "CRITICAL");
  if (level === "HIGH") return t("analysis.riskHigh", "HIGH");
  if (level === "MEDIUM") return t("analysis.riskMedium", "MEDIUM");
  return t("analysis.riskLow", "LOW");
}

function truncateResultArtifact(value: string, type?: string) {
  if (type !== "hash") return value;
  if (value.length <= 20) return value;
  return `${value.slice(0, 20)}...`;
}

function formatSectionsToPlainText(sections: AnalysisSection[]) {
  return sections
    .flatMap((section) => [section.title, ...section.body.map((line) => `• ${line}`), ""])
    .join("\n")
    .trim();
}

function buildConciseAnalystSections(args: {
  target: string;
  targetType?: string;
  reportLanguage: "pt" | "en" | "es";
  verdictStatus: string;
  threatScore: number;
  riskSources: number;
  totalSources: number;
  fileName?: string;
  provider?: string;
  providerAsn?: string;
  providerDomain?: string;
  usageType?: string;
  location?: string;
  ports: Array<{ port: number }>;
}) {
  const rt = (key: string, fallback?: string) => translate(args.reportLanguage, key, fallback);
  const artifactLabel = getArtifactLabel(args.targetType, rt).toUpperCase();
  const sections: AnalysisSection[] = [];

  if (args.totalSources > 0) {
    sections.push({
      id: "executive_summary",
      title: rt("analysis.conciseExecutiveTitle", "Executive Summary"),
      body: [
        `${artifactLabel} ${args.target} ${rt("analysis.conciseExecutiveMiddle", "was classified as")} ${args.verdictStatus.toLowerCase()} ${rt("analysis.conciseExecutiveSuffix", "with a threat score of")} ${args.threatScore}%.`,
      ],
    });
  }

  const contextLines = [
    args.fileName
      ? `${rt("analysis.fileNameLabel", "File name")}: ${args.fileName}`
      : "",
    args.provider
      ? `${rt("analysis.providerLabel", "Provider")}: ${args.provider}${args.providerAsn ? ` (${args.providerAsn})` : ""}`
      : args.providerAsn
        ? `${rt("analysis.asnLabel", "ASN")}: ${args.providerAsn}`
        : "",
    args.providerDomain
      ? `${rt("analysis.domainLabel", "Domain")}: ${args.providerDomain}`
      : "",
    args.usageType
      ? `${rt("analysis.usageLabel", "Usage")}: ${args.usageType}`
      : "",
    args.location
      ? `${rt("analysis.locationLabel", "Location")}: ${args.location}`
      : rt("analysis.conciseNoReliableLocation", "No reliable location context was returned."),
    args.ports.length
      ? `${rt("analysis.concisePortsLabel", "Observed ports")}: ${args.ports.slice(0, 6).map((port) => port.port).join(", ")}`
      : rt("analysis.conciseNoObservedPorts", "No exposed ports were observed in the active sources."),
  ].filter(Boolean);

  sections.push({
    id: "operational_context",
    title: rt("analysis.conciseContextTitle", "Operational Context"),
    body: contextLines.slice(0, 3),
  });

  const confidenceLine =
    args.totalSources <= 2
      ? rt("analysis.conciseConfidenceLowCoverage", "Coverage is limited and the conclusion should be treated with caution.")
      : `${rt("analysis.conciseConfidenceCoveragePrefix", "Coverage includes")} ${args.totalSources} ${rt("analysis.conciseConfidenceCoverageSuffix", "active sources, with")} ${args.riskSources}/${args.totalSources} ${rt("analysis.conciseConfidenceCoverageTail", "indicating elevated risk.")}`;

  const signalLine =
    args.riskSources === 0
      ? rt("analysis.conciseConfidenceNoRisk", "No source returned signals strong enough to sustain a risk escalation.")
      : args.riskSources === args.totalSources
        ? rt("analysis.conciseConfidenceConvergent", "The active sources are strongly convergent and reinforce the current verdict.")
        : rt("analysis.conciseConfidenceMixed", "The source picture is mixed, so the verdict should be read together with the supporting context.")
        ;

  sections.push({
    id: "confidence_coverage",
    title: rt("analysis.conciseConfidenceTitle", "Confidence & Coverage"),
    body: [confidenceLine, signalLine],
  });

  const actionBody =
    args.threatScore >= 70
      ? [
          rt("analysis.conciseActionHigh", "Escalate triage, preserve evidence, and correlate this artifact with adjacent activity immediately."),
        ]
      : args.threatScore > 0
        ? [
            rt("analysis.conciseActionMedium", "Maintain monitoring, validate the supporting context, and pivot only on the strongest indicators."),
          ]
        : [
            rt("analysis.conciseActionLow", "Treat this artifact as currently low-risk, but keep it available for future correlation if new evidence appears."),
          ];

  sections.push({
    id: "recommended_action",
    title: rt("analysis.conciseActionTitle", "Recommended Action"),
    body: actionBody,
  });

  return sections;
}

export default function AnalysisResult() {
  const { language, t } = useLanguage();
  const navigate = useNavigate();
  const { target } = useParams();
  const displayTarget = decodeTarget(target);
  const [payload, setPayload] = useState<AnalyzePayload | null>(() => peekAnalyzePayload<AnalyzePayload>(displayTarget, language));
  const [reportLanguage, setReportLanguage] = useState<"pt" | "en" | "es">(language);
  const [loading, setLoading] = useState(() => !peekAnalyzePayload<AnalyzePayload>(displayTarget, language));
  const [error, setError] = useState<string | null>(null);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [launchingSocc, setLaunchingSocc] = useState(false);

  useEffect(() => {
    setReportLanguage(language);
  }, [language]);

  useEffect(() => {
    localStorage.setItem("lastSearch", displayTarget);
  }, [displayTarget]);

  useEffect(() => {
    let cancelled = false;
    const cachedPayload = peekAnalyzePayload<AnalyzePayload>(displayTarget, language);

    setPayload(cachedPayload);
    setLoading(!cachedPayload);
    setError(null);

    loadAnalyzePayload<AnalyzePayload>(displayTarget, language)
      .then((data) => {
        if (cancelled) return;
        setPayload(data);
      })
      .catch((err: Error) => {
        if (cancelled) return;
        setError(err.message);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [displayTarget, language]);

  const summary = payload?.summary;
  const threatScore = scoreToPercent(summary?.risk_sources, summary?.total_sources);
  const meta = verdictMeta(summary?.verdict);
  const ports = getOpenPorts(payload?.results, language);
  const rows = buildEvidenceRows(payload?.results, language, displayTarget);
  const currentReport =
    payload?.analysis_reports?.[reportLanguage] ||
    payload?.analysis_report ||
    t("analysis.noReport", "No narrative report was generated for this target.");
  const currentSections =
    payload?.analysis_section_sets?.[reportLanguage] ||
    payload?.analysis_sections ||
    [];
  const geoSummary = payload?.geo_summary;

  const entity =
    geoSummary?.display_entity ||
    payload?.results?.virustotal?.data?.attributes?.as_owner ||
    payload?.results?.shodan?.org ||
    payload?.results?.alienvault?.asn ||
    "Unclassified";

  const category =
    payload?.results?.abusech?.data?.[0]?.threat_type ||
    payload?.results?.greynoise?.classification ||
    summary?.verdict ||
    t("analysis.unknown", "Unknown");
  const location = formatSummaryLocation(geoSummary);
  const locationFlag = countryFlag(geoSummary?.country_code);
  const artifactLabel = getArtifactLabel(payload?.type, t);
  const summaryArtifactValue = truncateResultArtifact(displayTarget, payload?.type);
  const analysisSubtitle = `${t("analysis.subtitlePrefix", "Consolidated intelligence profile assembled from")} ${summary?.total_sources || 0} ${t("analysis.subtitleMiddle", "active sources for this")} ${artifactLabel}.`;
  const fileName = payload?.results?.virustotal?.data?.attributes?.meaningful_name || "";
  const provider =
    geoSummary?.isp ||
    payload?.results?.abuseipdb?.data?.isp ||
    payload?.results?.shodan?.org ||
    payload?.results?.virustotal?.data?.attributes?.as_owner ||
    "";
  const providerAsn =
    geoSummary?.asn ||
    payload?.results?.alienvault?.asn ||
    payload?.results?.virustotal?.data?.attributes?.asn ||
    "";
  const providerDomain =
    payload?.results?.abuseipdb?.data?.domain ||
    payload?.results?.urlscan?.results?.[0]?.page?.domain ||
    "";
  const usageType = payload?.results?.abuseipdb?.data?.usageType || "";
  const conciseSections = useMemo(
    () =>
      buildConciseAnalystSections({
        target: displayTarget,
        targetType: payload?.type,
        reportLanguage,
        verdictStatus: translate(reportLanguage, meta.statusKey, "Safe"),
        threatScore,
        riskSources: summary?.risk_sources || 0,
        totalSources: summary?.total_sources || 0,
        fileName,
        provider,
        providerAsn,
        providerDomain,
        usageType,
        location: location || "",
        ports,
      }),
    [
      displayTarget,
      fileName,
      location,
      meta.statusKey,
      payload?.type,
      ports,
      provider,
      providerAsn,
      providerDomain,
      reportLanguage,
      summary?.risk_sources,
      summary?.total_sources,
      threatScore,
      usageType,
    ],
  );
  const reportTextForExport =
    conciseSections.length > 0
      ? formatSectionsToPlainText(conciseSections)
      : currentReport;

  const exportJson = () => {
    const blob = new Blob(
      [JSON.stringify(payload?.results || {}, null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `vantage-analysis-${displayTarget}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const exportPdf = async () => {
    if (!payload) return;
    setExportingPdf(true);
    try {
      const { generatePdfReport } = await import("../utils/pdfReport");
      generatePdfReport(payload, reportTextForExport, reportLanguage);
    } finally {
      setExportingPdf(false);
    }
  };

  const analyzeWithSocc = async () => {
    if (!payload || !displayTarget) return;
    setLaunchingSocc(true);
    try {
      // Collect IOCs from payload
      const ips: string[] = [];
      const domains: string[] = [];
      const hashes: string[] = [];

      if (payload.results) {
        for (const [, data] of Object.entries(payload.results)) {
          if (typeof data === "object" && data !== null) {
            const d = data as Record<string, any>;
            if (d.ip_str) ips.push(d.ip_str);
            if (d.ip) ips.push(d.ip);
            if (d.data?.domain) domains.push(d.data.domain);
          }
        }
      }

      // Detect target type
      const targetLooksLikeIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(displayTarget);
      const targetLooksLikeHash = /^[a-fA-F0-9]{32,64}$/.test(displayTarget);
      if (targetLooksLikeIp) ips.push(displayTarget);
      else if (targetLooksLikeHash) hashes.push(displayTarget);
      else domains.push(displayTarget);

      const analysisId = `analyze:${encodeURIComponent(displayTarget)}`;

      // Create a session and inject context
      const providersRes = await fetch(`${API_URL}/api/socc/providers`, { credentials: "include" });
      if (!providersRes.ok) {
        navigate("/socc");
        return;
      }
      const providersData = await providersRes.json();
      const creds: any[] = providersData.credentials ?? [];
      if (creds.length === 0) {
        navigate("/socc");
        return;
      }

      const sessionRes = await fetch(`${API_URL}/api/socc/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ credentialId: creds[0].id, analysisId }),
      });
      if (!sessionRes.ok) {
        navigate("/socc");
        return;
      }
      const { sessionId } = await sessionRes.json();

      // Inject context
      await fetch(`${API_URL}/api/socc/session/${sessionId}/context`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          ips: ips.length ? [...new Set(ips)] : undefined,
          domains: domains.length ? [...new Set(domains)] : undefined,
          hashes: hashes.length ? [...new Set(hashes)] : undefined,
          rawContext: payload.analysis_report ?? payload.analysis_sections?.map(s => s.body.join(" ")).join("\n"),
          analysisId,
        }),
      });

      navigate(`/socc?sessionId=${sessionId}`);
    } catch {
      navigate("/socc");
    } finally {
      setLaunchingSocc(false);
    }
  };

  useEffect(() => {
    function handleExportCurrentView() {
      if (!payload) return;
      void exportPdf();
    }

    window.addEventListener("vantage:export-current-view", handleExportCurrentView);
    return () => window.removeEventListener("vantage:export-current-view", handleExportCurrentView);
  }, [payload, reportLanguage, reportTextForExport]);

  if (loading) {
    return (
      <div className="page-frame analyze-page-frame">
        <div className="surface-section px-6 py-8 text-sm text-on-surface-variant">
          {t("analysis.loadingPrefix", "Running cross-provider analysis for")}{" "}
          <strong className="text-on-surface">{displayTarget}</strong>
          ...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-frame analyze-page-frame max-w-4xl">
        <div className="surface-section overflow-hidden border-error/20">
          <div className="bg-surface-container-high px-6 py-4">
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">
              {t("analysis.failureTitle", "Analysis Failure")}
            </h2>
          </div>
          <div className="px-6 py-8 text-error text-sm">{error}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="page-frame analyze-page-frame space-y-8">
      <PageHeader
        title={displayTarget}
        description={analysisSubtitle}
      />

      <PageToolbar label={t("analysis.evidenceActions", "Evidence actions")}>
        <PageToolbarGroup className="ml-auto">
          <label className="inline-flex items-center gap-2 rounded-sm bg-surface-container-low px-3 py-2 text-xs font-semibold text-on-surface">
            {t("analysis.reportLanguage", "Report language")}
            <select
              value={reportLanguage}
              onChange={(event) =>
                setReportLanguage(event.target.value as "pt" | "en" | "es")
              }
              className="bg-transparent text-on-surface outline-none"
              aria-label={t("analysis.reportLanguage", "Report language")}
              title={t("analysis.reportLanguage", "Report language")}
            >
              <option value="pt">PT</option>
              <option value="en">EN</option>
              <option value="es">ES</option>
            </select>
          </label>
          <button
            className="btn btn-outline"
            onClick={exportJson}
          >
            {t("analysis.exportJson", "Export JSON")}
          </button>
          <button
            className="btn btn-secondary flex items-center gap-2"
            onClick={() => void analyzeWithSocc()}
            disabled={launchingSocc || !payload}
            title={t("analysis.analyzeWithSocc", "Analyze with SOC Copilot")}
          >
            {launchingSocc ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <MessageSquare className="w-4 h-4" />
            )}
            {t("analysis.analyzeWithSocc", "Analyze with SOCC")}
          </button>
          <button
            className="btn btn-primary"
            onClick={() => void exportPdf()}
            disabled={exportingPdf}
          >
            {exportingPdf
              ? t("analysis.exportingPdf", "Exporting PDF...")
              : t("analysis.exportPdf", "Export PDF")}
          </button>
        </PageToolbarGroup>
      </PageToolbar>

      <div className="page-with-side-rail">
        <div className="page-main-pane space-y-6">
          <section className="surface-section flex flex-col h-full">
            <header className="surface-section-header">
              <div>
                <h2 className="surface-section-title uppercase">{t("analysis.evidenceTitle", "Evidence & Indicators")}</h2>
                <p className="mt-1 text-[10px] text-on-surface-variant font-medium">
                  {t("analysis.evidenceSubtitlePrefix", "Showing live search results from")} {summary?.total_sources || 0}{" "}
                  {t("analysis.evidenceSubtitleSuffix", "intelligence sources")}
                </p>
              </div>
            </header>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-surface-container text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
                    <th className="px-6 py-3">{t("analysis.source", "Source")}</th>
                    <th className="px-6 py-3">{t("analysis.indicatorSignal", "Indicator / Signal")}</th>
                    <th className="px-6 py-3">{t("analysis.riskLevel", "Risk Level")}</th>
                    <th className="px-6 py-3">{t("analysis.confidence", "Confidence")}</th>
                    <th className="px-6 py-3 text-right">{t("analysis.action", "Action")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-container-low">
                  {rows.length > 0 ? (
                    rows.map((row) => (
                      <tr key={`${row.source}-${row.signal}`} className="hover:bg-surface-container-low transition-colors duration-150 h-10">
                        <td className="px-6 py-2">
                          <span className="text-[11px] font-bold text-primary-dim">{row.source}</span>
                        </td>
                        <td className="px-6 py-2">
                          <div className="space-y-1">
                            <span className="text-[11px] font-medium text-on-surface">{row.signal}</span>
                            {row.detailFields.length > 0 ? (
                              <div className="text-[10px] text-on-surface-variant break-words">
                                {row.detailFields.map((field) => `${field.label}: ${field.value}`).join(" • ")}
                              </div>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-6 py-2">
                          <span className={`text-[10px] px-2 py-0.5 font-black rounded-sm ${riskBadgeClasses(row.riskLabel)}`}>
                            {getRiskLabel(row.riskLabel, t)}
                          </span>
                        </td>
                        <td className="px-6 py-2">
                          <div className="w-20 h-1 bg-surface-container-low rounded-full overflow-hidden">
                            <div
                              className={row.riskLabel === "CRITICAL" || row.riskLabel === "HIGH" ? "bg-error h-full" : row.riskLabel === "MEDIUM" ? "bg-amber-500 h-full" : "bg-slate-500 h-full"}
                              style={{ width: `${row.confidence}%` }}
                            ></div>
                          </div>
                        </td>
                        <td className="px-6 py-2 text-right">
                          <button
                            className="text-primary-dim hover:underline text-[11px] font-bold"
                            onClick={() => navigate(`/analyze/${encodeURIComponent(row.pivotValue || displayTarget)}`)}
                          >
                            {t("analysis.pivot", "Pivot")}
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-sm text-on-surface-variant">
                        {t("analysis.noSuccessfulSources", "No successful source responses were returned for this target.")}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="surface-section overflow-hidden">
            <header className="surface-section-header">
              <div>
                <h2 className="surface-section-title uppercase">{t("analysis.analystReportTitle", "Analyst Report")}</h2>
                <p className="mt-1 text-[10px] text-on-surface-variant font-medium">
                  {t("analysis.analystReportSubtitle", "Structured analyst synthesis generated by the VANTAGE analysis engine")}
                </p>
              </div>
            </header>
            <div className="px-6 py-5">
              {conciseSections.length ? (
                <div className="space-y-6">
                  {conciseSections.map((section) => (
                    <section key={section.id} className="space-y-3">
                      <div className="text-[11px] font-black uppercase tracking-[0.16em] text-on-surface">
                        {section.title}
                      </div>
                      <ul className="space-y-3 text-sm leading-7 text-on-surface-variant">
                        {section.body.map((line, index) => (
                          <li key={`${section.id}-${index}`} className="flex gap-3">
                            <span className="mt-2 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-primary"></span>
                            <span>{line}</span>
                          </li>
                        ))}
                      </ul>
                    </section>
                  ))}
                </div>
              ) : currentSections.length ? (
                <div className="space-y-6">
                  {currentSections.map((section) => (
                    <section key={section.id} className="space-y-3">
                      <div className="text-[11px] font-black uppercase tracking-[0.16em] text-on-surface">
                        {section.title}
                      </div>
                      <ul className="space-y-3 text-sm leading-7 text-on-surface-variant">
                        {section.body.map((line, index) => (
                          <li key={`${section.id}-${index}`} className="flex gap-3">
                            <span className="mt-2 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-primary"></span>
                            <span>{line}</span>
                          </li>
                        ))}
                      </ul>
                    </section>
                  ))}
                </div>
              ) : (
                <pre className="whitespace-pre-wrap text-sm leading-7 text-on-surface-variant font-sans">
                  {currentReport}
                </pre>
              )}
            </div>
          </section>
        </div>

        <div className="page-side-rail-right">
        <section className="surface-section p-0 overflow-hidden">
          <header className="bg-surface-container-high px-4 py-3 flex justify-between items-center">
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">{t("analysis.resultsSummaryTitle", "Results Summary")}</h2>
            <span className={`text-[10px] font-black px-2 py-0.5 rounded-sm ${meta.colorClass}`}>{t(meta.badgeKey, "CLEAN")}</span>
          </header>
          <div className="p-6 flex flex-col items-center text-center">
            <div className="relative w-32 h-32 mb-6 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90">
                <circle className="text-surface-container-low" cx="64" cy="64" fill="transparent" r="58" stroke="currentColor" strokeWidth="8"></circle>
                <circle
                  className={summary?.verdict === "HIGH RISK" ? "text-error" : summary?.verdict === "SUSPICIOUS" ? "text-amber-500" : "text-emerald-500"}
                  cx="64"
                  cy="64"
                  fill="transparent"
                  r="58"
                  stroke="currentColor"
                  strokeDasharray="364.4"
                  strokeDashoffset={364.4 - (364.4 * threatScore) / 100}
                  strokeWidth="8"
                ></circle>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-black text-on-surface leading-none">{threatScore}</span>
                <span className="text-[9px] font-bold text-on-surface-variant uppercase tracking-tighter">{t("analysis.resultsThreatScore", "Threat Score")}</span>
              </div>
            </div>
            <div className="space-y-1 mb-8">
              <h3
                className="max-w-full overflow-hidden text-2xl font-bold tracking-tight text-on-surface break-all"
                title={displayTarget}
              >
                {summaryArtifactValue}
              </h3>
              <p className="text-sm text-outline font-medium">{artifactLabel.toUpperCase()}</p>
            </div>
            <div className="w-full grid grid-cols-2 gap-4 text-left border-t border-surface-container-low pt-6">
              <div>
                <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.statusLabel", "Status")}</p>
                <div className="flex items-center space-x-2">
                  <div className={`w-2 h-2 rounded-full ${summary?.verdict === "HIGH RISK" ? "bg-error" : summary?.verdict === "SUSPICIOUS" ? "bg-amber-500" : "bg-emerald-500"}`}></div>
                  <span className={`text-sm font-bold ${summary?.verdict === "HIGH RISK" ? "text-error" : summary?.verdict === "SUSPICIOUS" ? "text-amber-600" : "text-emerald-700"}`}>
                    {t(meta.statusKey, "Safe")}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.entityLabel", "Entity")}</p>
                <span className="text-sm font-bold text-on-surface">{entity || t("analysis.unclassified", "Unclassified")}</span>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.validSourcesLabel", "Valid Sources")}</p>
                <span className="text-sm font-medium text-on-surface">
                  {summary?.risk_sources || 0}/{summary?.total_sources || 0}
                </span>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.categoryLabel", "Category")}</p>
                <span className="text-sm font-medium text-on-surface" style={{ textTransform: "capitalize" }}>
                  {String(category).replace(/_/g, " ")}
                </span>
              </div>
              <div className="col-span-2">
                <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.locationLabel", "Location")}</p>
                <span className="text-sm font-medium text-on-surface">
                  {locationFlag ? `${locationFlag} ` : ""}
                  {location || t("analysis.unavailable", "Unavailable")}
                </span>
              </div>
              {fileName ? (
                <div className="col-span-2">
                  <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.fileNameLabel", "File name")}</p>
                  <span className="text-sm font-medium text-on-surface break-all">{fileName}</span>
                </div>
              ) : null}
              {provider ? (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.providerLabel", "Provider")}</p>
                  <span className="text-sm font-medium text-on-surface">{provider}</span>
                </div>
              ) : null}
              {providerAsn ? (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.asnLabel", "ASN")}</p>
                  <span className="text-sm font-medium text-on-surface">{providerAsn}</span>
                </div>
              ) : null}
              {providerDomain ? (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.domainLabel", "Domain")}</p>
                  <span className="text-sm font-medium text-on-surface break-all">{providerDomain}</span>
                </div>
              ) : null}
              {usageType ? (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-outline-variant font-bold mb-1">{t("analysis.usageLabel", "Usage")}</p>
                  <span className="text-sm font-medium text-on-surface">{usageType}</span>
                </div>
              ) : null}
            </div>
          </div>
        </section>

        <section className="surface-section overflow-hidden">
          <header className="bg-surface-container-high px-4 py-3">
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">{t("analysis.activeExposureTitle", "Active Exposure (Ports)")}</h2>
          </header>
          <div className="p-4 space-y-2">
            {ports.length > 0 ? (
              ports.map((port) => (
                <div
                  key={port.port}
                  className={`flex items-center justify-between p-3 rounded-sm ${port.danger ? "border border-error-container bg-error/5" : "bg-surface-container-low"}`}
                >
                  <div className="flex items-center space-x-3">
                    <span className={`text-sm font-bold ${port.danger ? "text-error" : "text-primary-dim"}`}>{port.port}</span>
                    <span className="text-xs font-semibold text-on-surface">{port.label}</span>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 font-bold uppercase ${port.danger ? "bg-error/10 text-error" : "bg-primary/10 text-primary-dim"}`}>
                    {port.tag}
                  </span>
                </div>
              ))
            ) : (
              <div className="p-3 bg-surface-container-low rounded-sm text-sm text-on-surface-variant">
                {t("analysis.noExposedPorts", "No exposed ports were returned by the active sources.")}
              </div>
            )}
          </div>
        </section>
        </div>
      </div>
    </div>
  );
}
