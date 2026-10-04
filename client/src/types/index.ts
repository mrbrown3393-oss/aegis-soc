export type Role = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  tenant?: 'government' | 'private' | 'saas';
  department?: string;
  mfaEnabled?: boolean;
  lastLogin?: string;
}

export interface Alert {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: string;
  source: string;
  category: string;
  assetId: string;
  riskScore: number;
  createdAt: string;
  updatedAt: string;
  assignee: string | null;
  description: string;
  mitre?: string;
  aiSummary?: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  owner: string | null;
  relatedAlerts: string[];
  timeline: { ts: string; actor: string; action: string }[];
  impact: string;
}

export interface Asset {
  id: string;
  name: string;
  type: string;
  os: string;
  ip: string;
  criticality: string;
  status: string;
  owner: string;
  lastSeen: string;
  tags: string[];
}

export interface Identity {
  id: string;
  principal: string;
  type: string;
  provider: string;
  riskScore: number;
  mfa: boolean;
  lastAuth: string;
  devices: number;
  privileges: string;
  anomalies: number;
}

export interface Overview {
  simulation: boolean;
  generatedAt: string;
  kpis: {
    openAlerts: number;
    criticalAlerts: number;
    highAlerts: number;
    openIncidents: number;
    assetsMonitored: number;
    identitiesMonitored: number;
    avgIdentityRisk: number;
    policyCoverage: number;
    overallRiskScore: number;
    riskLevel: string;
  };
  assetHealth: { healthy: number; warning: number; critical: number };
  recentAlerts: Alert[];
  activeIncidents: Incident[];
  health: Record<string, { status: string; [k: string]: unknown }>;
  threatIntelCount: number;
  expiringCredentials: number;
}
