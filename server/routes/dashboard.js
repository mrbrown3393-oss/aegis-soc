import { Router } from 'express';
import { store } from '../data/store.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();
router.use(authenticate);

router.get('/overview', (req, res) => {
  const openAlerts = store.alerts.filter(a => !['resolved', 'dismissed'].includes(a.status));
  const critical = openAlerts.filter(a => a.severity === 'critical').length;
  const high = openAlerts.filter(a => a.severity === 'high').length;
  const openIncidents = store.incidents.filter(i => !['closed', 'resolved'].includes(i.status));
  const avgRisk = Math.round(
    store.identities.reduce((s, i) => s + i.riskScore, 0) / store.identities.length
  );
  const assetHealth = {
    healthy: store.assets.filter(a => a.status === 'healthy').length,
    warning: store.assets.filter(a => a.status === 'warning').length,
    critical: store.assets.filter(a => a.status === 'critical').length
  };
  const policyCoverage = Math.round(
    store.policies.reduce((s, p) => s + p.coverage, 0) / store.policies.length
  );

  const riskScore = Math.min(100, Math.round(
    critical * 18 + high * 8 + openIncidents.length * 6 +
    (100 - policyCoverage) * 0.3 + avgRisk * 0.2
  ));

  res.json({
    simulation: true,
    generatedAt: new Date().toISOString(),
    org: 'Aegis Demo Corporation',
    kpis: {
      openAlerts: openAlerts.length,
      criticalAlerts: critical,
      highAlerts: high,
      openIncidents: openIncidents.length,
      assetsMonitored: store.assets.length,
      identitiesMonitored: store.identities.length,
      avgIdentityRisk: avgRisk,
      policyCoverage,
      overallRiskScore: riskScore,
      riskLevel: riskScore >= 70 ? 'critical' : riskScore >= 45 ? 'elevated' : riskScore >= 25 ? 'moderate' : 'low'
    },
    assetHealth,
    recentAlerts: openAlerts.slice(0, 8),
    activeIncidents: openIncidents,
    health: store.health,
    threatIntelCount: store.threatIntel.length,
    expiringCredentials: store.credentials.filter(c => c.status === 'expiring' || c.risk === 'critical').length
  });
});

router.get('/health', (req, res) => {
  res.json({ ...store.health, simulation: true, timestamp: new Date().toISOString() });
});

export default router;
