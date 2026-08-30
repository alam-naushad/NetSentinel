export type DetectionStatus = 'NORMAL' | 'UNKNOWN_ANOMALY' | 'KNOWN_ATTACK';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ModelRole = 'SUPERVISED_CLASSIFIER' | 'STATISTICAL_ANOMALY_DETECTOR';
export type ModelProtocol = 'A' | 'B';
export type DeploymentTier = 'PRODUCTION_DEFAULT' | 'PRODUCTION_ALTERNATIVE' | 'RESEARCH_EVALUATION';

export type AttackFamily =
  | 'BENIGN'
  | 'BOTNET'
  | 'BRUTE_FORCE'
  | 'DDOS'
  | 'DOS'
  | 'HEARTBLEED'
  | 'INFILTRATION'
  | 'PORT_SCAN'
  | 'WEB_ATTACK';
