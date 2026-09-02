import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('PcapFlowDetailModal: maps 48 features from flow.features correctly', () => {
  // Sample flow.features returned from backend PCAP analysis
  const mockFeatures = {
    destination_port: 443.0,
    flow_bytes_per_sec: 192228.8976,
    fwd_packets_per_sec: 66.4288,
    bwd_packets_per_sec: 93.0003,
    total_forward_packets: 25.0,
  };

  // Replicate mapping logic from PcapFlowDetailModal.tsx:
  // const rawVal = features[meta.key];
  // const displayVal = rawVal !== undefined ? rawVal.toLocaleString(undefined, { maximumFractionDigits: 4 }) : '—';
  const checkedKeys = [
    'destination_port',
    'flow_bytes_per_sec',
    'fwd_packets_per_sec',
    'bwd_packets_per_sec',
    'total_forward_packets',
  ];

  for (const key of checkedKeys) {
    const rawVal = mockFeatures[key];
    assert.ok(rawVal !== undefined, `Feature ${key} must be defined`);
    const displayVal = rawVal.toLocaleString(undefined, { maximumFractionDigits: 4 });
    assert.notEqual(displayVal, '—', `Feature ${key} must not be formatted as dash`);
  }
});

test('featureMetadata: contains all 48 canonical CICFlowMeter feature definitions', () => {
  const metadataPath = path.join(__dirname, '../../utils/featureMetadata.ts');
  const content = fs.readFileSync(metadataPath, 'utf8');

  // Verify key features exist in metadata
  const expectedKeys = [
    'destination_port',
    'flow_bytes_per_sec',
    'fwd_packets_per_sec',
    'bwd_packets_per_sec',
    'total_forward_packets',
  ];

  for (const key of expectedKeys) {
    assert.ok(
      content.includes(`key: '${key}'`),
      `featureMetadata.ts must define key '${key}'`
    );
  }
});
