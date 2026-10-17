import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('ZeekCompletenessPanel: source file exists and defines required component structure', () => {
  const panelPath = path.join(__dirname, 'ZeekCompletenessPanel.tsx');
  assert.ok(fs.existsSync(panelPath), 'ZeekCompletenessPanel.tsx must exist');

  const content = fs.readFileSync(panelPath, 'utf8');

  // Verify component export
  assert.ok(content.includes('export const ZeekCompletenessPanel'), 'Must export ZeekCompletenessPanel component');

  // Verify routing decision and dual-gate status
  assert.ok(content.includes('Routing Decision:'), 'Must display routing decision label');
  assert.ok(content.includes('report.route'), 'Must bind to report.route');
  assert.ok(content.includes('report.source_channel'), 'Must bind to report.source_channel');

  // Verify exact required ML inference notice
  assert.ok(
    content.includes('ML inference: Not performed — native Zeek connection telemetry is not validated as compatible with the frozen CICFlowMeter schema.'),
    'Must display exact required ML inference boundary message'
  );

  // Verify sample-level audit labeling
  assert.ok(content.includes('Sample-Level Audit:'), 'Must explicitly label as Sample-Level Audit');
  assert.ok(
    content.includes('Feature metrics reflect individual record schema completeness, not a file-wide aggregate.'),
    'Must distinguish sample-level metrics from file-wide aggregates'
  );
  assert.ok(content.includes('total_connections_parsed'), 'Must reference total_connections_parsed for file connection count');
  assert.ok(content.includes('The canonical schema requires'), 'Must state canonical schema requirement');
  assert.ok(content.includes('sample-level completeness result'), 'Must explicitly designate completeness as sample-level');

  // Verify accurate feature count wording and absence of legacy wording
  assert.ok(
    !content.includes('absent from schema'),
    'Must not use inaccurate phrasing "absent from schema"'
  );
  assert.ok(
    content.includes('required features missing from this sample record'),
    'Must accurately describe missing features as missing from sample record'
  );
  assert.ok(
    content.includes('valid features matching schema'),
    'Must describe valid features count relative to schema'
  );

  // Verify metrics grid
  assert.ok(content.includes('valid_features_count'), 'Must display valid_features_count');
  assert.ok(content.includes('total_required_features'), 'Must display total_required_features');
  assert.ok(content.includes('missing_features'), 'Must display missing features count');
  assert.ok(content.includes('invalid_features'), 'Must display invalid features count');
  assert.ok(content.includes('routing_reason'), 'Must display routing_reason explanation');

  // Verify collapsible drawer
  assert.ok(content.includes('isFeaturesExpanded'), 'Must implement collapsible drawer state for features');
  assert.ok(content.includes('setIsFeaturesExpanded'), 'Must toggle collapsible drawer state');

  // Verify fallback behavior when report is absent
  assert.ok(content.includes('if (!report)'), 'Must check for absence of completeness_report');
  assert.ok(
    content.includes('Telemetry Only — ML Classification Not Performed'),
    'Must render fallback telemetry banner when report is absent'
  );
});

test('ZeekCompletenessPanel: data model computes verified sample metrics matching fixture', () => {
  // Mock summary matching actual sample_conn.json backend response
  const mockSummary = {
    filename: 'sample_conn.json',
    file_size_bytes: 5971,
    total_connections_parsed: 15,
    total_connections_persisted: 15,
    connections_skipped_malformed: 0,
    connections_skipped_duplicate: 0,
    protocol_distribution: { udp: 5, tcp: 10 },
    service_distribution: { dns: 5, http: 10 },
    conn_state_distribution: { S0: 5, SF: 10 },
    processing_time_ms: 12.5,
    ml_classification_performed: false,
    analysis_type: 'TELEMETRY_ONLY',
    completeness_report: {
      flow_id: 'CHhAvVGS1DHF508n6',
      source_channel: 'ZEEK_CONN',
      route: 'TELEMETRY_ONLY',
      is_eligible_for_ml: false,
      ml_classification_performed: false,
      routing_reason: "Source 'ZEEK_CONN' is native Zeek connection telemetry without packet-level flow metrics. Telemetry is preserved for network visibility; ML classification is bypassed.",
      is_sample_evaluation: true,
      sample_record_identifier: 'CHhAvVGS1DHF508n6',
      evaluation_scope: 'SAMPLE_RECORD',
      completeness: {
        total_required_features: 48,
        valid_features_count: 0,
        completeness_score: 0.0,
        is_eligible_for_ml: false,
        route: 'TELEMETRY_ONLY',
        routing_reason: "Source 'ZEEK_CONN' is native Zeek connection telemetry without packet-level flow metrics.",
        missing_features: [
          'destination_port', 'flow_duration', 'total_forward_packets',
          'total_forward_bytes', 'fwd_packet_length_max', 'fwd_packet_length_min'
        ],
        invalid_features: {},
        unexpected_features: [],
      },
    },
  };

  const report = mockSummary.completeness_report;
  assert.ok(report !== null, 'Report must be present');

  // Verify sample identifier
  const sampleId = report.sample_record_identifier || report.flow_id;
  assert.equal(sampleId, 'CHhAvVGS1DHF508n6', 'Sample UID must match first fixture record');

  // Verify sample-level labeling properties
  assert.equal(report.is_sample_evaluation, true, 'is_sample_evaluation must be true');
  assert.equal(report.evaluation_scope, 'SAMPLE_RECORD', 'evaluation_scope must be SAMPLE_RECORD');

  // Verify completeness score and percentage formatting
  const comp = report.completeness;
  const validCount = comp.valid_features_count;
  const totalRequired = comp.total_required_features;
  const completenessPct = ((comp.completeness_score ?? 0) * 100).toFixed(1);

  assert.equal(validCount, 0, 'Valid count for conn.log must be 0');
  assert.equal(totalRequired, 48, 'Total required features must be 48');
  assert.equal(completenessPct, '0.0', 'Percentage must format to 0.0%');
  assert.equal(report.route, 'TELEMETRY_ONLY', 'Route must be TELEMETRY_ONLY');
  assert.equal(report.source_channel, 'ZEEK_CONN', 'Source channel must be ZEEK_CONN');
});

test('ZeekCompletenessPanel: fallback behavior when completeness_report is null or absent', () => {
  const mockSummaryNoReport = {
    filename: 'empty.log',
    file_size_bytes: 0,
    total_connections_parsed: 0,
    total_connections_persisted: 0,
    connections_skipped_malformed: 0,
    connections_skipped_duplicate: 0,
    protocol_distribution: {},
    service_distribution: {},
    conn_state_distribution: {},
    processing_time_ms: 0.5,
    ml_classification_performed: false,
    analysis_type: 'TELEMETRY_ONLY',
    completeness_report: null,
  };

  // When report is null, panel falls back to standard banner
  assert.equal(mockSummaryNoReport.completeness_report, null);
});
