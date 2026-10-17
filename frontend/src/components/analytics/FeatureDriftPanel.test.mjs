import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('FeatureDriftPanel: source file exists and adheres to statistical observability specifications', () => {
  const panelPath = path.join(__dirname, 'FeatureDriftPanel.tsx');
  assert.ok(fs.existsSync(panelPath), 'FeatureDriftPanel.tsx must exist');

  const content = fs.readFileSync(panelPath, 'utf8');
  const normalizedContent = content.replace(/\s+/g, ' ');

  // Verify component export
  assert.ok(content.includes('export const FeatureDriftPanel'), 'Must export FeatureDriftPanel component');

  // Verify mandatory statistical disclaimer
  assert.ok(
    normalizedContent.includes('Statistical Observability Notice:'),
    'Must display Statistical Observability Notice'
  );
  assert.ok(
    normalizedContent.includes('does NOT constitute evidence of malicious activity or an ongoing attack'),
    'Must state explicitly that drift does not prove malicious activity or an attack'
  );
  assert.ok(
    normalizedContent.includes('operational observability signal for model reliability'),
    'Must define drift as an operational observability signal for model reliability'
  );
  assert.ok(
    normalizedContent.includes('No substantial distribution shift was detected under the configured PSI threshold. Model performance was not assessed by this metric.'),
    'Must state exact model performance disclaimer'
  );
  assert.ok(
    normalizedContent.includes('low PSI does not prove model accuracy or confidence is maintained'),
    'Must state low PSI caveat'
  );
  assert.ok(
    normalizedContent.includes('high PSI does not prove an attack is occurring'),
    'Must state high PSI caveat'
  );
  assert.ok(
    normalizedContent.includes('does not measure prediction performance without suitable ground-truth labels'),
    'Must state performance measurement limitation'
  );

  // Verify metric displays
  assert.ok(content.includes('Evaluated Flows'), 'Must display Evaluated Flows metric');
  assert.ok(content.includes('Canonical Features'), 'Must display Canonical Features metric');
  assert.ok(content.includes('Mean PSI'), 'Must display Mean PSI metric');
  assert.ok(content.includes('Shift Tally'), 'Must display Shift Tally summary');

  // Verify status indicators
  assert.ok(content.includes('STABLE DISTRIBUTION'), 'Must handle STABLE status');
  assert.ok(content.includes('MODERATE SHIFT'), 'Must handle MODERATE_DRIFT status');
  assert.ok(content.includes('SIGNIFICANT DRIFT'), 'Must handle SIGNIFICANT_DRIFT status');
  assert.ok(content.includes('INSUFFICIENT SAMPLE'), 'Must handle INSUFFICIENT_DATA status');

  // Verify insufficient sample size caution handling
  assert.ok(
    content.includes('is_sample_size_sufficient'),
    'Must handle is_sample_size_sufficient flag'
  );
  assert.ok(
    content.includes('insufficient_sample_reason'),
    'Must display insufficient_sample_reason explanation'
  );

  // Verify feature table structure
  assert.ok(content.includes('Feature Name'), 'Must include Feature Name column');
  assert.ok(content.includes('PSI'), 'Must include PSI column');
  assert.ok(content.includes("SMD (Cohen's d)"), 'Must include SMD column');
  assert.ok(content.includes('Baseline Mean ± Std'), 'Must include Baseline Mean ± Std column');
  assert.ok(content.includes('Observed Mean ± Std'), 'Must include Observed Mean ± Std column');

  // Verify no prohibited charting/UI dependencies added
  assert.ok(!content.includes('from \'chart.js\''), 'Must not introduce chart.js dependency');
  assert.ok(!content.includes('from \'d3\''), 'Must not introduce d3 dependency');
});
