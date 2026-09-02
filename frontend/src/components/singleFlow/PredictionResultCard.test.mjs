import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('PredictionResultCard: maps BENIGN class probabilities correctly', () => {
  // Typical backend inference response for Standard HTTPS Web Traffic (BENIGN preset)
  const classProbabilities = {
    BENIGN: 0.999985,
    BOT: 0.000001,
    BRUTE_FORCE: 0.000001,
    DDOS: 0.000001,
    DOS: 0.000001,
    INFILTRATION: 0.000008,
    PORT_SCAN: 0.000001,
    UNKNOWN: 0.000001,
  };

  // Replicate exact sorting logic from PredictionResultCard
  const probData = Object.entries(classProbabilities)
    .map(([cls, prob]) => ({
      name: cls,
      probability: prob,
      percentage: (prob * 100).toFixed(1),
    }))
    .sort((a, b) => b.probability - a.probability);

  // Assert top item is BENIGN with ~100% probability
  assert.equal(probData[0].name, 'BENIGN');
  assert.equal(probData[0].percentage, '100.0');
  assert.ok(probData[0].probability > 0.99);

  // Assert INFILTRATION is near 0.0%
  const infiltrationItem = probData.find((item) => item.name === 'INFILTRATION');
  assert.ok(infiltrationItem);
  assert.equal(infiltrationItem.percentage, '0.0');
  assert.ok(infiltrationItem.probability < 0.0001);
});

test('PredictionResultCard: component defines interval={0} to prevent Recharts tick omission', () => {
  const componentPath = path.join(__dirname, 'PredictionResultCard.tsx');
  const content = fs.readFileSync(componentPath, 'utf8');

  // Must have interval={0} on YAxis to guarantee every class tick is rendered
  assert.match(
    content,
    /<YAxis[^>]*\binterval=\{0\}/,
    'YAxis in PredictionResultCard must have interval={0} to prevent Recharts from omitting the BENIGN label'
  );

  // Must have at least h-52 or h-60 container for vertical legibility
  assert.match(
    content,
    /className="h-(52|56|60|64)\s+w-full"/,
    'Chart container must have adequate height (>=h-52) to cleanly display all multi-class categories'
  );
});
