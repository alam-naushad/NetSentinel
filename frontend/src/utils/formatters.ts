export function formatBytes(bytes: number, decimals = 1): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i] || 'B'}`;
}

export function formatLatency(ms: number): string {
  if (ms < 1) {
    return `${(ms * 1000).toFixed(0)} µs`;
  }
  return `${ms.toFixed(2)} ms`;
}

export function formatPercent(val: number): string {
  return `${(val * 100).toFixed(1)}%`;
}

export function formatNumber(val: number): string {
  return new Intl.NumberFormat().format(val);
}
