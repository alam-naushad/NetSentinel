import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Radio, Info, RefreshCw, Layers } from 'lucide-react';
import { ZeekIngestionStatus, ZeekLiveEvent, ZeekSSEConnectionState } from '../../types/zeek';
import { ZeekStreamClient, zeekStreamApi } from '../../api/zeekStreamApi';
import { ZeekConnectionIndicator } from './ZeekConnectionIndicator';
import { ZeekLiveStats } from './ZeekLiveStats';
import { ZeekLiveConnectionTable } from './ZeekLiveConnectionTable';

const MAX_STREAM_BUFFER = 500;

export const ZeekLiveView: React.FC = () => {
  const [connectionState, setConnectionState] = useState<ZeekSSEConnectionState>('CONNECTING');
  const [ingestionStatus, setIngestionStatus] = useState<ZeekIngestionStatus | null>(null);
  const [events, setEvents] = useState<ZeekLiveEvent[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [totalStreamedCount, setTotalStreamedCount] = useState(0);

  const clientRef = useRef<ZeekStreamClient | null>(null);
  const pausedRef = useRef(false);
  pausedRef.current = isPaused;

  // Fetch backend ingestion status
  const fetchStatus = useCallback(async () => {
    try {
      const status = await zeekStreamApi.getIngestionStatus();
      setIngestionStatus(status);
      if (!status.enabled) {
        setConnectionState('DISABLED');
      }
    } catch {
      // Ingestion status API error
    }
  }, []);

  // Connect to SSE stream
  const startStreaming = useCallback(() => {
    if (clientRef.current) {
      clientRef.current.disconnect();
    }

    const client = new ZeekStreamClient();
    clientRef.current = client;

    client.connect({
      onEvent: (event) => {
        setTotalStreamedCount((c) => c + 1);
        if (!pausedRef.current) {
          setEvents((prev) => [event, ...prev.slice(0, MAX_STREAM_BUFFER - 1)]);
        }
      },
      onStatusChange: (status) => {
        setConnectionState(status);
      },
      onError: () => {
        // SSE error handled by reconnect logic
      },
    });
  }, []);

  useEffect(() => {
    fetchStatus();
    startStreaming();

    const statusInterval = window.setInterval(fetchStatus, 5000);

    return () => {
      window.clearInterval(statusInterval);
      if (clientRef.current) {
        clientRef.current.disconnect();
        clientRef.current = null;
      }
    };
  }, [fetchStatus, startStreaming]);

  const handleTogglePause = () => {
    setIsPaused((p) => !p);
  };

  const handleClear = () => {
    setEvents([]);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Radio className="w-5 h-5 text-emerald-400" />
              Zeek Real-Time Telemetry Stream
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-600/40 uppercase tracking-wider">
              Stage 9B • Live SSE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time native Zeek connection stream from local spool directory via Server-Sent Events (SSE).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <ZeekConnectionIndicator
            status={connectionState}
            onReconnect={startStreaming}
          />
        </div>
      </div>

      {/* Telemetry-Only Banner */}
      <div className="flex items-start gap-3 p-3.5 bg-blue-950/40 border border-blue-800/40 rounded-xl text-blue-300 text-xs">
        <Info className="w-4 h-4 shrink-0 mt-0.5 text-blue-400" />
        <div className="space-y-0.5">
          <p className="font-semibold text-blue-200">
            Telemetry Only — ML Classification Not Performed
          </p>
          <p className="text-blue-300/80 leading-relaxed">
            This live stream displays native Zeek connection metadata in real time. In accordance with Stage 9A validation findings, no automated ML attack classification, risk score, or anomaly score is applied to native Zeek connection logs.
          </p>
        </div>
      </div>

      {/* Live Stats */}
      <ZeekLiveStats
        status={ingestionStatus}
        liveSessionCount={totalStreamedCount}
      />

      {/* Live Connection Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Live Connection Activity</h3>
            <p className="text-xs text-slate-400">
              Streaming newest connections (rolling buffer of {MAX_STREAM_BUFFER}).
            </p>
          </div>
        </div>

        <ZeekLiveConnectionTable
          events={events}
          isPaused={isPaused}
          onTogglePause={handleTogglePause}
          onClear={handleClear}
          maxBuffer={MAX_STREAM_BUFFER}
        />
      </div>
    </div>
  );
};
