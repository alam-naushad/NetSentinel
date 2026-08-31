import { apiClient } from './client';
import { ZeekIngestionStatus, ZeekLiveEvent, ZeekSSEConnectionState } from '../types/zeek';

export interface ZeekStreamCallbacks {
  onEvent: (event: ZeekLiveEvent) => void;
  onStatusChange: (state: ZeekSSEConnectionState) => void;
  onError?: (error: any) => void;
}

export class ZeekStreamClient {
  private eventSource: EventSource | null = null;
  private lastEventId: string | null = null;
  private callbacks: ZeekStreamCallbacks | null = null;
  private reconnectTimer: number | null = null;
  private isManuallyClosed = false;

  public connect(callbacks: ZeekStreamCallbacks): void {
    this.callbacks = callbacks;
    this.isManuallyClosed = false;
    this.initEventSource();
  }

  public disconnect(): void {
    this.isManuallyClosed = true;
    if (this.reconnectTimer) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.callbacks?.onStatusChange('DISCONNECTED');
  }

  private initEventSource(): void {
    if (this.eventSource) {
      this.eventSource.close();
    }

    this.callbacks?.onStatusChange('CONNECTING');

    const url = this.lastEventId
      ? `/api/v1/zeek/stream?last_event_id=${encodeURIComponent(this.lastEventId)}`
      : '/api/v1/zeek/stream';

    try {
      this.eventSource = new EventSource(url);

      this.eventSource.onopen = () => {
        this.callbacks?.onStatusChange('CONNECTED');
      };

      this.eventSource.addEventListener('connected', (e: MessageEvent) => {
        this.callbacks?.onStatusChange('CONNECTED');
      });

      this.eventSource.addEventListener('zeek_connection', (e: MessageEvent) => {
        try {
          const parsed = JSON.parse(e.data) as ZeekLiveEvent;
          if (e.lastEventId) {
            this.lastEventId = e.lastEventId;
          } else if (parsed.session_id && parsed.sequence_id !== undefined) {
            this.lastEventId = `${parsed.session_id}:${parsed.sequence_id}`;
          }
          this.callbacks?.onEvent(parsed);
        } catch (err) {
          console.error('Error parsing Zeek SSE event data:', err);
        }
      });

      this.eventSource.onerror = (e) => {
        if (this.isManuallyClosed) return;
        this.callbacks?.onStatusChange('RECONNECTING');
        this.callbacks?.onError?.(e);
      };
    } catch (err) {
      this.callbacks?.onStatusChange('DISCONNECTED');
      this.callbacks?.onError?.(err);
    }
  }
}

export const zeekStreamApi = {
  async getIngestionStatus(): Promise<ZeekIngestionStatus> {
    return apiClient<ZeekIngestionStatus>('/api/v1/zeek/ingestion/status');
  },
};
