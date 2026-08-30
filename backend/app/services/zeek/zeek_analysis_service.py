import time
import uuid
from typing import List, Optional
from collections import defaultdict
from pydantic import BaseModel, ConfigDict

from app.core.config import settings
from app.services.zeek.zeek_connection_record import ZeekConnectionRecord
from app.services.zeek.zeek_log_parser import ZeekLogParser, ZeekParseResult
from app.schemas.zeek import (
    ZeekConnectionSummary,
    ZeekAnalysisSummary,
)


class ZeekAnalysisResult(BaseModel):
    """Result of analyzing a Zeek log file."""
    model_config = ConfigDict(extra="ignore")

    summary: ZeekAnalysisSummary
    connections: List[ZeekConnectionSummary]
    raw_records: List[ZeekConnectionRecord]
    parse_result: ZeekParseResult
    file_sha256: Optional[str]
    file_size_bytes: int
    filename: str


class ZeekAnalysisService:
    """Service for parsing Zeek logs and preparing them for telemetry persistence."""

    def analyze(
        self,
        file_content: bytes,
        filename: str,
        file_size_bytes: int,
        file_sha256: Optional[str] = None
    ) -> ZeekAnalysisResult:
        """Parse Zeek log content and compute telemetry summaries."""
        start_time = time.time()

        # 1. Call ZeekLogParser
        parser = ZeekLogParser()
        parse_result = parser.parse_file(file_content, max_connections=settings.ZEEK_MAX_CONNECTIONS)
        
        # 3. Compute distributions
        protocol_distribution = defaultdict(int)
        service_distribution = defaultdict(int)
        conn_state_distribution = defaultdict(int)

        connections: List[ZeekConnectionSummary] = []
        raw_records: List[ZeekConnectionRecord] = parse_result.connections

        for rec in raw_records:
            protocol_distribution[rec.proto.lower()] += 1
            service_distribution[rec.service or "-"] += 1
            conn_state_distribution[rec.conn_state or "-"] += 1

            # 4. Map to ZeekConnectionSummary
            connections.append(
                ZeekConnectionSummary(
                    zeek_uid=rec.uid,
                    src_ip=rec.id_orig_h,
                    dst_ip=rec.id_resp_h,
                    src_port=rec.id_orig_p,
                    dst_port=rec.id_resp_p,
                    proto=rec.proto,
                    service=rec.service,
                    duration_sec=rec.duration,
                    orig_bytes=rec.orig_bytes,
                    resp_bytes=rec.resp_bytes,
                    conn_state=rec.conn_state,
                    history=rec.history,
                    orig_pkts=rec.orig_pkts,
                    resp_pkts=rec.resp_pkts,
                    missed_bytes=rec.missed_bytes,
                )
            )

        # 2. Measure parsing and preparation time in ms
        end_time = time.time()
        processing_time_ms = round((end_time - start_time) * 1000.0, 3)

        # 5. Build ZeekAnalysisSummary
        summary = ZeekAnalysisSummary(
            filename=filename,
            file_size_bytes=file_size_bytes,
            total_connections_parsed=len(connections),
            total_connections_persisted=len(connections),
            connections_skipped_malformed=parse_result.malformed_count,
            connections_skipped_duplicate=parse_result.duplicate_count,
            protocol_distribution=dict(protocol_distribution),
            service_distribution=dict(service_distribution),
            conn_state_distribution=dict(conn_state_distribution),
            processing_time_ms=processing_time_ms,
            ml_classification_performed=False,
            analysis_type="TELEMETRY_ONLY"
        )

        # 6. Return ZeekAnalysisResult
        return ZeekAnalysisResult(
            summary=summary,
            connections=connections,
            raw_records=raw_records,
            parse_result=parse_result,
            file_sha256=file_sha256,
            file_size_bytes=file_size_bytes,
            filename=filename
        )
