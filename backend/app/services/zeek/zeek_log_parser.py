import json
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from app.services.zeek.zeek_connection_record import ZeekConnectionRecord

logger = logging.getLogger(__name__)

@dataclass
class ZeekParseResult:
    connections: List[ZeekConnectionRecord]
    total_lines_read: int
    malformed_count: int
    duplicate_count: int
    format_detected: str

class ZeekLogParser:
    @staticmethod
    def _parse_json_line(line: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(line)
            parsed = {}
            mapping = {
                "ts": "ts",
                "uid": "uid",
                "id.orig_h": "id_orig_h",
                "id.orig_p": "id_orig_p",
                "id.resp_h": "id_resp_h",
                "id.resp_p": "id_resp_p",
                "proto": "proto",
                "service": "service",
                "duration": "duration",
                "orig_bytes": "orig_bytes",
                "resp_bytes": "resp_bytes",
                "conn_state": "conn_state",
                "local_orig": "local_orig",
                "local_resp": "local_resp",
                "missed_bytes": "missed_bytes",
                "history": "history",
                "orig_pkts": "orig_pkts",
                "orig_ip_bytes": "orig_ip_bytes",
                "resp_pkts": "resp_pkts",
                "resp_ip_bytes": "resp_ip_bytes",
                "tunnel_parents": "tunnel_parents"
            }
            
            for k, v in mapping.items():
                val = data.get(k)
                if val is None and "." in k:
                    parts = k.split(".")
                    curr = data
                    for p in parts:
                        if isinstance(curr, dict) and p in curr:
                            curr = curr[p]
                        else:
                            curr = None
                            break
                    val = curr
                    
                if val == "-":
                    val = None
                    
                parsed[v] = val
                
            return parsed
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _parse_tsv_line(line: str, headers: List[str]) -> Optional[Dict[str, Any]]:
        parts = line.rstrip('\n').split('\t')
        if len(parts) != len(headers):
            return None
            
        mapping = {
            "ts": "ts",
            "uid": "uid",
            "id.orig_h": "id_orig_h",
            "id.orig_p": "id_orig_p",
            "id.resp_h": "id_resp_h",
            "id.resp_p": "id_resp_p",
            "proto": "proto",
            "service": "service",
            "duration": "duration",
            "orig_bytes": "orig_bytes",
            "resp_bytes": "resp_bytes",
            "conn_state": "conn_state",
            "local_orig": "local_orig",
            "local_resp": "local_resp",
            "missed_bytes": "missed_bytes",
            "history": "history",
            "orig_pkts": "orig_pkts",
            "orig_ip_bytes": "orig_ip_bytes",
            "resp_pkts": "resp_pkts",
            "resp_ip_bytes": "resp_ip_bytes",
            "tunnel_parents": "tunnel_parents"
        }
        
        parsed = {}
        for h, v in zip(headers, parts):
            if h in mapping:
                if v == '-' or v == '(empty)':
                    parsed[mapping[h]] = None
                else:
                    parsed[mapping[h]] = v
        return parsed

    @classmethod
    def parse_file(cls, file_content: bytes, max_connections: int = 100_000) -> ZeekParseResult:
        try:
            text_content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            text_content = file_content.decode('latin-1')

        lines = text_content.splitlines()
        
        if not lines:
            return ZeekParseResult([], 0, 0, 0, "unknown")
            
        format_detected = 'unknown'
        for line in lines:
            stripped = line.strip()
            if stripped:
                format_detected = 'tsv' if stripped.startswith('#') else 'json'
                break
                
        if format_detected == 'unknown':
            return ZeekParseResult([], 0, 0, 0, "unknown")
        
        connections = []
        total_lines_read = 0
        malformed_count = 0
        duplicate_count = 0
        
        seen_uids = set()
        headers = []
        
        for line in lines:
            if not line.strip():
                continue
                
            total_lines_read += 1
            
            if format_detected == 'tsv':
                if line.startswith('#'):
                    if line.startswith('#fields\t'):
                        headers = line.strip().split('\t')[1:]
                    continue
                
                if not headers:
                    malformed_count += 1
                    continue
                    
                parsed_dict = cls._parse_tsv_line(line, headers)
            else:
                parsed_dict = cls._parse_json_line(line)
                
            if not parsed_dict:
                malformed_count += 1
                continue
                
            uid = parsed_dict.get('uid')
            if not uid:
                malformed_count += 1
                continue
                
            if uid in seen_uids:
                duplicate_count += 1
                continue
                
            try:
                record = ZeekConnectionRecord(**parsed_dict)
                connections.append(record)
                seen_uids.add(uid)
            except Exception:
                malformed_count += 1
                
            if len(connections) >= max_connections:
                break
                
        return ZeekParseResult(
            connections=connections,
            total_lines_read=total_lines_read,
            malformed_count=malformed_count,
            duplicate_count=duplicate_count,
            format_detected=format_detected
        )
