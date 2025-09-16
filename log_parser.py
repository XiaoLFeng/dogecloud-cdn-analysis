#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gzip
import re
import os
from datetime import datetime
from typing import Dict, List, Generator, Optional
from dataclasses import dataclass

@dataclass
class LogEntry:
    timestamp: str
    ip_address: str
    domain: str
    path: str
    response_size: int
    processing_time: int
    unknown1: int
    status_code: int
    referer: str
    unknown2: int
    user_agent: str
    unknown3: str
    method: str
    protocol: str
    cache_status: str
    traffic_bytes: int

    def get_datetime(self) -> datetime:
        return datetime.strptime(self.timestamp, '%Y%m%d%H%M%S')

class LogParser:
    def __init__(self, logger_dir: str = "logger"):
        self.logger_dir = logger_dir
        self.log_pattern = re.compile(
            r'^(\d{14})\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+'
            r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([^\s]+)\s+'
            r'(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+([^\s]+)\s+'
            r'([^\s]+)\s+([^\s]+)\s+(\d+)$'
        )

    def find_log_files(self) -> List[str]:
        log_files = []
        if not os.path.exists(self.logger_dir):
            print(f"呀~ 找不到目录 {self.logger_dir} 呢！(´∀｀)")
            return log_files

        for filename in os.listdir(self.logger_dir):
            if filename.endswith('.gz'):
                log_files.append(os.path.join(self.logger_dir, filename))

        print(f"找到了 {len(log_files)} 个日志文件呀！✨")
        return sorted(log_files)

    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        match = self.log_pattern.match(line)
        if not match:
            return None

        try:
            return LogEntry(
                timestamp=match.group(1),
                ip_address=match.group(2),
                domain=match.group(3),
                path=match.group(4),
                response_size=int(match.group(5)),
                processing_time=int(match.group(6)),
                unknown1=int(match.group(7)),
                status_code=int(match.group(8)),
                referer=match.group(9),
                unknown2=int(match.group(10)),
                user_agent=match.group(11),
                unknown3=match.group(12),
                method=match.group(13),
                protocol=match.group(14),
                cache_status=match.group(15),
                traffic_bytes=int(match.group(16))
            )
        except (ValueError, IndexError) as e:
            return None

    def parse_file(self, file_path: str) -> Generator[LogEntry, None, None]:
        try:
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                line_count = 0
                parsed_count = 0

                for line in f:
                    line_count += 1
                    entry = self.parse_log_line(line)
                    if entry:
                        parsed_count += 1
                        yield entry

                print(f"📁 {os.path.basename(file_path)}: {parsed_count}/{line_count} 条记录解析成功")

        except Exception as e:
            print(f"解析文件 {file_path} 时出错啦！💦 错误: {e}")

    def parse_all_files(self) -> Generator[LogEntry, None, None]:
        log_files = self.find_log_files()
        total_entries = 0

        for file_path in log_files:
            for entry in self.parse_file(file_path):
                total_entries += 1
                yield entry

                if total_entries % 10000 == 0:
                    print(f"已处理 {total_entries} 条记录... 🎮")

        print(f"总共处理了 {total_entries} 条日志记录！嘿嘿~ ＼(^o^)／")