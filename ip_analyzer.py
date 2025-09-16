#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass, field

from log_parser import LogEntry

@dataclass
class IPStats:
    ip: str
    request_count: int = 0
    total_traffic: int = 0
    unique_paths: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    status_codes: Counter = field(default_factory=Counter)
    hourly_requests: Counter = field(default_factory=Counter)
    first_seen: datetime = None
    last_seen: datetime = None
    domains: Set[str] = field(default_factory=set)

    def add_request(self, entry: LogEntry):
        self.request_count += 1
        self.total_traffic += entry.traffic_bytes
        self.unique_paths.add(entry.path)
        self.user_agents.add(entry.user_agent)
        self.status_codes[entry.status_code] += 1
        self.domains.add(entry.domain)

        request_time = entry.get_datetime()
        hour_key = request_time.strftime('%Y%m%d%H')
        self.hourly_requests[hour_key] += 1

        if self.first_seen is None or request_time < self.first_seen:
            self.first_seen = request_time
        if self.last_seen is None or request_time > self.last_seen:
            self.last_seen = request_time

    def get_requests_per_hour(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0

        duration = self.last_seen - self.first_seen
        hours = max(1, duration.total_seconds() / 3600)
        return self.request_count / hours

    def get_peak_hourly_requests(self) -> int:
        return max(self.hourly_requests.values()) if self.hourly_requests else 0

    def get_active_hours(self) -> int:
        return len(self.hourly_requests)

@dataclass
class NetworkStats:
    network: str
    ip_count: int = 0
    total_requests: int = 0
    total_traffic: int = 0
    unique_ips: Set[str] = field(default_factory=set)

class IPAnalyzer:
    def __init__(self):
        self.ip_stats: Dict[str, IPStats] = {}
        self.network_stats: Dict[str, NetworkStats] = defaultdict(NetworkStats)
        self.total_entries = 0

    def add_entry(self, entry: LogEntry):
        self.total_entries += 1

        if entry.ip_address not in self.ip_stats:
            self.ip_stats[entry.ip_address] = IPStats(ip=entry.ip_address)

        self.ip_stats[entry.ip_address].add_request(entry)
        self._update_network_stats(entry)

    def _update_network_stats(self, entry: LogEntry):
        try:
            ip = ipaddress.ip_address(entry.ip_address)

            if ip.version == 6:
                network_64 = ipaddress.IPv6Network(f"{ip}/{64}", strict=False)
                network_48 = ipaddress.IPv6Network(f"{ip}/{48}", strict=False)

                for prefix, network in [("IPv6/64", network_64), ("IPv6/48", network_48)]:
                    net_key = f"{prefix}_{str(network)}"
                    if net_key not in self.network_stats:
                        self.network_stats[net_key] = NetworkStats(network=str(network))

                    self.network_stats[net_key].unique_ips.add(entry.ip_address)
                    self.network_stats[net_key].ip_count = len(self.network_stats[net_key].unique_ips)
                    self.network_stats[net_key].total_requests += 1
                    self.network_stats[net_key].total_traffic += entry.traffic_bytes
            else:
                network_24 = ipaddress.IPv4Network(f"{ip}/{24}", strict=False)
                network_16 = ipaddress.IPv4Network(f"{ip}/{16}", strict=False)

                for prefix, network in [("IPv4/24", network_24), ("IPv4/16", network_16)]:
                    net_key = f"{prefix}_{str(network)}"
                    if net_key not in self.network_stats:
                        self.network_stats[net_key] = NetworkStats(network=str(network))

                    self.network_stats[net_key].unique_ips.add(entry.ip_address)
                    self.network_stats[net_key].ip_count = len(self.network_stats[net_key].unique_ips)
                    self.network_stats[net_key].total_requests += 1
                    self.network_stats[net_key].total_traffic += entry.traffic_bytes

        except ValueError:
            pass

    def get_top_ips_by_requests(self, limit: int = 50) -> List[Tuple[str, IPStats]]:
        return sorted(
            self.ip_stats.items(),
            key=lambda x: x[1].request_count,
            reverse=True
        )[:limit]

    def get_top_ips_by_traffic(self, limit: int = 50) -> List[Tuple[str, IPStats]]:
        return sorted(
            self.ip_stats.items(),
            key=lambda x: x[1].total_traffic,
            reverse=True
        )[:limit]

    def get_top_networks(self, limit: int = 20) -> List[Tuple[str, NetworkStats]]:
        return sorted(
            self.network_stats.items(),
            key=lambda x: (x[1].ip_count, x[1].total_requests),
            reverse=True
        )[:limit]

    def get_stats_summary(self) -> Dict:
        if not self.ip_stats:
            return {}

        total_requests = sum(stats.request_count for stats in self.ip_stats.values())
        total_traffic = sum(stats.total_traffic for stats in self.ip_stats.values())

        return {
            'total_unique_ips': len(self.ip_stats),
            'total_requests': total_requests,
            'total_traffic_bytes': total_traffic,
            'total_traffic_mb': total_traffic / (1024 * 1024),
            'total_traffic_gb': total_traffic / (1024 * 1024 * 1024),
            'avg_requests_per_ip': total_requests / len(self.ip_stats),
            'avg_traffic_per_ip': total_traffic / len(self.ip_stats)
        }

    def analyze_time_patterns(self) -> Dict:
        hour_distribution = Counter()
        day_distribution = Counter()

        for stats in self.ip_stats.values():
            for hour_key in stats.hourly_requests.keys():
                dt = datetime.strptime(hour_key, '%Y%m%d%H')
                hour_distribution[dt.hour] += stats.hourly_requests[hour_key]
                day_distribution[dt.strftime('%Y%m%d')] += stats.hourly_requests[hour_key]

        return {
            'hourly_distribution': dict(hour_distribution),
            'daily_distribution': dict(day_distribution)
        }

    def print_summary(self):
        summary = self.get_stats_summary()
        print("=" * 60)
        print("🎮 CDN 日志分析汇总 - 此方统计中... ")
        print("=" * 60)
        print(f"📊 总计唯一IP数量: {summary.get('total_unique_ips', 0):,}")
        print(f"📈 总请求次数: {summary.get('total_requests', 0):,}")
        print(f"💾 总流量: {summary.get('total_traffic_gb', 0):.2f} GB ({summary.get('total_traffic_mb', 0):.1f} MB)")
        print(f"📊 平均每IP请求数: {summary.get('avg_requests_per_ip', 0):.1f}")
        print(f"💾 平均每IP流量: {summary.get('avg_traffic_per_ip', 0) / 1024 / 1024:.1f} MB")
        print("=" * 60)