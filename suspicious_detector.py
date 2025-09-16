#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from collections import Counter
import statistics
import numpy as np

from ip_analyzer import IPStats, NetworkStats

@dataclass
class SuspiciousIP:
    ip: str
    risk_score: float
    reasons: List[str]
    stats: IPStats

    def __str__(self):
        return f"{self.ip} (风险分: {self.risk_score:.1f}) - {', '.join(self.reasons)}"

class SuspiciousDetector:
    def __init__(self):
        self.thresholds = {
            'high_request_rate_per_hour': 3000,
            'high_total_requests': 10000,
            'high_traffic_mb': 1000,
            'high_peak_hourly_requests': 5000,
            'low_unique_paths_ratio': 0.1,
            'high_user_agent_diversity': 20,
            'suspicious_user_agent_patterns': [
                'python', 'curl', 'wget', 'bot', 'spider', 'crawler',
                'scraper', 'scanner', 'test', 'monitor'
            ],
            'concentrated_time_pattern_threshold': 0.8
        }

    def analyze_suspicious_ips(self, ip_stats: Dict[str, IPStats],
                             network_stats: Dict[str, NetworkStats]) -> List[SuspiciousIP]:
        suspicious_ips = []

        request_counts = [stats.request_count for stats in ip_stats.values()]
        traffic_amounts = [stats.total_traffic for stats in ip_stats.values()]

        if request_counts:
            requests_q75 = np.percentile(request_counts, 75)
            requests_q90 = np.percentile(request_counts, 90)
            requests_q99 = np.percentile(request_counts, 99)

            traffic_q75 = np.percentile(traffic_amounts, 75)
            traffic_q90 = np.percentile(traffic_amounts, 90)
            traffic_q99 = np.percentile(traffic_amounts, 99)

        for ip, stats in ip_stats.items():
            risk_score = 0.0
            reasons = []

            # 高频请求检测
            if stats.request_count > self.thresholds['high_total_requests']:
                risk_score += 30
                reasons.append(f"高频请求({stats.request_count:,}次)")

            # 超高频请求检测（99百分位）
            if request_counts and stats.request_count > requests_q99:
                risk_score += 40
                reasons.append(f"超高频请求(>Q99: {requests_q99:,.0f})")

            # 每小时请求频率检测
            requests_per_hour = stats.get_requests_per_hour()
            if requests_per_hour > self.thresholds['high_request_rate_per_hour']:
                risk_score += 25
                reasons.append(f"高时频({requests_per_hour:.0f}/小时)")

            # 单小时峰值检测
            peak_hourly = stats.get_peak_hourly_requests()
            if peak_hourly > self.thresholds['high_peak_hourly_requests']:
                risk_score += 35
                reasons.append(f"峰值过高({peak_hourly:,}/小时)")

            # 高流量检测
            traffic_mb = stats.total_traffic / (1024 * 1024)
            if traffic_mb > self.thresholds['high_traffic_mb']:
                risk_score += 20
                reasons.append(f"高流量({traffic_mb:.1f}MB)")

            # 超高流量检测（99百分位）
            if traffic_amounts and stats.total_traffic > traffic_q99:
                risk_score += 35
                reasons.append(f"超高流量(>Q99: {traffic_q99 / 1024 / 1024:.1f}MB)")

            # 路径多样性检测
            if stats.request_count > 100:
                path_diversity = len(stats.unique_paths) / stats.request_count
                if path_diversity < self.thresholds['low_unique_paths_ratio']:
                    risk_score += 15
                    reasons.append(f"路径单一({path_diversity:.3f})")

            # User-Agent 异常检测
            suspicious_ua_count = sum(1 for ua in stats.user_agents
                                    if any(pattern in ua.lower()
                                          for pattern in self.thresholds['suspicious_user_agent_patterns']))
            if suspicious_ua_count > 0:
                risk_score += 10 + suspicious_ua_count * 5
                reasons.append(f"可疑UA({suspicious_ua_count}个)")

            # 时间集中度检测
            if len(stats.hourly_requests) > 1:
                total_requests = sum(stats.hourly_requests.values())
                max_hour_requests = max(stats.hourly_requests.values())
                concentration = max_hour_requests / total_requests

                if concentration > self.thresholds['concentrated_time_pattern_threshold']:
                    risk_score += 20
                    reasons.append(f"时间集中({concentration:.1%})")

            # 活跃时间异常检测
            active_hours = stats.get_active_hours()
            if stats.request_count > 1000 and active_hours <= 2:
                risk_score += 25
                reasons.append(f"时间窗口短({active_hours}小时)")

            # 状态码异常检测
            error_rate = (stats.status_codes.get(404, 0) +
                         stats.status_codes.get(403, 0) +
                         stats.status_codes.get(500, 0)) / max(stats.request_count, 1)

            if error_rate > 0.5:
                risk_score += 15
                reasons.append(f"高错误率({error_rate:.1%})")

            # 判定为可疑IP
            if risk_score >= 30 or len(reasons) >= 3:
                suspicious_ips.append(
                    SuspiciousIP(
                        ip=ip,
                        risk_score=risk_score,
                        reasons=reasons,
                        stats=stats
                    )
                )

        return sorted(suspicious_ips, key=lambda x: x.risk_score, reverse=True)

    def analyze_suspicious_networks(self, network_stats: Dict[str, NetworkStats]) -> List[Tuple[str, NetworkStats, float, List[str]]]:
        suspicious_networks = []

        for net_key, net_stats in network_stats.items():
            risk_score = 0.0
            reasons = []

            # 网段IP数量异常检测
            if net_stats.ip_count >= 50:
                risk_score += 40
                reasons.append(f"大量IP({net_stats.ip_count}个)")
            elif net_stats.ip_count >= 20:
                risk_score += 20
                reasons.append(f"较多IP({net_stats.ip_count}个)")

            # 网段请求频率检测
            avg_requests_per_ip = net_stats.total_requests / max(net_stats.ip_count, 1)
            if avg_requests_per_ip > 5000:
                risk_score += 30
                reasons.append(f"高平均请求({avg_requests_per_ip:.0f}/IP)")

            # 网段总流量检测
            total_traffic_gb = net_stats.total_traffic / (1024 * 1024 * 1024)
            if total_traffic_gb > 10:
                risk_score += 25
                reasons.append(f"高流量({total_traffic_gb:.1f}GB)")

            # 网段活跃度检测（IP数量 vs 总请求的比例）
            if net_stats.ip_count > 10 and net_stats.total_requests / net_stats.ip_count > 10000:
                risk_score += 20
                reasons.append("高度协同")

            if risk_score >= 25:
                suspicious_networks.append((net_key, net_stats, risk_score, reasons))

        return sorted(suspicious_networks, key=lambda x: x[2], reverse=True)

    def generate_block_suggestions(self, suspicious_ips: List[SuspiciousIP]) -> Dict:
        high_risk_ips = [sip for sip in suspicious_ips if sip.risk_score >= 60]
        medium_risk_ips = [sip for sip in suspicious_ips if 30 <= sip.risk_score < 60]

        # 按网段分组高风险IP
        ipv6_networks = {}
        ipv4_networks = {}

        for sip in high_risk_ips:
            try:
                import ipaddress
                ip = ipaddress.ip_address(sip.ip)
                if ip.version == 6:
                    network_64 = str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
                    if network_64 not in ipv6_networks:
                        ipv6_networks[network_64] = []
                    ipv6_networks[network_64].append(sip.ip)
                else:
                    network_24 = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                    if network_24 not in ipv4_networks:
                        ipv4_networks[network_24] = []
                    ipv4_networks[network_24].append(sip.ip)
            except ValueError:
                continue

        suggestions = {
            'immediate_block': [sip.ip for sip in high_risk_ips[:20]],
            'monitor_closely': [sip.ip for sip in medium_risk_ips[:30]],
            'network_blocks': {},
            'statistics': {
                'total_suspicious': len(suspicious_ips),
                'high_risk': len(high_risk_ips),
                'medium_risk': len(medium_risk_ips),
                'suggested_ipv6_networks': len([net for net, ips in ipv6_networks.items() if len(ips) >= 5]),
                'suggested_ipv4_networks': len([net for net, ips in ipv4_networks.items() if len(ips) >= 3])
            }
        }

        # 建议封禁整个网段
        for network, ips in ipv6_networks.items():
            if len(ips) >= 5:
                suggestions['network_blocks'][network] = f"包含{len(ips)}个高风险IP"

        for network, ips in ipv4_networks.items():
            if len(ips) >= 3:
                suggestions['network_blocks'][network] = f"包含{len(ips)}个高风险IP"

        return suggestions