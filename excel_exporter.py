#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple
import os

from ip_analyzer import IPStats, NetworkStats
from suspicious_detector import SuspiciousIP

class ExcelExporter:
    def __init__(self, output_file: str = None):
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"cdn_analysis_report_{timestamp}.xlsx"
        self.output_file = output_file

    def export_analysis_report(self, ip_stats: Dict[str, IPStats],
                             network_stats: Dict[str, NetworkStats],
                             suspicious_ips: List[SuspiciousIP],
                             suspicious_networks: List[Tuple],
                             block_suggestions: Dict,
                             summary_stats: Dict,
                             time_patterns: Dict):

        print(f"正在生成Excel报表... 📊")

        with pd.ExcelWriter(self.output_file, engine='openpyxl') as writer:
            # Sheet1: 总结分析
            self._create_summary_sheet(writer, summary_stats, time_patterns, block_suggestions, suspicious_ips)

            # Sheet2: 建议封禁IP以及网段
            self._create_block_suggestions_sheet(writer, block_suggestions, suspicious_ips)

            # Sheet3: 所有IP的次数统计
            self._create_all_ips_stats_sheet(writer, ip_stats)

            # Sheet4: 可疑IP详情（保留作为补充）
            self._create_suspicious_ips_sheet(writer, suspicious_ips)

            # Sheet5: 网段分析（保留作为补充）
            self._create_network_analysis_sheet(writer, network_stats, suspicious_networks)

            # Sheet6: 时间分布分析（保留作为补充）
            self._create_time_analysis_sheet(writer, time_patterns)

        print(f"✨ Excel报表已生成: {self.output_file}")
        return self.output_file

    def _create_summary_sheet(self, writer, summary_stats, time_patterns, block_suggestions, suspicious_ips):
        summary_data = {
            '统计项目': [
                '总计唯一IP数量',
                '总请求次数',
                '总流量(GB)',
                '总流量(MB)',
                '平均每IP请求数',
                '平均每IP流量(MB)',
                '可疑IP总数',
                '高风险IP数',
                '中等风险IP数',
                '建议立即封禁IP数',
                '建议密切监控IP数',
                '建议封禁网段数'
            ],
            '数值': [
                f"{summary_stats.get('total_unique_ips', 0):,}",
                f"{summary_stats.get('total_requests', 0):,}",
                f"{summary_stats.get('total_traffic_gb', 0):.2f}",
                f"{summary_stats.get('total_traffic_mb', 0):.1f}",
                f"{summary_stats.get('avg_requests_per_ip', 0):.1f}",
                f"{summary_stats.get('avg_traffic_per_ip', 0) / 1024 / 1024:.1f}",
                block_suggestions.get('statistics', {}).get('total_suspicious', 0),
                block_suggestions.get('statistics', {}).get('high_risk', 0),
                block_suggestions.get('statistics', {}).get('medium_risk', 0),
                len(block_suggestions.get('immediate_block', [])),
                len(block_suggestions.get('monitor_closely', [])),
                len(block_suggestions.get('network_blocks', {}))
            ]
        }

        df = pd.DataFrame(summary_data)
        df.to_excel(writer, sheet_name='Sheet1-总结分析', index=False)

    def _create_all_ips_stats_sheet(self, writer, ip_stats):
        all_ips_data = []
        for i, (ip, stats) in enumerate(sorted(ip_stats.items(), key=lambda x: x[1].request_count, reverse=True), 1):
            all_ips_data.append({
                '排名': i,
                'IP地址': ip,
                '请求总数': stats.request_count,
                '总流量(MB)': f"{stats.total_traffic / 1024 / 1024:.1f}",
                '总流量(GB)': f"{stats.total_traffic / 1024 / 1024 / 1024:.3f}",
                '平均请求/小时': f"{stats.get_requests_per_hour():.1f}",
                '峰值请求/小时': stats.get_peak_hourly_requests(),
                '活跃小时数': stats.get_active_hours(),
                '唯一路径数': len(stats.unique_paths),
                '唯一UA数': len(stats.user_agents),
                '访问域名数': len(stats.domains),
                '首次访问': stats.first_seen.strftime('%Y-%m-%d %H:%M:%S') if stats.first_seen else '',
                '最后访问': stats.last_seen.strftime('%Y-%m-%d %H:%M:%S') if stats.last_seen else '',
                '主要状态码': str(stats.status_codes.most_common(1)[0] if stats.status_codes else 'N/A'),
                '平均流量/请求(KB)': f"{stats.total_traffic / max(stats.request_count, 1) / 1024:.1f}"
            })

        df = pd.DataFrame(all_ips_data)
        df.to_excel(writer, sheet_name='Sheet3-所有IP统计', index=False)

        # 设置列宽
        worksheet = writer.sheets['Sheet3-所有IP统计']
        worksheet.column_dimensions['B'].width = 25  # IP地址

    def _create_suspicious_ips_sheet(self, writer, suspicious_ips):
        if not suspicious_ips:
            return

        data = []
        for sip in suspicious_ips:
            stats = sip.stats
            data.append({
                'IP地址': sip.ip,
                '风险评分': f"{sip.risk_score:.1f}",
                '风险等级': '高风险' if sip.risk_score >= 60 else '中等风险',
                '异常原因': ' | '.join(sip.reasons),
                '请求总数': stats.request_count,
                '流量(MB)': f"{stats.total_traffic / 1024 / 1024:.1f}",
                '平均请求/小时': f"{stats.get_requests_per_hour():.1f}",
                '峰值请求/小时': stats.get_peak_hourly_requests(),
                '活跃小时数': stats.get_active_hours(),
                '唯一路径数': len(stats.unique_paths),
                '唯一UA数': len(stats.user_agents),
                '访问域名数': len(stats.domains),
                '首次访问': stats.first_seen.strftime('%Y-%m-%d %H:%M:%S') if stats.first_seen else '',
                '最后访问': stats.last_seen.strftime('%Y-%m-%d %H:%M:%S') if stats.last_seen else '',
                '主要状态码': str(stats.status_codes.most_common(1)[0] if stats.status_codes else 'N/A')
            })

        df = pd.DataFrame(data)
        df.to_excel(writer, sheet_name='Sheet4-可疑IP详情', index=False)

        # 设置列宽
        worksheet = writer.sheets['Sheet4-可疑IP详情']
        worksheet.column_dimensions['A'].width = 25  # IP地址
        worksheet.column_dimensions['D'].width = 50  # 异常原因

    def _create_top_ips_sheet(self, writer, ip_stats):
        top_requests = sorted(ip_stats.items(), key=lambda x: x[1].request_count, reverse=True)[:100]
        top_traffic = sorted(ip_stats.items(), key=lambda x: x[1].total_traffic, reverse=True)[:100]

        # Top请求数IP
        requests_data = []
        for i, (ip, stats) in enumerate(top_requests, 1):
            requests_data.append({
                '排名': i,
                'IP地址': ip,
                '请求总数': stats.request_count,
                '流量(MB)': f"{stats.total_traffic / 1024 / 1024:.1f}",
                '平均请求/小时': f"{stats.get_requests_per_hour():.1f}",
                '唯一路径数': len(stats.unique_paths),
                '活跃小时数': stats.get_active_hours()
            })

        df_requests = pd.DataFrame(requests_data)
        df_requests.to_excel(writer, sheet_name='Top请求数IP', index=False)

        # Top流量IP
        traffic_data = []
        for i, (ip, stats) in enumerate(top_traffic, 1):
            traffic_data.append({
                '排名': i,
                'IP地址': ip,
                '流量(MB)': f"{stats.total_traffic / 1024 / 1024:.1f}",
                '流量(GB)': f"{stats.total_traffic / 1024 / 1024 / 1024:.2f}",
                '请求总数': stats.request_count,
                '平均流量/请求(KB)': f"{stats.total_traffic / max(stats.request_count, 1) / 1024:.1f}",
                '活跃小时数': stats.get_active_hours()
            })

        df_traffic = pd.DataFrame(traffic_data)
        df_traffic.to_excel(writer, sheet_name='Top流量IP', index=False)

    def _create_network_analysis_sheet(self, writer, network_stats, suspicious_networks):
        # 所有网段统计
        network_data = []
        for net_key, net_stats in sorted(network_stats.items(),
                                       key=lambda x: (x[1].ip_count, x[1].total_requests),
                                       reverse=True)[:200]:
            network_type = net_key.split('_')[0]
            network_addr = net_key.split('_', 1)[1]

            network_data.append({
                '网段类型': network_type,
                '网段地址': network_addr,
                'IP数量': net_stats.ip_count,
                '总请求数': net_stats.total_requests,
                '总流量(MB)': f"{net_stats.total_traffic / 1024 / 1024:.1f}",
                '平均请求/IP': f"{net_stats.total_requests / max(net_stats.ip_count, 1):.1f}",
                '平均流量/IP(MB)': f"{net_stats.total_traffic / max(net_stats.ip_count, 1) / 1024 / 1024:.1f}"
            })

        df_networks = pd.DataFrame(network_data)
        df_networks.to_excel(writer, sheet_name='Sheet5-网段分析', index=False)

        # 可疑网段
        if suspicious_networks:
            suspicious_data = []
            for net_key, net_stats, risk_score, reasons in suspicious_networks:
                network_type = net_key.split('_')[0]
                network_addr = net_key.split('_', 1)[1]

                suspicious_data.append({
                    '网段类型': network_type,
                    '网段地址': network_addr,
                    '风险评分': f"{risk_score:.1f}",
                    '异常原因': ' | '.join(reasons),
                    'IP数量': net_stats.ip_count,
                    '总请求数': net_stats.total_requests,
                    '总流量(MB)': f"{net_stats.total_traffic / 1024 / 1024:.1f}",
                    '平均请求/IP': f"{net_stats.total_requests / max(net_stats.ip_count, 1):.1f}"
                })

            df_suspicious_networks = pd.DataFrame(suspicious_data)
            df_suspicious_networks.to_excel(writer, sheet_name='可疑网段', index=False)

    def _create_block_suggestions_sheet(self, writer, block_suggestions, suspicious_ips):
        import ipaddress

        # 创建一个综合的封禁建议工作表
        all_suggestions = []

        # 获取建议封禁的网段
        network_blocks = block_suggestions.get('network_blocks', {})

        # 创建网段到IP的映射，找出哪些IP属于建议封禁的网段
        network_covered_ips = set()
        network_ip_details = {}

        for network in network_blocks.keys():
            try:
                network_obj = ipaddress.ip_network(network)
                network_ip_details[network] = []

                # 检查哪些可疑IP属于这个网段
                for sip in suspicious_ips:
                    try:
                        ip_obj = ipaddress.ip_address(sip.ip)
                        if ip_obj in network_obj:
                            network_covered_ips.add(sip.ip)
                            network_ip_details[network].append({
                                'ip': sip.ip,
                                'risk_score': sip.risk_score,
                                'reasons': sip.reasons
                            })
                    except ValueError:
                        continue
            except ValueError:
                continue

        # 先添加网段封禁建议（优先显示）
        for network, reason in network_blocks.items():
            # 构建网段详细原因
            detailed_reason = f"{reason}。"
            if network in network_ip_details and network_ip_details[network]:
                ip_examples = network_ip_details[network][:3]  # 显示前3个IP作为例子
                detailed_reason += f" 包含高风险IP例如: "
                examples = []
                for ip_info in ip_examples:
                    examples.append(f"{ip_info['ip']}(风险分{ip_info['risk_score']:.0f})")
                detailed_reason += ", ".join(examples)

                if len(network_ip_details[network]) > 3:
                    detailed_reason += f" 等共{len(network_ip_details[network])}个问题IP"

            all_suggestions.append({
                '类型': '网段',
                '地址/网段': network,
                '建议操作': '封禁整个网段',
                '风险级别': '高',
                '风险评分': '',
                '原因': detailed_reason
            })

        # 添加不在网段内的单独IP封禁建议
        for ip in block_suggestions.get('immediate_block', []):
            if ip not in network_covered_ips:  # 只添加不在建议网段内的IP
                # 找到对应的可疑IP信息
                sip_info = next((sip for sip in suspicious_ips if sip.ip == ip), None)
                risk_score = sip_info.risk_score if sip_info else 0
                reasons = ', '.join(sip_info.reasons) if sip_info else ''

                all_suggestions.append({
                    '类型': '单IP',
                    '地址/网段': ip,
                    '建议操作': '立即封禁',
                    '风险级别': '高',
                    '风险评分': f"{risk_score:.1f}",
                    '原因': f"单独恶意IP。{reasons}"
                })

        # 添加监控建议IP（不在网段内的）
        for ip in block_suggestions.get('monitor_closely', []):
            if ip not in network_covered_ips:  # 只添加不在建议网段内的IP
                sip_info = next((sip for sip in suspicious_ips if sip.ip == ip), None)
                risk_score = sip_info.risk_score if sip_info else 0
                reasons = ', '.join(sip_info.reasons) if sip_info else ''

                all_suggestions.append({
                    '类型': '单IP',
                    '地址/网段': ip,
                    '建议操作': '密切监控',
                    '风险级别': '中等',
                    '风险评分': f"{risk_score:.1f}",
                    '原因': f"可疑行为待观察。{reasons}"
                })

        if all_suggestions:
            df = pd.DataFrame(all_suggestions)
            df.to_excel(writer, sheet_name='Sheet2-建议封禁IP及网段', index=False)

            # 设置列宽
            worksheet = writer.sheets['Sheet2-建议封禁IP及网段']
            worksheet.column_dimensions['B'].width = 30  # 地址/网段
            worksheet.column_dimensions['F'].width = 60  # 原因

    def _create_time_analysis_sheet(self, writer, time_patterns):
        # 小时分布
        if time_patterns.get('hourly_distribution'):
            hourly_data = [{'小时': hour, '请求数': count}
                         for hour, count in sorted(time_patterns['hourly_distribution'].items())]
            df_hourly = pd.DataFrame(hourly_data)
            df_hourly.to_excel(writer, sheet_name='Sheet6-时间分布', index=False)

        # 在同一个工作表中添加日期分布（作为第二个表格）
        if time_patterns.get('daily_distribution'):
            # 由于openpyxl限制，这里我们将日期分布数据追加到小时分布的下方
            daily_data = [{'日期': date, '请求数': count}
                        for date, count in sorted(time_patterns['daily_distribution'].items())]

            # 如果没有小时分布，则直接创建日期分布
            if not time_patterns.get('hourly_distribution'):
                df_daily = pd.DataFrame(daily_data)
                df_daily.to_excel(writer, sheet_name='Sheet6-时间分布', index=False)