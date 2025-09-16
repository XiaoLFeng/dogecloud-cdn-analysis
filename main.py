#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from datetime import datetime

from log_parser import LogParser
from ip_analyzer import IPAnalyzer
from suspicious_detector import SuspiciousDetector
from excel_exporter import ExcelExporter

def print_banner():
    print("=" * 70)
    print("🎮 CDN日志分析工具 - 此方为你分析可疑IP呀~ ")
    print("   帮助筱锋找出那些恶意刷流量的PCDN用户！✨")
    print("=" * 70)

def print_top_suspicious_ips(suspicious_ips, limit=20):
    if not suspicious_ips:
        print("嘿嘿~ 没有发现可疑IP呢！(´∀｀)")
        return

    print(f"\n🔍 Top {min(limit, len(suspicious_ips))} 可疑IP列表：")
    print("-" * 120)
    print(f"{'IP地址':<30} {'风险分':<8} {'请求数':<10} {'流量(MB)':<12} {'异常原因'}")
    print("-" * 120)

    for i, sip in enumerate(suspicious_ips[:limit], 1):
        traffic_mb = sip.stats.total_traffic / (1024 * 1024)
        reasons = ', '.join(sip.reasons[:2])
        if len(sip.reasons) > 2:
            reasons += f"... (+{len(sip.reasons)-2}项)"

        print(f"{sip.ip:<30} {sip.risk_score:<8.1f} {sip.stats.request_count:<10,} {traffic_mb:<12.1f} {reasons}")

def print_block_suggestions(suggestions):
    print("\n💡 封禁建议：")
    print("-" * 60)

    stats = suggestions.get('statistics', {})
    print(f"📊 总计可疑IP: {stats.get('total_suspicious', 0)} 个")
    print(f"🔴 高风险IP: {stats.get('high_risk', 0)} 个")
    print(f"🟡 中等风险IP: {stats.get('medium_risk', 0)} 个")

    immediate_block = suggestions.get('immediate_block', [])
    if immediate_block:
        print(f"\n🚫 建议立即封禁 ({len(immediate_block)} 个IP):")
        for ip in immediate_block[:10]:
            print(f"   {ip}")
        if len(immediate_block) > 10:
            print(f"   ... 还有 {len(immediate_block) - 10} 个")

    network_blocks = suggestions.get('network_blocks', {})
    if network_blocks:
        print(f"\n🌐 建议封禁网段 ({len(network_blocks)} 个):")
        for network, reason in list(network_blocks.items())[:5]:
            print(f"   {network} - {reason}")
        if len(network_blocks) > 5:
            print(f"   ... 还有 {len(network_blocks) - 5} 个网段")

def main():
    start_time = time.time()

    print_banner()

    # 检查logger目录
    logger_dir = "logger"
    if not os.path.exists(logger_dir):
        print(f"❌ 找不到日志目录 '{logger_dir}'")
        print("请确保在正确的目录下运行，并且logger目录存在！")
        sys.exit(1)

    try:
        # 1. 解析日志文件
        print("📂 开始解析日志文件...")
        parser = LogParser(logger_dir)
        analyzer = IPAnalyzer()

        entry_count = 0
        for entry in parser.parse_all_files():
            analyzer.add_entry(entry)
            entry_count += 1

        if entry_count == 0:
            print("❌ 没有找到有效的日志记录！")
            sys.exit(1)

        print(f"✅ 成功解析 {entry_count:,} 条日志记录")

        # 2. 生成统计信息
        print("\n📊 生成统计分析...")
        summary_stats = analyzer.get_stats_summary()
        time_patterns = analyzer.analyze_time_patterns()

        # 显示基本统计
        analyzer.print_summary()

        # 3. 检测可疑IP
        print("\n🔍 检测可疑IP...")
        detector = SuspiciousDetector()
        suspicious_ips = detector.analyze_suspicious_ips(analyzer.ip_stats, analyzer.network_stats)
        suspicious_networks = detector.analyze_suspicious_networks(analyzer.network_stats)
        block_suggestions = detector.generate_block_suggestions(suspicious_ips)

        print(f"发现 {len(suspicious_ips)} 个可疑IP，{len(suspicious_networks)} 个可疑网段")

        # 4. 显示结果
        print_top_suspicious_ips(suspicious_ips, 20)
        print_block_suggestions(block_suggestions)

        # 5. 导出Excel报表
        print(f"\n📋 生成详细报表...")
        exporter = ExcelExporter()
        excel_file = exporter.export_analysis_report(
            ip_stats=analyzer.ip_stats,
            network_stats=analyzer.network_stats,
            suspicious_ips=suspicious_ips,
            suspicious_networks=suspicious_networks,
            block_suggestions=block_suggestions,
            summary_stats=summary_stats,
            time_patterns=time_patterns
        )

        # 6. 完成
        elapsed_time = time.time() - start_time
        print("\n" + "=" * 70)
        print(f"🎉 分析完成！耗时 {elapsed_time:.1f} 秒")
        print(f"📄 详细报表已保存到: {excel_file}")
        print("嘿嘿~ 此方已经帮你找出所有可疑IP啦！＼(^o^)／")
        print("=" * 70)

        # 7. 显示使用建议
        if suspicious_ips:
            print("\n💡 使用建议：")
            print("1. 查看生成的Excel报表获取详细分析")
            print("2. 优先封禁高风险IP（风险分≥60）")
            print("3. 考虑封禁建议的网段以防止换IP重来")
            print("4. 监控中等风险IP的后续行为")

    except KeyboardInterrupt:
        print(f"\n用户中断操作 💦")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 分析过程中出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()