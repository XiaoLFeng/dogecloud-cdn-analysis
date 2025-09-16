# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概览

CDN-Logger-Count 是一个用于分析CDN日志、检测可疑IP活动的Python工具。主要用于识别恶意刷流量的PCDN用户和异常访问模式。

## 核心架构

项目采用模块化架构，包含以下核心组件：

- **main.py** - 主程序入口，协调各个模块工作
- **log_parser.py** - 日志解析器，处理gzip压缩的CDN日志文件
- **ip_analyzer.py** - IP统计分析器，收集和分析IP访问模式
- **suspicious_detector.py** - 可疑活动检测器，基于统计阈值检测异常IP
- **excel_exporter.py** - Excel报表导出器，生成详细的分析报告

### 数据流

1. LogParser 解析 `logger/` 目录中的 .gz 日志文件
2. IPAnalyzer 统计每个IP的访问模式（请求数、流量、时间分布等）
3. SuspiciousDetector 基于统计阈值分析可疑IP
4. ExcelExporter 生成包含6个工作表的详细分析报告

## 开发环境

### 依赖管理
```bash
# 安装依赖
pip install -r requirements.txt

# 核心依赖：
# - pandas==2.1.4 (数据处理)
# - openpyxl==3.1.2 (Excel导出)
# - ipaddress (IP地址处理，内置模块)
```

### 运行程序
```bash
# 运行完整分析
python main.py

# 确保logger目录存在且包含.gz日志文件
ls logger/  # 应该看到类似 2025091010-frontleaves.com.gz 的文件
```

## 数据结构

### LogEntry (log_parser.py)
CDN日志的单条记录，包含时间戳、IP地址、域名、路径、响应大小、状态码等14个字段。

### IPStats (ip_analyzer.py)
IP统计信息，跟踪单个IP的：
- 请求总数和流量
- 访问路径和User-Agent多样性
- 状态码分布和时间模式
- 首次/最后访问时间

### SuspiciousIP (suspicious_detector.py)
可疑IP对象，包含风险分数、异常原因和统计信息。

## 检测算法

SuspiciousDetector 使用多维度阈值检测：

### 量化指标
- 高请求率：>3000次/小时
- 高总请求数：>10000次
- 高流量：>1000MB
- 峰值请求：>5000次/小时

### 行为模式
- 路径多样性低：<0.1比例
- User-Agent模式可疑（包含bot、spider等关键词）
- 时间集中度高：>0.8阈值

### 统计方法
使用NumPy计算75%、90%、99%分位数作为动态阈值，适应不同规模的数据集。

## Excel报表结构

生成的报表包含6个工作表：
1. **总结分析** - 整体统计和关键指标
2. **建议封禁** - 高风险IP和网段列表（核心输出）
3. **所有IP统计** - 完整IP访问统计
4. **可疑IP详情** - 详细的异常分析
5. **网段分析** - 网络段级别的统计
6. **时间分布** - 访问时间模式分析

## 重要文件位置

- 日志文件：`logger/*.gz` (CDN原始日志)
- 输出报表：`cdn_analysis_report_YYYYMMDD_HHMMSS.xlsx`
- 配置：检测阈值硬编码在 `suspicious_detector.py:24-36`

## 代码特点

- 使用生成器模式处理大文件，内存效率高
- 正则表达式解析固定格式的CDN日志
- 基于统计学的异常检测方法
- 模块化设计，易于扩展和维护
- 丰富的中文输出和可爱的界面元素（此方风格）

## 常见问题

- 确保 `logger/` 目录存在且包含 .gz 日志文件
- 日志格式必须匹配 `log_parser.py:36-41` 中的正则表达式
- Excel文件可能较大，建议在SSD上运行以提升性能