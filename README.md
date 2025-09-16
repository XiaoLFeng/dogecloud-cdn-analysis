# 🎮 CDN-Logger-Count

一个用于分析CDN日志、检测可疑IP活动的Python工具，主要用于识别恶意刷流量的PCDN用户和异常访问模式。

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)

## ✨ 特性

- 🔍 **智能检测** - 基于多维度统计阈值检测可疑IP行为
- 📊 **详细报表** - 生成包含6个工作表的Excel分析报告
- ⚡ **高性能** - 使用生成器模式处理大型日志文件，内存效率高
- 🎯 **精准分析** - 支持IP级别和网段级别的异常检测
- 📈 **统计分析** - 提供时间模式、流量分布、访问行为等多维度分析

## 🚀 快速开始

### 环境要求

- Python 3.7+
- pandas 2.1.4+
- openpyxl 3.1.2+

### 安装依赖

```bash
pip install -r requirements.txt
```

### 准备日志文件

将CDN日志文件（.gz格式）放入 `logger/` 目录：

```
logger/
├── 2025091010-frontleaves.com.gz
├── 2025091011-frontleaves.com.gz
└── ...
```

### 运行分析

```bash
python main.py
```

程序将自动：
1. 解析所有日志文件
2. 分析IP访问模式
3. 检测可疑行为
4. 生成详细的Excel报表

## 📋 输出报表

生成的Excel报表包含以下工作表：

| 工作表 | 描述 |
|--------|------|
| 📊 总结分析 | 整体统计信息和关键指标 |
| 🚫 建议封禁 | 高风险IP和网段列表（**核心输出**） |
| 📈 所有IP统计 | 完整的IP访问统计数据 |
| 🔍 可疑IP详情 | 详细的异常行为分析 |
| 🌐 网段分析 | 网络段级别的统计分析 |
| ⏰ 时间分布 | 访问时间模式分析 |

## 🔧 检测算法

### 量化指标
- **高请求率**: > 3,000次/小时
- **高总请求数**: > 10,000次
- **高流量**: > 1,000MB
- **峰值请求**: > 5,000次/小时

### 行为模式
- **路径多样性低**: < 0.1比例
- **可疑User-Agent**: 包含bot、spider、crawler等关键词
- **时间集中度高**: > 0.8阈值

### 统计方法
使用NumPy计算75%、90%、99%分位数作为动态阈值，自适应不同规模的数据集。

## 📁 项目结构

```
CDN-Logger-Count/
├── main.py              # 主程序入口
├── log_parser.py        # 日志解析器
├── ip_analyzer.py       # IP统计分析器
├── suspicious_detector.py  # 可疑活动检测器
├── excel_exporter.py    # Excel报表导出器
├── requirements.txt     # 项目依赖
├── logger/             # 日志文件目录（需要创建）
└── *.xlsx              # 生成的分析报表
```

## 🎯 使用场景

- **CDN运营商** - 识别滥用CDN资源的用户
- **网站管理员** - 检测异常流量和攻击行为
- **安全分析师** - 分析访问模式和威胁情报
- **运维工程师** - 监控和优化CDN性能

## 📖 详细文档

查看 [CLAUDE.md](./CLAUDE.md) 获取详细的开发文档和架构说明。

## 🤝 贡献

欢迎提交Issue和Pull Request！

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 📝 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 👨‍💻 作者

**筱锋 (xiao_lfeng)**

- 🌐 网站: [https://www.x-lf.com](https://www.x-lf.com)
- 📧 如有问题欢迎通过网站联系

---

⭐ 如果这个项目对你有帮助，请给个Star支持一下！