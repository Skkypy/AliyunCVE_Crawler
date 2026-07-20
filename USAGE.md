# 使用文档

## 目录
- [快速开始](#快速开始)
- [基本用法](#基本用法)
- [高级配置](#高级配置)
- [API参考](#api参考)
- [示例代码](#示例代码)
- [最佳实践](#最佳实践)

## 快速开始

### 1. 环境准备

确保您的系统满足以下要求：
- Python 3.8 或更高版本
- 至少 2GB 可用内存
- 稳定的网络连接

### 2. 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/vistaminc/aliyun-cve-crawler.git
cd aliyun-cve-crawler

# 2. 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate     # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 安装浏览器驱动
playwright install chromium
```

### 3. 第一次运行

```bash
# 爬取前3页数据进行测试
python main.py --pages 3
```

## 基本用法

### 命令行接口

```bash
# 基本爬取
python main.py --pages 10                    # 爬取前10页
python main.py --pages 5 --start-page 3    # 从第3页开始爬取5页

# 增量爬取
python main.py --incremental                # 爬取最近7天数据
python main.py --incremental --days 3       # 爬取最近3天数据

# 按类型筛选
python main.py --type 数据库 --pages 10     # 爬取数据库类型漏洞
python main.py --type 操作系统 --pages 10    # 爬取操作系统类型漏洞

# 按关键词搜索
python main.py --search oracle --pages 10    # 搜索oracle相关漏洞
python main.py -q mysql --pages 5           # 搜索mysql相关漏洞

# 按月份爬取（自动翻页直到披露时间不满足）
python main.py --month 2026-07 --pages 20 --start-page 1

# 数据库类型爬取（支持逗号分割多类型）
python main.py --data-type oracle --pages 10   # 爬取oracle相关漏洞
python main.py --data-type 达梦 --pages 10     # 爬取达梦相关漏洞
python main.py --data-type oracle,mysql,达梦   # 爬取多种类型漏洞

# 输出格式
python main.py --data-type oracle -o json     # 输出为JSON（默认）
python main.py --data-type oracle -o md       # 输出为Markdown
python main.py --data-type oracle --format yaml  # 内容格式为YAML

# 文件拆分
python main.py --data-type oracle --split day   # 按天拆分（默认）
python main.py --data-type oracle --split month # 按月拆分

# 重试失败记录
python main.py --retry                      # 重试之前失败的CVE

# 调试模式
python main.py --pages 3 --no-headless     # 显示浏览器界面
```

### Python API

#### 简单爬取

```python
import asyncio
from main import crawl_aliyun_cves

async def simple_crawl():
    # 爬取前5页数据
    cve_infos = await crawl_aliyun_cves(max_pages=5)

    print(f"成功爬取 {len(cve_infos)} 个CVE")

    # 显示前3个结果
    for i, cve in enumerate(cve_infos[:3]):
        print(f"\n{i+1}. {cve.cve_id}")
        print(f"   严重性: {cve.to_merged_dict().get('severity')}")
        print(f"   CVSS: {cve.cvss_score}")
        print(f"   描述: {cve.description[:100]}...")

# 运行
asyncio.run(simple_crawl())
```

#### 按类型和关键词爬取

```python
import asyncio
from main import crawl_aliyun_cves

async def search_crawl():
    # 按关键词搜索oracle相关漏洞
    cves = await crawl_aliyun_cves(
        max_pages=10,
        search_keyword="oracle"
    )
    print(f"找到 {len(cves)} 个oracle相关漏洞")

    # 按数据库类型爬取
    cves = await crawl_aliyun_cves(
        max_pages=10,
        data_type="oracle"
    )
    print(f"找到 {len(cves)} 个oracle漏洞")

    # 按多类型爬取
    cves = await crawl_aliyun_cves(
        max_pages=10,
        data_type="oracle,mysql,达梦"
    )

    # 按月份爬取
    cves = await crawl_aliyun_cves(
        max_pages=20,
        start_page=1,
        target_month="2026-07"
    )
    print(f"找到 {len(cves)} 个2026年7月的漏洞")

asyncio.run(search_crawl())
```

#### 增量爬取

```python
import asyncio
from datetime import datetime, timedelta
from main import crawl_aliyun_cves_incremental

async def incremental_crawl():
    # 爬取最近7天的数据
    new_cves = await crawl_aliyun_cves_incremental(days=7)

    if new_cves:
        print(f"发现 {len(new_cves)} 个新CVE")

        # 按严重性分类
        critical = [cve for cve in new_cves if cve.to_merged_dict().get('severity') == "CRITICAL"]
        high = [cve for cve in new_cves if cve.to_merged_dict().get('severity') == "HIGH"]

        print(f"严重: {len(critical)}, 高危: {len(high)}")
    else:
        print("没有发现新的CVE")

asyncio.run(incremental_crawl())
```

#### 重试失败记录

```python
import asyncio
from main import retry_aliyun_cves

async def retry_failed():
    # 重试之前失败的CVE
    cve_details = await retry_aliyun_cves(
        output_format="json",
        split_by="day"
    )
    print(f"重试成功: {len(cve_details)} 个CVE")

asyncio.run(retry_failed())
```

## 高级配置

### 自定义爬虫配置

```python
from main import AliyunCVECrawler, CrawlConfig

# 创建自定义配置
config = CrawlConfig(
    # 爬取设置
    max_pages=50,              # 最大页数
    delay_range=(2, 5),        # 请求间隔2-5秒
    timeout=60,                # 页面超时60秒
    
    # 浏览器设置
    headless=True,             # 无头模式
    user_agent="Custom-Agent", # 自定义User-Agent
    
    # 存储设置
    data_dir="./my_data",      # 自定义数据目录
    cache_ttl=3600             # 缓存1小时
)

async def custom_crawl():
    async with AliyunCVECrawler(config) as crawler:
        # 爬取数据
        cve_infos = await crawler.crawl_all(start_page=1, max_pages=10)
        
        # 获取统计信息
        metrics = crawler.get_metrics()
        print(f"爬取统计: {metrics}")
        
        return cve_infos
```

### 错误处理和重试

```python
import asyncio
from main import AliyunCVECrawler, CrawlConfig

async def robust_crawl():
    config = CrawlConfig(
        max_pages=20,
        delay_range=(3, 6),  # 增加延迟减少被限制的可能
        timeout=90           # 增加超时时间
    )
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            async with AliyunCVECrawler(config) as crawler:
                cve_infos = await crawler.crawl_all()
                print(f"成功爬取 {len(cve_infos)} 个CVE")
                return cve_infos
                
        except Exception as e:
            print(f"第 {attempt + 1} 次尝试失败: {e}")
            if attempt < max_retries - 1:
                print("等待30秒后重试...")
                await asyncio.sleep(30)
            else:
                print("所有重试都失败了")
                raise

asyncio.run(robust_crawl())
```

## API参考

### CrawlConfig 类

配置爬虫行为的参数类。

```python
@dataclass
class CrawlConfig:
    base_url: str = "https://avd.aliyun.com"
    list_url: str = "https://avd.aliyun.com/nvd/list"
    search_url: str = "https://avd.aliyun.com/search"
    detail_url_template: str = "https://avd.aliyun.com/detail?id={}"

    # 爬取配置
    max_pages: int = 100        # 最大爬取页数
    page_size: int = 30         # 每页条目数
    delay_range: tuple = (1, 3) # 请求间隔范围（秒）
    timeout: int = 30           # 页面加载超时
    max_retries: int = 3        # 最大重试次数
    cve_type: str = ""           # CVE类型筛选（如：数据库、操作系统）
    search_keyword: str = ""    # 搜索关键词（如：oracle）
    target_month: str = ""       # 目标月份(YYYY-MM)
    data_type: str = ""          # 数据库类型（逗号分割）

    # 浏览器配置
    headless: bool = True       # 是否无头模式
    user_agent: str = "..."     # User-Agent字符串

    # 数据存储
    data_dir: str = "./data/aliyun_cve"  # 数据目录
    cache_ttl: int = 86400      # 缓存TTL（秒）
    output_format: str = "json"  # 内容格式: json 或 yaml
    output_type: str = "json"   # 输出类型: json 或 md
    split_by: str = "day"       # 文件拆分维度: day 或 month
```

### AliyunCVECrawler 类

主要的爬虫类。

#### 方法

- `crawl_all(start_page, max_pages)`: 爬取所有CVE数据
- `crawl_incremental(since_date)`: 增量爬取
- `retry_failed()`: 重试之前失败的CVE
- `get_failed_cves()`: 获取失败记录的CVE列表
- `clear_failed_cves()`: 清除失败记录
- `get_metrics()`: 获取爬取统计信息

#### 使用示例

```python
async with AliyunCVECrawler(config) as crawler:
    # 全量爬取
    all_cves = await crawler.crawl_all(start_page=1, max_pages=10)

    # 按月份爬取
    config.target_month = "2026-07"
    config.search_keyword = "oracle"
    all_cves = await crawler.crawl_all(start_page=1, max_pages=20)

    # 增量爬取
    since_date = datetime.now() - timedelta(days=7)
    new_cves = await crawler.crawl_incremental(since_date)

    # 重试失败记录
    retry_cves = await crawler.retry_failed()

    # 查看失败记录
    failed = crawler.get_failed_cves()
    print(f"失败记录: {len(failed)} 个")

    # 清除失败记录
    crawler.clear_failed_cves()

    # 获取统计
    stats = crawler.get_metrics()
```

### 便捷函数

#### crawl_aliyun_cves()

```python
async def crawl_aliyun_cves(
    max_pages: int = 10,
    start_page: int = 1,
    headless: bool = True,
    output_format: str = "json",
    output_type: str = "json",
    split_by: str = "day",
    cve_type: str = "",
    search_keyword: str = "",
    target_month: str = "",
    data_type: str = ""
) -> List[CVEDetail]
```

快速爬取CVE数据的便捷函数。

**参数说明**:
- `max_pages`: 最大爬取页数
- `start_page`: 起始页码
- `headless`: 是否无头模式
- `output_format`: 内容格式 (json/yaml)
- `output_type`: 输出类型 (json/md)
- `split_by`: 文件拆分维度 (day/month)
- `cve_type`: CVE类型筛选
- `search_keyword`: 搜索关键词
- `target_month`: 目标月份(YYYY-MM)，按披露时间过滤
- `data_type`: 数据库类型（逗号分割），如 "oracle,mysql,达梦"

#### crawl_aliyun_cves_incremental()

```python
async def crawl_aliyun_cves_incremental(
    days: int = 7,
    output_format: str = "json",
    split_by: str = "day",
    cve_type: str = "",
    search_keyword: str = ""
) -> List[CVEDetail]
```

快速进行增量爬取的便捷函数。

#### retry_aliyun_cves()

```python
async def retry_aliyun_cves(
    output_format: str = "json",
    split_by: str = "day",
    cve_type: str = ""
) -> List[CVEDetail]
```

重试之前失败记录的CVE。

**使用示例**:
```python
import asyncio
from main import retry_aliyun_cves

async def retry_failed():
    # 重试所有失败的CVE
    cve_details = await retry_aliyun_cves()

    # 指定输出格式
    cve_details = await retry_aliyun_cves(
        output_format="json",
        split_by="month"
    )

    print(f"重试成功: {len(cve_details)} 个CVE")

asyncio.run(retry_failed())
```

## 示例代码

### 示例1：批量爬取并分析

```python
import asyncio
from collections import Counter
from main import crawl_aliyun_cves

async def analyze_cves():
    # 爬取数据
    cves = await crawl_aliyun_cves(max_pages=10)

    # 统计分析
    severity_count = Counter(
        cve.to_merged_dict().get('severity') for cve in cves
    )
    print("严重性分布:")
    for severity, count in severity_count.items():
        print(f"  {severity}: {count}")

    # 找出高危漏洞
    high_risk = [
        cve for cve in cves
        if cve.to_merged_dict().get('cvss_score', 0) >= 7.0
    ]
    print(f"\n高危漏洞 (CVSS >= 7.0): {len(high_risk)}")

    # 显示最新的5个高危漏洞
    high_risk.sort(
        key=lambda x: x.to_merged_dict().get('disclosure_date', ''),
        reverse=True
    )
    print("\n最新高危漏洞:")
    for cve in high_risk[:5]:
        merged = cve.to_merged_dict()
        print(f"  {cve.cve_id} - {merged.get('severity')} - CVSS: {merged.get('cvss_score')}")

asyncio.run(analyze_cves())
```

### 示例2：数据库类型漏洞监控

```python
import asyncio
from main import crawl_aliyun_cves

async def monitor_db_cves():
    """监控主流数据库漏洞"""
    data_types = ["oracle", "达梦", "金仓", "goldendb", "海山"]

    for data_type in data_types:
        cves = await crawl_aliyun_cves(
            max_pages=10,
            data_type=data_type
        )
        print(f"\n{data_type} 相关漏洞: {len(cves)} 个")

        # 统计严重漏洞
        critical = [
            cve for cve in cves
            if cve.to_merged_dict().get('severity') == 'CRITICAL'
        ]
        high = [
            cve for cve in cves
            if cve.to_merged_dict().get('severity') == 'HIGH'
        ]
        print(f"  严重: {len(critical)}, 高危: {len(high)}")

asyncio.run(monitor_db_cves())
```

### 示例3：按月份爬取特定漏洞

```python
import asyncio
from main import crawl_aliyun_cves

async def crawl_by_month():
    """爬取指定月份的漏洞数据"""
    # 爬取2026年7月的oracle相关漏洞
    cves = await crawl_aliyun_cves(
        max_pages=20,
        start_page=1,
        target_month="2026-07",
        data_type="oracle"
    )

    print(f"2026年7月 oracle 漏洞: {len(cves)} 个")

    # 按严重性分类统计
    severity_stats = {}
    for cve in cves:
        sev = cve.to_merged_dict().get('severity', 'UNKNOWN')
        severity_stats[sev] = severity_stats.get(sev, 0) + 1

    print("严重性分布:", severity_stats)

asyncio.run(crawl_by_month())
```

### 示例4：定期监控

```python
import asyncio
import schedule
import time
from datetime import datetime
from main import crawl_aliyun_cves_incremental

async def daily_monitor():
    """每日监控新漏洞"""
    print(f"[{datetime.now()}] 开始每日CVE监控...")

    try:
        new_cves = await crawl_aliyun_cves_incremental(days=1)

        if new_cves:
            critical_cves = [
                cve for cve in new_cves
                if cve.to_merged_dict().get('severity') == "CRITICAL"
            ]

            print(f"发现 {len(new_cves)} 个新CVE")
            if critical_cves:
                print(f"发现 {len(critical_cves)} 个严重漏洞!")
                for cve in critical_cves:
                    print(f"  - {cve.cve_id}: {cve.description[:100]}...")
        else:
            print("没有发现新CVE")

    except Exception as e:
        print(f"监控失败: {e}")

def run_monitor():
    """运行监控任务"""
    asyncio.run(daily_monitor())

# 设置定时任务
schedule.every().day.at("09:00").do(run_monitor)

print("CVE监控服务已启动，每天09:00执行检查...")
while True:
    schedule.run_pending()
    time.sleep(60)
```

## 最佳实践

### 1. 合理设置爬取频率

```python
# 推荐配置
config = CrawlConfig(
    delay_range=(2, 5),  # 2-5秒随机延迟
    timeout=60,          # 足够的超时时间
    max_pages=20         # 适中的页数
)
```

### 2. 错误处理

```python
async def safe_crawl():
    try:
        cves = await crawl_aliyun_cves(max_pages=10)
        return cves
    except Exception as e:
        logger.error(f"爬取失败: {e}")
        # 可以选择返回空列表或重新抛出异常
        return []
```

### 3. 数据验证

```python
def validate_cve_data(cves):
    """验证CVE数据质量"""
    valid_cves = []

    for cve in cves:
        merged = cve.to_merged_dict()
        if (cve.cve_id and
            cve.description and
            merged.get('cvss_score', 0) > 0):
            valid_cves.append(cve)
        else:
            print(f"无效CVE数据: {cve.cve_id}")

    return valid_cves
```

### 4. 内存管理

```python
async def memory_efficient_crawl():
    """内存高效的爬取方式"""
    config = CrawlConfig(max_pages=5)  # 分批处理
    
    all_cves = []
    for batch_start in range(1, 21, 5):  # 每次5页，总共20页
        batch_cves = await crawl_aliyun_cves(
            max_pages=5, 
            start_page=batch_start
        )
        all_cves.extend(batch_cves)
        
        # 可选：保存中间结果
        print(f"已处理 {len(all_cves)} 个CVE")
    
    return all_cves
```

### 6. 输出格式选择

```python
from main import CrawlConfig

# JSON输出（默认）
config = CrawlConfig(
    output_format="json",  # 内容格式
    output_type="json",   # 输出类型
)

# Markdown输出（适合阅读和报告）
config = CrawlConfig(
    output_format="json",
    output_type="md"
)

# YAML输出（适合配置集成）
config = CrawlConfig(
    output_format="yaml",
    output_type="json"
)
```

### 7. 文件结构说明

爬取结果保存在 `data_dir` 目录下：

```
data/aliyun_cve/
├── cve_data_data-oracle_20260716.json      # 按数据类型和实际日期
├── cve_data_data-oracle-mysql-达梦_20260716.json  # 多类型
├── cve_data_data-oracle_month-202607_20260716.json  # 按月+类型
├── cve_data_20260716.md                     # Markdown格式
├── failed_cves.json                         # 失败记录（可使用 --retry 重试）
└── ...
```

### 8. 失败重试机制

爬取过程中失败的CVE会记录到 `failed_cves.json`，后续可通过 `--retry` 重试：

```bash
# 查看失败记录数量
python main.py --retry --data-type oracle

# 配合其他参数使用
python main.py --retry --format yaml
```

## 数据字段说明

爬取的数据包含以下字段：

| 字段 | 说明 |
|------|------|
| cve_id | CVE编号（如 CVE-2026-1234） |
| title | 漏洞标题 |
| description | 漏洞描述 |
| severity | 严重等级（CRITICAL/HIGH/MEDIUM/LOW） |
| cvss_score | CVSS评分（0-10） |
| cvss_vector | CVSS向量 |
| published_date | 披露日期（ISO格式） |
| modified_date | 修改日期（ISO格式） |
| disclosure_date | 披露日期（原始格式 YYYY-MM-DD） |
| references | 参考链接列表 |
| solution | 解决方案 |
| cwe_ids | CWE编号列表 |
| patch_status | 补丁状态 |
| exploit_status | 利用状态 |

这些示例和最佳实践可以帮助您更好地使用阿里云CVE爬虫工具。根据您的具体需求调整配置和使用方式。
