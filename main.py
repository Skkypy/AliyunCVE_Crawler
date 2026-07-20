"""
阿里云漏洞库爬虫 - 爬取CVE数据

本模块提供阿里云漏洞库的数据爬取功能，包括：
- CVE列表页面的批量爬取
- CVE详情页面的详细信息提取
- 数据清洗和标准化处理
- 增量更新和去重机制
- 与知识库的集成
"""

import asyncio
import json
import aiofiles
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import os
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
import random

from loguru import logger
from playwright.async_api import async_playwright, Browser, Page, BrowserContext

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class CVEInfo:
    """标准CVE信息格式"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: datetime
    modified_date: datetime
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'published_date': self.published_date.isoformat(),
            'modified_date': self.modified_date.isoformat(),
            'references': self.references,
            'affected_products': self.affected_products,
            'cwe_ids': self.cwe_ids
        }


@dataclass
class CrawlConfig:
    """爬虫配置"""
    base_url: str = "https://avd.aliyun.com"
    list_url: str = "https://avd.aliyun.com/nvd/list"
    search_url: str = "https://avd.aliyun.com/search"
    detail_url_template: str = "https://avd.aliyun.com/detail?id={}"

    # 爬取配置
    max_pages: int = 100  # 最大爬取页数
    page_size: int = 30   # 每页条目数
    delay_range: tuple = (1, 3)  # 请求间隔范围（秒）
    timeout: int = 30     # 页面加载超时
    max_retries: int = 3  # 最大重试次数
    cve_type: str = ""    # CVE类型筛选，如 "数据库"、"操作系统" 等
    search_keyword: str = ""  # 搜索关键词，如 "oracle"
    target_month: str = ""  # 目标月份，如 "2026-07"，按披露时间过滤
    data_type: str = ""  # 数据库类型（逗号分割）：oracle、达梦、金仓、goldendb、海山、mysql等

    # 浏览器配置
    headless: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # 数据存储
    data_dir: str = "./data/aliyun_cve"
    cache_ttl: int = 86400  # 缓存TTL（秒）
    output_format: str = "json"  # 内容格式: json 或 yaml
    output_type: str = "json"  # 输出类型: json 或 md (markdown)
    split_by: str = "day"  # 拆分维度: day 或 month


@dataclass
class CVEListItem:
    """CVE列表项"""
    cve_id: str
    title: str
    cwe_type: str
    disclosure_date: str
    cvss_score: str
    detail_url: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'title': self.title,
            'cwe_type': self.cwe_type,
            'disclosure_date': self.disclosure_date,
            'cvss_score': self.cvss_score,
            'detail_url': self.detail_url
        }


@dataclass
class CVEDetail:
    """CVE详细信息"""
    cve_id: str
    title: str
    description: str
    solution: str
    references: List[str] = field(default_factory=list)
    cvss_score: str = ""
    cvss_vector: str = ""
    cwe_info: List[Dict[str, str]] = field(default_factory=list)
    disclosure_date: str = ""
    patch_status: str = ""
    exploit_status: str = ""

    @staticmethod
    def clean_text(text: str) -> str:
        """清理文本中的换行符和多余空格"""
        if not text:
            return ""
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _parse_cvss_score(self, cvss_str: str) -> float:
        """解析CVSS分数，处理各种可能的值"""
        if not cvss_str:
            return 0.0

        # 清理字符串
        cvss_str = str(cvss_str).strip().upper()

        # 处理常见的非数字值
        if cvss_str in ['N/A', 'NA', 'NULL', 'NONE', '', '-', '未知', '无']:
            return 0.0

        # 处理范围值，如 "7.5-8.0"，取平均值
        if '-' in cvss_str and cvss_str.count('-') == 1:
            try:
                parts = cvss_str.split('-')
                if len(parts) == 2:
                    start = float(parts[0].strip())
                    end = float(parts[1].strip())
                    return (start + end) / 2
            except ValueError:
                pass

        # 尝试直接转换为浮点数
        try:
            score = float(cvss_str)
            # 确保分数在有效范围内 (0.0-10.0)
            return max(0.0, min(10.0, score))
        except ValueError:
            # 如果无法转换，记录警告并返回默认值
            logger.warning(f"无法解析CVSS分数: '{cvss_str}', 使用默认值0.0")
            return 0.0

    def _guess_severity_from_description(self) -> str:
        """根据描述推测严重性等级"""
        text = (self.title + " " + self.description).lower()

        # 严重关键词
        critical_keywords = ['remote code execution', 'rce', '远程代码执行', '任意代码执行',
                           'privilege escalation', '权限提升', 'sql injection', 'sql注入',
                           'buffer overflow', '缓冲区溢出', 'memory corruption', '内存损坏']

        # 高危关键词
        high_keywords = ['cross-site scripting', 'xss', '跨站脚本', 'csrf', '跨站请求伪造',
                        'directory traversal', '目录遍历', 'file inclusion', '文件包含',
                        'authentication bypass', '认证绕过', 'authorization bypass', '授权绕过']

        # 中危关键词
        medium_keywords = ['information disclosure', '信息泄露', 'denial of service', 'dos',
                          '拒绝服务', 'weak encryption', '弱加密', 'insecure', '不安全']

        # 检查关键词
        for keyword in critical_keywords:
            if keyword in text:
                return "CRITICAL"

        for keyword in high_keywords:
            if keyword in text:
                return "HIGH"

        for keyword in medium_keywords:
            if keyword in text:
                return "MEDIUM"

        # 默认为中等
        return "MEDIUM"

    def to_cve_info(self) -> CVEInfo:
        """转换为标准CVEInfo格式"""
        try:
            # 解析CVSS分数，处理各种可能的值
            cvss_score = self._parse_cvss_score(self.cvss_score)
            
            # 确定严重性等级
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0.0:
                severity = "LOW"
            else:
                # CVSS为0或N/A时，根据标题或描述推测严重性
                severity = self._guess_severity_from_description()
            
            # 解析日期
            try:
                published_date = datetime.strptime(self.disclosure_date, "%Y-%m-%d")
            except:
                published_date = datetime.now()
            
            # 提取CWE ID
            cwe_ids = []
            for cwe in self.cwe_info:
                if 'id' in cwe and cwe['id'].startswith('CWE-'):
                    cwe_ids.append(cwe['id'])
            
            return CVEInfo(
                cve_id=self.cve_id,
                description=self.description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published_date,
                modified_date=published_date,
                references=self.references,
                affected_products=[],
                cwe_ids=cwe_ids
            )
            
        except Exception as e:
            logger.error(f"转换CVE信息失败 {self.cve_id}: {e}")
            # 返回基本信息
            return CVEInfo(
                cve_id=self.cve_id,
                description=self.description or f"CVE {self.cve_id} vulnerability",
                severity="MEDIUM",
                cvss_score=5.0,
                published_date=datetime.now(),
                modified_date=datetime.now(),
                references=self.references
            )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'title': self.clean_text(self.title),
            'description': self.clean_text(self.description),
            'solution': self.clean_text(self.solution),
            'references': self.references,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cwe_info': self.cwe_info,
            'disclosure_date': self.disclosure_date,
            'patch_status': self.clean_text(self.patch_status),
            'exploit_status': self.clean_text(self.exploit_status)
        }

    def to_merged_dict(self) -> Dict[str, Any]:
        """转换为合并格式（同时包含info和detail的字段）"""
        cvss_score = self._parse_cvss_score(self.cvss_score)

        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        elif cvss_score > 0.0:
            severity = "LOW"
        else:
            severity = self._guess_severity_from_description()

        try:
            published_date = datetime.strptime(self.disclosure_date, "%Y-%m-%d")
        except:
            published_date = None

        cwe_ids = []
        for cwe in self.cwe_info:
            if 'id' in cwe and cwe['id'].startswith('CWE-'):
                cwe_ids.append(cwe['id'])

        return {
            'cve_id': self.cve_id,
            'title': self.clean_text(self.title),
            'description': self.clean_text(self.description),
            'severity': severity,
            'cvss_score': cvss_score,
            'cvss_vector': self.cvss_vector,
            'published_date': published_date.isoformat() if published_date else None,
            'modified_date': published_date.isoformat() if published_date else None,
            'disclosure_date': self.disclosure_date,
            'references': self.references,
            'solution': self.clean_text(self.solution),
            'cwe_ids': cwe_ids,
            'patch_status': self.clean_text(self.patch_status),
            'exploit_status': self.clean_text(self.exploit_status)
        }


class AliyunCVECrawler:
    """阿里云CVE爬虫"""

    def __init__(self, config: Optional[CrawlConfig] = None):
        """初始化爬虫"""
        self.config = config or CrawlConfig()

        # 创建数据目录
        self.data_dir = Path(self.config.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 缓存和状态
        self.crawled_cves: Set[str] = set()
        self.failed_cves: Set[str] = set()
        self.stop_requested: bool = False

        # 失败记录文件
        self.failed_file = self.data_dir / "failed_cves.json"
        self._load_failed_cves()

        # 性能指标
        self.metrics = {
            "pages_crawled": 0,
            "cves_found": 0,
            "cves_detailed": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None
        }

        # 浏览器实例
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None

        logger.info("阿里云CVE爬虫初始化完成")

    def _load_failed_cves(self):
        """加载之前失败记录的CVE"""
        if self.failed_file.exists():
            try:
                with open(self.failed_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.failed_cves = set(data.get('failed_cves', []))
                    if self.failed_cves:
                        logger.info(f"已加载 {len(self.failed_cves)} 条失败记录")
            except Exception as e:
                logger.warning(f"加载失败记录失败: {e}")
                self.failed_cves = set()

    def _save_failed_cves(self):
        """保存失败记录的CVE到文件"""
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "failed_cves": list(self.failed_cves)
            }
            with open(self.failed_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存失败记录失败: {e}")

    def get_failed_cves(self) -> List[str]:
        """获取所有失败记录的CVE ID列表"""
        return list(self.failed_cves)

    def clear_failed_cves(self):
        """清除失败记录"""
        self.failed_cves.clear()
        if self.failed_file.exists():
            self.failed_file.unlink()
        logger.info("已清除失败记录")

    def request_stop(self):
        """请求停止爬取"""
        self.stop_requested = True
        logger.info("收到停止请求")

    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self._init_browser()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self._cleanup_browser()
    
    async def _init_browser(self):
        """初始化浏览器"""
        try:
            playwright = await async_playwright().start()
            
            self.browser = await playwright.chromium.launch(
                headless=self.config.headless,
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor'
                ]
            )
            
            self.context = await self.browser.new_context(
                user_agent=self.config.user_agent,
                viewport={'width': 1920, 'height': 1080},
                extra_http_headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
            )
            
            logger.info("浏览器初始化完成")
            
        except Exception as e:
            logger.error(f"浏览器初始化失败: {e}")
            raise
    
    async def _cleanup_browser(self):
        """清理浏览器资源"""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            logger.info("浏览器资源清理完成")
        except Exception as e:
            logger.error(f"浏览器清理失败: {e}")
    
    async def crawl_all(self, start_page: int = 1, max_pages: Optional[int] = None) -> List[CVEDetail]:
        """爬取所有CVE数据"""
        try:
            self.metrics["start_time"] = datetime.now()
            max_pages = max_pages or self.config.max_pages

            all_cve_list = []
            all_cve_details = []

            if self.config.data_type:
                data_types = [dt.strip() for dt in self.config.data_type.split(",") if dt.strip()]
                logger.info(f"开始数据库类型爬取，类型: {data_types}")

                for dt in data_types:
                    self.config.search_keyword = dt
                    logger.info(f"正在爬取类型: {dt}")

                    if self.config.target_month:
                        cve_list = await self._crawl_search_by_month(start_page, max_pages)
                    else:
                        cve_list = await self._crawl_search_list(start_page, max_pages)

                    logger.info(f"类型 {dt} 找到 {len(cve_list)} 个CVE条目")
                    all_cve_list.extend(cve_list)

                    cve_details = await self._crawl_cve_details(cve_list)
                    all_cve_details.extend(cve_details)
                    logger.info(f"类型 {dt} 爬取详情完成，获得 {len(cve_details)} 条")

                    delay = random.uniform(*self.config.delay_range)
                    await asyncio.sleep(delay)

                cve_list = all_cve_list
                cve_details = all_cve_details
            elif self.config.target_month:
                if self.config.search_keyword:
                    logger.info(f"开始搜索爬取阿里云CVE数据，关键词: {self.config.search_keyword}，目标月份: {self.config.target_month}")
                    cve_list = await self._crawl_search_by_month(start_page, max_pages)
                else:
                    logger.info(f"开始按月爬取，目标月份: {self.config.target_month}，起始页: {start_page}")
                    cve_list = await self._crawl_list_by_month(start_page, max_pages)

                self.metrics["cves_found"] = len(cve_list)
                logger.info(f"找到 {len(cve_list)} 个CVE条目")

                cve_details = await self._crawl_cve_details(cve_list)
                self.metrics["cves_detailed"] = len(cve_details)
            elif self.config.search_keyword:
                logger.info(f"开始搜索爬取阿里云CVE数据，关键词: {self.config.search_keyword}")
                cve_list = await self._crawl_search_list(start_page, max_pages)

                self.metrics["cves_found"] = len(cve_list)
                logger.info(f"找到 {len(cve_list)} 个CVE条目")

                cve_details = await self._crawl_cve_details(cve_list)
                self.metrics["cves_detailed"] = len(cve_details)
            else:
                logger.info(f"开始爬取阿里云CVE数据，起始页: {start_page}, 最大页数: {max_pages}")
                cve_list = await self._crawl_cve_list(start_page, max_pages)

                self.metrics["cves_found"] = len(cve_list)
                logger.info(f"找到 {len(cve_list)} 个CVE条目")

                cve_details = await self._crawl_cve_details(cve_list)
                self.metrics["cves_detailed"] = len(cve_details)

            self.metrics["cves_found"] = len(cve_list)
            logger.info(f"共找到 {len(cve_list)} 个CVE条目")

            # 第三步：转换为标准格式
            cve_infos = []
            for detail in cve_details:
                try:
                    cve_info = detail.to_cve_info()
                    cve_infos.append(cve_info)
                except Exception as e:
                    logger.error(f"转换CVE信息失败 {detail.cve_id}: {e}")
                    self.metrics["errors"] += 1

            # 保存结果
            await self._save_results(cve_details, cve_details)

            self.metrics["end_time"] = datetime.now()
            duration = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()

            logger.info(f"爬取完成，耗时: {duration:.2f}秒，成功: {len(cve_details)}，失败: {len(self.failed_cves)}")

            return cve_details

        except Exception as e:
            logger.error(f"爬取过程失败: {e}")
            self.metrics["errors"] += 1
            raise
    
    async def _crawl_cve_list(self, start_page: int, max_pages: int) -> List[CVEListItem]:
        """爬取CVE列表"""
        cve_list = []
        
        for page_num in range(start_page, start_page + max_pages):
            # 检查是否收到停止请求
            if self.stop_requested:
                logger.info("收到停止请求，中断列表爬取")
                break

            try:
                logger.info(f"爬取第 {page_num} 页")

                page_cves = await self._crawl_list_page(page_num)
                if not page_cves:
                    logger.info(f"第 {page_num} 页没有数据，停止爬取")
                    break

                cve_list.extend(page_cves)
                self.metrics["pages_crawled"] += 1

                # 随机延迟
                delay = random.uniform(*self.config.delay_range)
                await asyncio.sleep(delay)

            except Exception as e:
                logger.error(f"爬取第 {page_num} 页失败: {e}")
                self.metrics["errors"] += 1
                continue
        
        return cve_list

    async def _crawl_list_by_month(self, start_page: int, max_pages: int) -> List[CVEListItem]:
        """按目标月份爬取CVE列表，自动翻页直到披露时间不满足月份"""
        cve_list = []
        target_year_month = self.config.target_month

        try:
            target_date = datetime.strptime(target_year_month, "%Y-%m")
            target_year = target_date.year
            target_month = target_date.month
        except ValueError:
            logger.error(f"无效的月份格式: {target_year_month}，请使用 YYYY-MM 格式")
            return []

        page_num = start_page
        stop_due_to_date = False

        while self.metrics["pages_crawled"] < max_pages:
            if self.stop_requested:
                logger.info("收到停止请求，中断月度爬取")
                break

            if stop_due_to_date:
                logger.info(f"发现比 {target_year_month} 更早的披露时间，停止爬取")
                break

            try:
                logger.info(f"月度爬取第 {page_num} 页，目标月份: {target_year_month}")

                page_cves = await self._crawl_list_page(page_num)
                if not page_cves:
                    logger.info(f"第 {page_num} 页没有数据，停止爬取")
                    break

                for cve in page_cves:
                    try:
                        cve_date = datetime.strptime(cve.disclosure_date, "%Y-%m-%d")
                        if cve_date.year < target_year or (cve_date.year == target_year and cve_date.month < target_month):
                            logger.info(f"发现更早的披露时间 {cve.disclosure_date}，停止爬取")
                            stop_due_to_date = True
                            break
                        elif cve_date.year == target_year and cve_date.month == target_month:
                            cve_list.append(cve)
                        else:
                            cve_list.append(cve)
                    except ValueError:
                        cve_list.append(cve)

                if stop_due_to_date:
                    break

                self.metrics["pages_crawled"] += 1

                delay = random.uniform(*self.config.delay_range)
                await asyncio.sleep(delay)
                page_num += 1

            except Exception as e:
                logger.error(f"月度爬取第 {page_num} 页失败: {e}")
                self.metrics["errors"] += 1
                continue

        logger.info(f"月度爬取完成，共获取 {len(cve_list)} 条记录")
        return cve_list

    async def _crawl_search_list(self, start_page: int, max_pages: int) -> List[CVEListItem]:
        """爬取搜索结果列表"""
        cve_list = []

        for page_num in range(start_page, start_page + max_pages):
            if self.stop_requested:
                logger.info("收到停止请求，中断搜索爬取")
                break

            try:
                logger.info(f"搜索爬取第 {page_num} 页")

                page_cves = await self._crawl_search_page(page_num)
                if not page_cves:
                    logger.info(f"搜索第 {page_num} 页没有数据，停止爬取")
                    break

                cve_list.extend(page_cves)
                self.metrics["pages_crawled"] += 1

                delay = random.uniform(*self.config.delay_range)
                await asyncio.sleep(delay)

            except Exception as e:
                logger.error(f"搜索爬取第 {page_num} 页失败: {e}")
                self.metrics["errors"] += 1
                continue

        return cve_list

    async def _crawl_search_by_month(self, start_page: int, max_pages: int) -> List[CVEListItem]:
        """按目标月份爬取搜索结果列表，自动翻页直到披露时间不满足月份"""
        cve_list = []
        target_year_month = self.config.target_month

        try:
            target_date = datetime.strptime(target_year_month, "%Y-%m")
            target_year = target_date.year
            target_month = target_date.month
        except ValueError:
            logger.error(f"无效的月份格式: {target_year_month}，请使用 YYYY-MM 格式")
            return []

        page_num = start_page
        stop_due_to_date = False

        while self.metrics["pages_crawled"] < max_pages:
            if self.stop_requested:
                logger.info("收到停止请求，中断搜索爬取")
                break

            if stop_due_to_date:
                logger.info(f"发现比 {target_year_month} 更早的披露时间，停止爬取")
                break

            try:
                logger.info(f"搜索月度爬取第 {page_num} 页，目标月份: {target_year_month}")

                page_cves = await self._crawl_search_page(page_num)
                if not page_cves:
                    logger.info(f"搜索第 {page_num} 页没有数据，停止爬取")
                    break

                for cve in page_cves:
                    try:
                        cve_date = datetime.strptime(cve.disclosure_date, "%Y-%m-%d")
                        if cve_date.year < target_year or (cve_date.year == target_year and cve_date.month < target_month):
                            logger.info(f"发现更早的披露时间 {cve.disclosure_date}，停止爬取")
                            stop_due_to_date = True
                            break
                        elif cve_date.year == target_year and cve_date.month == target_month:
                            cve_list.append(cve)
                        else:
                            cve_list.append(cve)
                    except ValueError:
                        cve_list.append(cve)

                if stop_due_to_date:
                    break

                self.metrics["pages_crawled"] += 1

                delay = random.uniform(*self.config.delay_range)
                await asyncio.sleep(delay)
                page_num += 1

            except Exception as e:
                logger.error(f"搜索月度爬取第 {page_num} 页失败: {e}")
                self.metrics["errors"] += 1
                continue

        logger.info(f"搜索月度爬取完成，共获取 {len(cve_list)} 条记录")
        return cve_list

    async def _crawl_list_page(self, page_num: int) -> List[CVEListItem]:
        """爬取单个列表页面"""
        page = await self.context.new_page()

        try:
            # 构建URL
            url = f"{self.config.list_url}?page={page_num}"
            if self.config.cve_type:
                url = f"{self.config.list_url}?type={self.config.cve_type}&page={page_num}"

            # 访问页面
            await page.goto(url, timeout=self.config.timeout * 1000)
            await page.wait_for_load_state('networkidle')

            # 等待表格加载
            await page.wait_for_selector('table tbody tr', timeout=10000)

            # 提取CVE数据
            cve_items = []
            rows = await page.query_selector_all('table tbody tr')

            for row in rows:
                try:
                    # 提取各列数据
                    cells = await row.query_selector_all('td')
                    if len(cells) >= 5:
                        # CVE编号
                        cve_link = await cells[0].query_selector('a')
                        if cve_link:
                            cve_id = await cve_link.text_content()
                            detail_url = await cve_link.get_attribute('href')
                            if detail_url:
                                detail_url = urljoin(self.config.base_url, detail_url)
                        else:
                            continue

                        # 漏洞名称
                        title = await cells[1].text_content()

                        # 漏洞类型
                        cwe_type = await cells[2].text_content()

                        # 披露时间
                        disclosure_date = await cells[3].text_content()

                        # CVSS评分
                        cvss_score = await cells[4].text_content()

                        cve_item = CVEListItem(
                            cve_id=cve_id.strip(),
                            title=title.strip(),
                            cwe_type=cwe_type.strip(),
                            disclosure_date=disclosure_date.strip(),
                            cvss_score=cvss_score.strip(),
                            detail_url=detail_url
                        )

                        cve_items.append(cve_item)

                except Exception as e:
                    logger.warning(f"解析CVE行失败: {e}")
                    continue

            logger.debug(f"第 {page_num} 页提取到 {len(cve_items)} 个CVE")
            return cve_items

        except Exception as e:
            logger.error(f"爬取列表页面失败 {page_num}: {e}")
            raise
        finally:
            await page.close()

    async def _crawl_search_page(self, page_num: int) -> List[CVEListItem]:
        """爬取搜索结果页面"""
        page = await self.context.new_page()

        try:
            url = f"{self.config.search_url}?q={self.config.search_keyword}&page={page_num}"

            await page.goto(url, timeout=self.config.timeout * 1000)
            await page.wait_for_load_state('networkidle')

            await page.wait_for_selector('table tbody tr', timeout=10000)

            cve_items = []
            rows = await page.query_selector_all('table tbody tr')

            for row in rows:
                try:
                    cells = await row.query_selector_all('td')
                    if len(cells) >= 5:
                        cve_link = await cells[0].query_selector('a')
                        if cve_link:
                            cve_id = await cve_link.text_content()
                            detail_url = await cve_link.get_attribute('href')
                            if detail_url:
                                detail_url = urljoin(self.config.base_url, detail_url)
                        else:
                            continue

                        title = await cells[1].text_content()
                        cwe_type = await cells[2].text_content()
                        disclosure_date = await cells[3].text_content()
                        cvss_score = await cells[4].text_content()

                        cve_item = CVEListItem(
                            cve_id=cve_id.strip(),
                            title=title.strip(),
                            cwe_type=cwe_type.strip(),
                            disclosure_date=disclosure_date.strip(),
                            cvss_score=cvss_score.strip(),
                            detail_url=detail_url
                        )

                        cve_items.append(cve_item)

                except Exception as e:
                    logger.warning(f"解析CVE行失败: {e}")
                    continue

            logger.debug(f"搜索结果第 {page_num} 页提取到 {len(cve_items)} 个CVE")
            return cve_items

        except Exception as e:
            logger.error(f"爬取搜索页面失败 {page_num}: {e}")
            raise
        finally:
            await page.close()
    
    async def _crawl_cve_details(self, cve_list: List[CVEListItem]) -> List[CVEDetail]:
        """爬取CVE详情"""
        cve_details = []
        
        # 限制并发数
        semaphore = asyncio.Semaphore(5)
        
        async def crawl_single_detail(cve_item: CVEListItem) -> Optional[CVEDetail]:
            async with semaphore:
                # 检查是否收到停止请求
                if self.stop_requested:
                    return None

                try:
                    detail = await self._crawl_detail_page(cve_item)
                    if detail:
                        self.crawled_cves.add(cve_item.cve_id)
                        return detail
                    else:
                        self.failed_cves.add(cve_item.cve_id)
                        return None
                except Exception as e:
                    logger.error(f"爬取CVE详情失败 {cve_item.cve_id}: {e}")
                    self.failed_cves.add(cve_item.cve_id)
                    return None
        
        # 并发爬取详情
        tasks = [crawl_single_detail(cve_item) for cve_item in cve_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集成功的结果
        for result in results:
            if isinstance(result, CVEDetail):
                cve_details.append(result)
            elif isinstance(result, Exception):
                logger.error(f"CVE详情爬取异常: {result}")
                self.metrics["errors"] += 1
        
        return cve_details
    
    async def _crawl_detail_page(self, cve_item: CVEListItem, retries: int = 0) -> Optional[CVEDetail]:
        """爬取单个CVE详情页面"""
        page = await self.context.new_page()

        try:
            # 访问详情页面
            await page.goto(cve_item.detail_url, timeout=self.config.timeout * 1000)
            await page.wait_for_load_state('networkidle')

            # 等待内容加载
            await page.wait_for_selector('h5', timeout=10000)

            # 提取标题
            title_element = await page.query_selector('h5')
            title = await title_element.text_content() if title_element else cve_item.title

            # 提取基本信息
            cve_id = cve_item.cve_id
            disclosure_date = cve_item.disclosure_date

            # 提取利用情况和补丁情况
            exploit_status = ""
            patch_status = ""

            info_sections = await page.query_selector_all('div.info-section div')
            for section in info_sections:
                text = await section.text_content()
                if "利用情况" in text:
                    exploit_status = text.replace("利用情况", "").strip()
                elif "补丁情况" in text:
                    patch_status = text.replace("补丁情况", "").strip()

            # 提取漏洞描述
            description = ""
            desc_element = await page.query_selector('h6:has-text("漏洞描述") + div')
            if desc_element:
                description = await desc_element.text_content()

            # 提取解决建议
            solution = ""
            solution_element = await page.query_selector('h6:has-text("解决建议") + div')
            if solution_element:
                solution = await solution_element.text_content()

            # 提取参考链接
            references = []
            ref_links = await page.query_selector_all('table a[href]')
            for link in ref_links:
                href = await link.get_attribute('href')
                if href and href.startswith('http'):
                    references.append(href)

            # 提取CVSS信息
            cvss_score = cve_item.cvss_score
            cvss_vector = ""

            cvss_element = await page.query_selector('div:has-text("CVSS:3.1/")')
            if cvss_element:
                cvss_text = await cvss_element.text_content()
                cvss_match = re.search(r'CVSS:3\.1/[A-Z:/]+', cvss_text)
                if cvss_match:
                    cvss_vector = cvss_match.group()

            # 提取CWE信息
            cwe_info = []
            cwe_rows = await page.query_selector_all('table tbody tr')
            for row in cwe_rows:
                cells = await row.query_selector_all('td')
                if len(cells) >= 2:
                    cwe_id = await cells[0].text_content()
                    cwe_desc = await cells[1].text_content()
                    if cwe_id and cwe_id.startswith('CWE-'):
                        cwe_info.append({
                            'id': cwe_id.strip(),
                            'description': cwe_desc.strip()
                        })

            # 创建CVE详情对象
            cve_detail = CVEDetail(
                cve_id=cve_id,
                title=title.strip() if title else "",
                description=description.strip() if description else "",
                solution=solution.strip() if solution else "",
                references=references,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_info=cwe_info,
                disclosure_date=disclosure_date,
                patch_status=patch_status,
                exploit_status=exploit_status
            )

            # 随机延迟
            delay = random.uniform(*self.config.delay_range)
            await asyncio.sleep(delay)

            return cve_detail

        except Exception as e:
            logger.error(f"爬取CVE详情页面失败 {cve_item.cve_id}: {e}")
            if retries < self.config.max_retries:
                logger.info(f"重试 {cve_item.cve_id} ({retries + 1}/{self.config.max_retries})")
                await asyncio.sleep(2 ** retries)
                return await self._crawl_detail_page(cve_item, retries + 1)
            raise
        finally:
            await page.close()
    
    async def _save_results(self, cve_details: List[CVEDetail], cve_infos: List[CVEDetail]):
        """保存爬取结果"""
        try:
            self._save_failed_cves()

            merged_data = [detail.to_merged_dict() for detail in cve_details]

            if not merged_data:
                logger.info("没有数据需要保存")
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            dates = []
            for item in merged_data:
                if item.get('disclosure_date'):
                    try:
                        dt = datetime.strptime(item['disclosure_date'], "%Y-%m-%d")
                        dates.append(dt)
                    except ValueError:
                        pass

            if dates:
                min_date = min(dates)
                max_date = max(dates)
                if self.config.split_by == "month":
                    date_range_prefix = min_date.strftime("%Y%m")
                else:
                    date_range_prefix = min_date.strftime("%Y%m%d")
            else:
                date_range_prefix = datetime.now().strftime("%Y%m%d")

            parts = ["cve_data"]

            if self.config.data_type:
                data_type_clean = self.config.data_type.replace(",", "-")
                parts.append(f"data-{data_type_clean}")
            if self.config.search_keyword and not self.config.data_type:
                parts.append(f"kw-{self.config.search_keyword}")
            if self.config.cve_type:
                parts.append(f"type-{self.config.cve_type}")
            if self.config.target_month:
                parts.append(f"month-{self.config.target_month.replace('-', '')}")

            parts.append(date_range_prefix)

            filename_prefix = "_".join(parts)

            if self.config.output_type == "md":
                output_file = self.data_dir / f"{filename_prefix}.md"
                md_content = self._generate_markdown(merged_data, timestamp)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(md_content)
            elif self.config.output_format == "yaml" and YAML_AVAILABLE:
                output_file = self.data_dir / f"{filename_prefix}.yaml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    yaml.dump(merged_data, f, allow_unicode=True, default_flow_style=False)
            else:
                output_file = self.data_dir / f"{filename_prefix}.json"
                output_data = {
                    "timestamp": timestamp,
                    "count": len(merged_data),
                    "data": merged_data
                }
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, ensure_ascii=False, indent=2)

            logger.info(f"结果已保存到: {output_file}")

        except Exception as e:
            logger.error(f"保存结果失败: {e}")

    def _generate_markdown(self, data: List[Dict[str, Any]], timestamp: str) -> str:
        """生成Markdown格式内容"""
        lines = []
        lines.append(f"# CVE漏洞列表\n")
        lines.append(f"- 生成时间: {timestamp}\n")
        lines.append(f"- 总数量: {len(data)}\n\n")

        lines.append("## 漏洞列表\n\n")
        lines.append("| CVE ID | 标题 | 严重性 | CVSS | 披露日期 | CWE | 补丁状态 | 利用状态 |\n")
        lines.append("|--------|------|--------|------|----------|-----|---------|----------|\n")

        for item in data:
            cve_id = item.get('cve_id', '')
            title = item.get('title', '')[:50] + ('...' if len(item.get('title', '')) > 50 else '')
            severity = item.get('severity', 'N/A')
            cvss = item.get('cvss_score', 'N/A')
            disclosure_date = item.get('disclosure_date', 'N/A')
            cwe = ', '.join(item.get('cwe_ids', [])[:2]) if item.get('cwe_ids') else 'N/A'
            patch = item.get('patch_status', 'N/A')
            exploit = item.get('exploit_status', 'N/A')

            lines.append(f"| {cve_id} | {title} | {severity} | {cvss} | {disclosure_date} | {cwe} | {patch} | {exploit} |\n")

        lines.append("\n## 漏洞详情\n\n")
        for item in data:
            lines.append(f"### {item.get('cve_id', '')}\n\n")
            lines.append(f"- **标题**: {item.get('title', '')}\n")
            lines.append(f"- **严重性**: {item.get('severity', 'N/A')}\n")
            lines.append(f"- **CVSS评分**: {item.get('cvss_score', 'N/A')}\n")
            lines.append(f"- **CVSS向量**: {item.get('cvss_vector', 'N/A')}\n")
            lines.append(f"- **披露日期**: {item.get('disclosure_date', 'N/A')}\n")

            cwe_ids = item.get('cwe_ids', [])
            if cwe_ids:
                lines.append(f"- **CWE**: {', '.join(cwe_ids)}\n")

            lines.append(f"- **补丁状态**: {item.get('patch_status', 'N/A')}\n")
            lines.append(f"- **利用状态**: {item.get('exploit_status', 'N/A')}\n")

            description = item.get('description', '')
            if description:
                lines.append(f"\n**描述**:\n{description[:500]}{'...' if len(description) > 500 else ''}\n")

            solution = item.get('solution', '')
            if solution:
                lines.append(f"\n**解决方案**:\n{solution[:300]}{'...' if len(solution) > 300 else ''}\n")

            references = item.get('references', [])
            if references:
                lines.append(f"\n**参考链接**:\n")
                for ref in references[:5]:
                    lines.append(f"- {ref}\n")

            lines.append("\n---\n\n")

        return ''.join(lines)
    
    async def crawl_incremental(self, since_date: Optional[datetime] = None) -> List[CVEDetail]:
        """增量爬取（爬取指定日期之后的CVE）"""
        try:
            if not since_date:
                since_date = datetime.now() - timedelta(days=7)  # 默认爬取最近7天

            logger.info(f"开始增量爬取，起始日期: {since_date.strftime('%Y-%m-%d')}")

            # 爬取第一页检查最新数据
            cve_list = await self._crawl_list_page(1)

            # 过滤出需要爬取的CVE
            new_cves = []
            for cve_item in cve_list:
                try:
                    cve_date = datetime.strptime(cve_item.disclosure_date, "%Y-%m-%d")
                    if cve_date >= since_date:
                        new_cves.append(cve_item)
                except:
                    # 日期解析失败，保守起见包含在内
                    new_cves.append(cve_item)

            if not new_cves:
                logger.info("没有新的CVE数据")
                return []

            logger.info(f"找到 {len(new_cves)} 个新CVE")

            # 爬取详情
            cve_details = await self._crawl_cve_details(new_cves)

            # 转换为标准格式
            cve_infos = []
            for detail in cve_details:
                try:
                    cve_info = detail.to_cve_info()
                    cve_infos.append(cve_info)
                except Exception as e:
                    logger.error(f"转换CVE信息失败 {detail.cve_id}: {e}")

            # 保存结果
            await self._save_results(cve_details, cve_details)

            logger.info(f"增量爬取完成，获得 {len(cve_details)} 个新CVE")
            return cve_details

        except Exception as e:
            logger.error(f"增量爬取失败: {e}")
            raise

    async def retry_failed(self) -> List[CVEDetail]:
        """重试之前失败的CVE"""
        if not self.failed_cves:
            logger.info("没有需要重试的失败记录")
            return []

        logger.info(f"开始重试 {len(self.failed_cves)} 个失败的CVE")

        cve_list = []
        for cve_id in list(self.failed_cves):
            cve_list.append(CVEListItem(
                cve_id=cve_id,
                title="",
                cwe_type="",
                disclosure_date="",
                cvss_score="",
                detail_url=f"{self.config.detail_url_template.format(cve_id)}"
            ))

        cve_details = await self._crawl_cve_details(cve_list)

        if cve_details:
            await self._save_results(cve_details, cve_details)

        logger.info(f"重试完成，成功: {len(cve_details)}, 剩余失败: {len(self.failed_cves)}")
        return cve_details

    def get_metrics(self) -> Dict[str, Any]:
        """获取爬取指标"""
        return self.metrics.copy()


# 便捷函数
async def crawl_aliyun_cves(max_pages: int = 10,
                           start_page: int = 1,
                           headless: bool = True,
                           output_format: str = "json",
                           output_type: str = "json",
                           split_by: str = "day",
                           cve_type: str = "",
                           search_keyword: str = "",
                           target_month: str = "",
                           data_type: str = "") -> List[CVEDetail]:
    """便捷的CVE爬取函数"""
    config = CrawlConfig(
        max_pages=max_pages,
        headless=headless,
        output_format=output_format,
        output_type=output_type,
        split_by=split_by,
        cve_type=cve_type,
        search_keyword=search_keyword,
        target_month=target_month,
        data_type=data_type
    )

    async with AliyunCVECrawler(config) as crawler:
        return await crawler.crawl_all(start_page, max_pages)


async def crawl_aliyun_cves_incremental(days: int = 7,
                                        output_format: str = "json",
                                        split_by: str = "day",
                                        cve_type: str = "",
                                        search_keyword: str = "") -> List[CVEDetail]:
    """便捷的增量CVE爬取函数"""
    config = CrawlConfig(
        output_format=output_format,
        split_by=split_by,
        cve_type=cve_type,
        search_keyword=search_keyword
    )
    since_date = datetime.now() - timedelta(days=days)

    async with AliyunCVECrawler(config) as crawler:
        return await crawler.crawl_incremental(since_date)


async def retry_aliyun_cves(output_format: str = "json",
                            split_by: str = "day",
                            cve_type: str = "") -> List[CVEDetail]:
    """便捷的重试失败CVE函数"""
    config = CrawlConfig(
        output_format=output_format,
        split_by=split_by,
        cve_type=cve_type
    )

    async with AliyunCVECrawler(config) as crawler:
        return await crawler.retry_failed()


# 命令行接口
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="阿里云CVE爬虫",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基本爬取
  python main.py --pages 10

  # 按类型筛选
  python main.py --type 数据库 --pages 5

  # 按关键词搜索
  python main.py --search oracle
  python main.py -q mysql --pages 5

  # 按月份爬取（自动翻页直到时间不满足）
  python main.py --month 2026-07 --start-page 1 --pages 20
  python main.py --data-type oracle --month 2026-07 --start-page 1 --pages 20

  # 数据库类型爬取（支持逗号分割多类型）
  python main.py --data-type oracle --pages 10
  python main.py --data-type 达梦 --pages 10
  python main.py --data-type oracle,mysql,达梦 --pages 10

  # 输出格式
  python main.py --data-type oracle -o json      # JSON输出（默认）
  python main.py --data-type oracle -o md        # Markdown输出
  python main.py --data-type oracle --format yaml # YAML内容格式

  # 增量爬取
  python main.py --incremental --days 7

  # 重试失败记录
  python main.py --retry
        """
    )
    parser.add_argument("--pages", type=int, default=5, help="爬取页数")
    parser.add_argument("--start-page", type=int, default=1, help="起始页")
    parser.add_argument("--incremental", action="store_true", help="增量爬取")
    parser.add_argument("--retry", action="store_true", help="重试失败的CVE")
    parser.add_argument("--days", type=int, default=7, help="增量爬取天数")
    parser.add_argument("--headless", action="store_true", default=True, help="无头模式")
    parser.add_argument("--format", type=str, default="json", choices=["json", "yaml"], help="内容格式 (json/yaml)")
    parser.add_argument("--output", "-o", type=str, default="json", choices=["json", "md"], help="输出类型 (json/md)")
    parser.add_argument("--split", type=str, default="day", choices=["day", "month"], help="文件拆分维度 (day/month)")
    parser.add_argument("--type", type=str, default="", help="CVE类型筛选，如: 数据库、操作系统、应用软件等")
    parser.add_argument("--search", "-q", type=str, default="", help="搜索关键词，如: oracle、mysql等")
    parser.add_argument("--month", type=str, default="", help="目标月份(YYYY-MM)，按披露时间过滤")
    parser.add_argument("--data-type", type=str, default="", help="数据库类型（逗号分割），如: oracle,mysql,达梦")

    args = parser.parse_args()

    def print_examples():
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                    阿里云CVE爬虫 - 使用指南                      ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  基本爬取:                                                        ║
║    python main.py --pages 10                    爬取前10页         ║
║    python main.py --pages 5 --start-page 3       从第3页开始爬取     ║
║                                                                  ║
║  类型筛选:                                                        ║
║    python main.py --type 数据库 --pages 10      数据库类型漏洞      ║
║    python main.py --type 操作系统 --pages 10     操作系统类型漏洞    ║
║                                                                  ║
║  关键词搜索:                                                      ║
║    python main.py --search oracle                搜索oracle漏洞    ║
║    python main.py -q mysql                       搜索mysql漏洞    ║
║                                                                  ║
║  按月份爬取:                                                      ║
║    python main.py --month 2026-07 --start-page 1 --pages 20        ║
║    python main.py --data-type oracle --month 2026-07 --start-page 1 --pages 20  ║
║                                                                  ║
║  数据库类型:                                                      ║
║    python main.py --data-type oracle --pages 10    Oracle漏洞        ║
║    python main.py --data-type 达梦 --pages 10       达梦漏洞          ║
║    python main.py --data-type oracle,mysql,达梦     多类型爬取        ║
║                                                                  ║
║  输出格式:                                                        ║
║    python main.py --data-type oracle -o json       JSON输出(默认)     ║
║    python main.py --data-type oracle -o md         Markdown输出      ║
║    python main.py --data-type oracle --format yaml YAML格式         ║
║                                                                  ║
║  增量爬取:                                                        ║
║    python main.py --incremental                  爬取最近7天       ║
║    python main.py --incremental --days 3         爬取最近3天       ║
║                                                                  ║
║  重试失败:                                                        ║
║    python main.py --retry                        重试失败记录      ║
║                                                                  ║
║  更多帮助:                                                        ║
║    python main.py -h                             显示完整帮助      ║
║    python main.py --help                                                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """)

    async def main():
        # 无参数运行时显示使用示例
        if len(sys.argv) == 1:
            print_examples()
            return
        if args.retry:
            cve_details = await retry_aliyun_cves(args.format, args.split, args.type)
        elif args.incremental:
            cve_details = await crawl_aliyun_cves_incremental(args.days, args.format, args.split, args.type, args.search)
        else:
            cve_details = await crawl_aliyun_cves(args.pages, args.start_page, args.headless, args.format, args.output, args.split, args.type, args.search, args.month, args.data_type)

        print(f"爬取完成，获得 {len(cve_details)} 个CVE")

        # 显示前几个结果
        for i, cve in enumerate(cve_details[:3]):
            print(f"\n{i+1}. {cve.cve_id}")
            print(f"   描述: {cve.description[:100]}...")
            print(f"   严重性: {cve.to_merged_dict().get('severity', 'N/A')}")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n爬取自动中断")