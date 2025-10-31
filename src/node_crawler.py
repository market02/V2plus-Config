#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点爬虫脚本 - Playwright版本
根据sub_in.json配置文件执行节点爬取任务
使用Playwright提供更好的性能和反检测能力
"""

import json
import re
import base64
import requests
import asyncio
from typing import Any, Dict, List, Optional
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from bs4 import BeautifulSoup
import logging
import os
from urllib.parse import urljoin

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def normalizeddecodefromb64(content: str) -> str:
    valid_protocols = [
        "vmess://",
        "vless://",
        "trojan://",
        "ss://",
        "ssr://",
        "hysteria2://",
    ]

    try:
        # 1. 原文直接包含协议，原样返回
        if any(proto in content for proto in valid_protocols):
            return content

        # 2. 尝试 Base64 解码（优先标准，再尝试 URL-safe），自动补齐填充
        data = content.strip()
        if not data:
            return ""

        padded = data + "=" * (-len(data) % 4)

        decoded_text = None
        try:
            decoded_text = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            try:
                decoded_text = base64.urlsafe_b64decode(padded).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                decoded_text = None

        if not decoded_text:
            return ""

        # 解码后再次检查协议头
        if any(proto in decoded_text for proto in valid_protocols):
            return decoded_text

        return ""
    except Exception:
        return ""


class ExecutionContext:
    """执行上下文类，用于管理步骤间的数据传递"""

    def __init__(self):
        self.data = None  # 当前步骤的数据
        self.page: Optional[Page] = None  # Playwright页面实例
        self.browser: Optional[Browser] = None  # 浏览器实例
        self.context: Optional[BrowserContext] = None  # 浏览器上下文
        self.results = []  # 存储所有结果
        self.current_url = None  # 当前URL

    def set_data(self, data: Any):
        """设置当前步骤的数据"""
        self.data = data

    def get_data(self) -> Any:
        """获取当前步骤的数据"""
        return self.data

    def add_result(self, result: str):
        """添加结果到结果集"""
        if result and result.strip():
            self.results.append(result.strip())

    def get_final_results(self) -> str:
        """获取最终合并的结果"""
        return "\n".join(self.results)

    async def cleanup(self):
        """清理资源"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()


class StepProcessor:
    """步骤处理器基类"""

    def __init__(self, context: ExecutionContext):
        self.context = context

    async def process_with_logging(self, step: Dict[str, Any]) -> Any:
        """带日志的步骤处理包装方法"""
        step_name = self.__class__.__name__
        logger.info(f"===> {step_name} 步骤开始 ")

        try:
            result = await self.process(step)
            logger.info(f" {step_name} 步骤结束 <===")
            return result
        except Exception as e:
            logger.error(f"<><> {step_name} 步骤异常结束: {e} <><>")
            raise

    async def process(self, step: Dict[str, Any]) -> Any:
        """处理步骤，子类需要实现此方法"""
        raise NotImplementedError


class ClickProcessor(StepProcessor):
    """点击步骤处理器"""

    async def process(self, step: Dict[str, Any]) -> Any:
        # 支持多种选择器方式
        selectors = step.get("selectors", [])
        xpath = step.get("xpath")

        # 如果有selectors数组，优先使用
        if selectors:
            target_selector = await self._find_working_selector(selectors)
            if not target_selector:
                raise ValueError(f"None of the selectors worked: {selectors}")
        elif xpath:
            # 兼容旧的xpath方式
            target_selector = f"xpath={xpath}"
        else:
            raise ValueError(
                "Click step requires either 'selectors' array or 'xpath' parameter"
            )

        logger.info(f"执行点击操作: {target_selector}")

        # 等待元素可见并点击
        await self.context.page.wait_for_selector(target_selector, timeout=60000)
        await self.context.page.click(target_selector)

        # 等待页面加载
        await self.context.page.wait_for_load_state("domcontentloaded", timeout=60000)

        # 返回当前页面的HTML
        return await self.context.page.content()

    async def _find_working_selector(self, selectors: List[str]) -> Optional[str]:
        """尝试多个选择器，返回第一个有效的选择器"""
        for selector in selectors:
            try:
                # 判断选择器类型并格式化
                formatted_selector = self._format_selector(selector)

                # 检查元素是否存在（短超时）
                await self.context.page.wait_for_selector(
                    formatted_selector, timeout=2000
                )
                logger.info(f"找到有效选择器: {formatted_selector}")
                return formatted_selector
            except Exception as e:
                logger.debug(f"选择器 '{selector}' 无效: {e}")
                continue
        return None

    def _format_selector(self, selector: str) -> str:
        """格式化选择器，自动识别类型"""
        selector = selector.strip()

        # XPath选择器（以 // 或 / 开头）
        if selector.startswith(("/", "//")):
            return f"xpath={selector}"

        # 其他情况当作CSS选择器处理
        return selector


class SearchProcessor(StepProcessor):
    """搜索步骤处理器"""

    async def process(self, step: Dict[str, Any]) -> Any:
        rules = step.get("rules")
        if not rules:
            raise ValueError("Search step requires 'rules' parameter")

        logger.info(f"执行搜索操作: {rules}")

        html_content = self.context.get_data()
        if not html_content:
            raise ValueError("Search step requires HTML content as input")

        soup = BeautifulSoup(html_content, "html.parser")

        # 仅返回"最近包含关键词的标签"：匹配到的文本节点的直接父标签
        keyword_re = re.compile(re.escape(rules), re.IGNORECASE)
        matched_strings = soup.find_all(
            string=lambda s: isinstance(s, str) and keyword_re.search(s)
        )

        nearest_tags = []
        seen_ids = set[Any]()
        for s in matched_strings:
            parent = getattr(s, "parent", None)
            if not getattr(parent, "name", None):
                continue
            obj_id = id(parent)
            if obj_id not in seen_ids:
                nearest_tags.append(parent)
                seen_ids.add(obj_id)

        logger.info(f"搜索到 {len(nearest_tags)} 个匹配元素")
        return nearest_tags


class ExtractProcessor(StepProcessor):
    """提取步骤处理器"""

    async def process(self, step: Dict[str, Any]) -> Any:
        rules = step.get("rules")
        protocols = step.get("protocols")  # 新增：支持协议列表
        output_mode = step.get("output", "single")
        next_step = step.get("next")

        # 如果指定了protocols，则进行明文节点提取
        if protocols:
            return await self._extract_plaintext_nodes(protocols)

        if not rules:
            raise ValueError("Extract step requires 'rules' parameter")

        logger.info(f"执行提取操作: {rules}")

        elements = self.context.get_data()
        if not elements:
            raise ValueError("Extract step requires elements as input")

        # 将通配符规则转换为正则表达式：将 * 转换为 .*
        escaped = re.escape(rules)
        wildcard_regex = escaped.replace(r"\*", ".*")
        # 不使用 ^$ 锚点，允许在容器区域内进行子串匹配
        pattern = re.compile(wildcard_regex, re.IGNORECASE)
        urls = []

        # 在"关键词所在标签的区域"提取 URL：祖先容器 + 子树
        for element in elements:
            node = (
                element
                if hasattr(element, "find_all")
                else getattr(element, "parent", None)
            )
            if not node:
                continue

            # 1) 最近祖先容器：向上最多 3 层，搜集 a[href] 与文本中的 URL
            container = node
            hop = 0
            while container and hop < 3:
                for link in container.find_all("a", href=True):
                    href = link.get("href")
                    if not href:
                        continue
                    full_href = href
                    if href.startswith("/") or href.startswith("./"):
                        base = self.context.current_url or ""
                        full_href = urljoin(base, href)
                    if pattern.search(full_href):
                        urls.append(full_href)

                text = container.get_text("\n", strip=True)
                for m in pattern.findall(text):
                    urls.append(m)

                container = container.parent
                hop += 1

            # 2) 子树补扫
            for link in node.find_all("a", href=True):
                href = link.get("href")
                if not href:
                    continue
                full_href = href
                if href.startswith("/") or href.startswith("./"):
                    base = self.context.current_url or ""
                    full_href = urljoin(base, href)
                if pattern.search(full_href):
                    urls.append(full_href)

            text = node.get_text("\n", strip=True)
            for m in pattern.findall(text):
                urls.append(m)

        # 去重
        urls = list[Any](dict.fromkeys(urls))
        logger.info(f"提取到 {len(urls)} 个URL")

        # 嵌套 open→decode：逐个处理并合并为单一输出
        if next_step and urls:
            combined_parts: List[str] = []
            for url in urls:
                try:
                    result = await self._process_nested_steps(url, next_step)
                    if result:
                        combined_parts.append(result)
                except Exception as e:
                    logger.error(f"处理URL {url} 时出错: {e}")
                    continue

            combined = "\n".join([p for p in combined_parts if p])
            if combined:
                self.context.add_result(combined)
            return combined

        result = urls if output_mode != "single" else (urls[0] if urls else None)
        return result

    async def _process_nested_steps(self, url: str, next_step: Dict[str, Any]) -> str:
        """处理嵌套步骤"""
        current_data = url
        step = next_step

        while step:
            step_type = step.get("type")

            if step_type == "open":
                processor = OpenProcessor(self.context)
                current_data = await processor.process_with_data(step, current_data)
            elif step_type == "decode":
                processor = DecodeProcessor(self.context)
                current_data = await processor.process_with_data(step, current_data)
            else:
                logger.warning(f"未知的嵌套步骤类型: {step_type}")
                break

            step = step.get("next")

        return current_data

    async def _extract_plaintext_nodes(self, protocols: List[str]) -> str:
        """从页面文本中提取明文节点"""
        logger.info(f"执行明文节点提取，支持协议: {protocols}")

        # 获取当前页面内容
        page = self.context.page
        if not page:
            raise ValueError("No page available for plaintext extraction")

        # 获取页面的所有文本内容
        page_content = await page.content()
        soup = BeautifulSoup(page_content, "html.parser")

        # 提取所有文本内容
        text_content = soup.get_text()

        # 查找所有匹配的节点
        nodes = []
        for protocol in protocols:
            # 使用正则表达式查找以指定协议开头的节点
            pattern = rf"{re.escape(protocol)}[^\s\n<>]*"
            matches = re.findall(pattern, text_content, re.IGNORECASE)

            for match in matches:
                if self._validate_node_format(match, protocol):
                    nodes.append(match)

        # 去重并排序
        unique_nodes = list(dict.fromkeys(nodes))

        logger.info(f"提取到 {len(unique_nodes)} 个明文节点")

        # 将结果添加到上下文
        result = "\n".join(unique_nodes)
        if result:
            self.context.add_result(result)

        return result

    def _validate_node_format(self, node: str, protocol: str) -> bool:
        """验证节点格式是否有效"""
        if not node or not node.startswith(protocol):
            return False

        # 基本长度检查
        if len(node) < len(protocol) + 10:  # 协议头 + 最少10个字符
            return False

        # 检查是否包含必要的字符（根据不同协议）
        if protocol in ["vmess://", "vless://"]:
            # 这些协议通常是base64编码的
            return len(node) > len(protocol) + 20
        elif protocol in ["trojan://", "ss://", "ssr://"]:
            # 这些协议通常包含@符号
            return "@" in node
        elif protocol.startswith("hysteria"):
            # hysteria协议通常包含端口号
            return ":" in node.replace(protocol, "")

        return True


class OpenProcessor(StepProcessor):
    """打开URL步骤处理器"""

    async def process(self, step: Dict[str, Any]) -> Any:
        url = self.context.get_data()
        return await self.process_with_data(step, url)

    async def process_with_data(self, step: Dict[str, Any], url: str) -> str:
        """使用指定数据处理步骤"""
        if not url:
            raise ValueError("Open step requires URL as input")

        logger.info(f"打开URL: {url}")

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }

            # 使用异步requests或者playwright的request功能
            # 这里使用传统的requests，也可以改为playwright的page.goto()
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: requests.get(url, headers=headers, timeout=30)
            )
            response.raise_for_status()

            return response.text

        except Exception as e:
            logger.error(f"打开URL失败: {e}")
            raise


class DecodeProcessor(StepProcessor):
    """解码步骤处理器"""

    async def process(self, step: Dict[str, Any]) -> Any:
        content = self.context.get_data()
        return await self.process_with_data(step, content)

    async def process_with_data(self, step: Dict[str, Any], content: str) -> str:
        """使用指定数据处理步骤"""
        encoding = step.get("encoding", "base64")

        if not content:
            raise ValueError("Decode step requires content as input")

        logger.info(f"执行解码操作: {encoding}")

        try:
            if encoding == "base64":
                # 规范化解码：
                # 1) 原文若包含有效协议，直接返回原文；
                # 2) 否则尝试base64解码，解码结果若包含有效协议则返回；
                # 3) 若仍不包含有效协议，返回空字符串。
                decoded_content = normalizeddecodefromb64(content)
                if not decoded_content:
                    logger.info("解码失败或未识别到有效协议，返回空")
                    return ""
            else:
                decoded_content = content

            # 到此为止 decoded_content 要么是原文（含协议），要么是解码结果（含协议）
            logger.info("解码完成，返回内容")
            return decoded_content

        except Exception as e:
            logger.error(f"解码失败: {e}")
            return ""


class NodeCrawlerPlaywright:

    def __init__(self, config_file: str = "../data/in/sub_in.json"):
        # 将配置文件路径锚定到脚本目录，避免工作目录不同导致读取错误文件
        script_dir = os.path.dirname(__file__)
        self.config_file = os.path.join(script_dir, config_file)
        self.context = ExecutionContext()
        self._playwright = None
        self.processors = {
            "click": ClickProcessor,
            "search": SearchProcessor,
            "extract": ExtractProcessor,
            "open": OpenProcessor,
            "decode": DecodeProcessor,
        }

    def load_config(self) -> List[Dict[str, Any]]:
        """加载配置文件"""
        try:
            logger.info(f"正在加载配置文件: {self.config_file}")
            # 直接以严格 JSON 解析；使用 utf-8-sig 兼容可能的 BOM
            with open(self.config_file, "r", encoding="utf-8-sig") as f:
                content = f.read()
            return json.loads(content)
        except FileNotFoundError:
            logger.error(f"配置文件不存在: {self.config_file}")
            raise
        except (ValueError, json.JSONDecodeError) as e:
            logger.error(f"JSON解析失败: {e}")
            try:
                # 只有在content已定义的情况下才进行错误分析
                if "content" in locals():
                    lines = content.split("\n")
                    lineno = getattr(e, "lineno", None)
                    colno = getattr(e, "colno", None)
                    if lineno is not None and 1 <= lineno <= len(lines):
                        error_line = lines[lineno - 1]
                        logger.error(f"出错行内容: {repr(error_line)}")
                        if colno is not None and 1 <= colno <= len(error_line):
                            snippet = error_line[
                                max(0, colno - 2) : min(len(error_line), colno + 1)
                            ]
                            logger.error(f"出错字符片段: {repr(snippet)}")
            except Exception:
                pass
            raise
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            raise

    async def setup_browser(self):
        """设置Playwright浏览器"""
        try:
            self._playwright = await async_playwright().start()

            # 启动浏览器（无头模式）
            self.context.browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-web-security",
                    "--disable-features=VizDisplayCompositor",
                ],
            )

            # 创建浏览器上下文，设置反检测
            self.context.context = await self.context.browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
                java_script_enabled=True,
                ignore_https_errors=True,
            )

            # 创建页面
            self.context.page = await self.context.context.new_page()

            # 添加反检测脚本
            await self.context.page.add_init_script(
                """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
                
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['zh-CN', 'zh', 'en'],
                });
                
                window.chrome = {
                    runtime: {},
                };
            """
            )

            logger.info("Playwright浏览器初始化成功")

        except Exception as e:
            logger.error(f"Playwright浏览器初始化失败: {e}")
            raise

    async def execute_task(self, task: Dict[str, Any]):
        """执行单个任务"""
        url = task.get("URL")
        steps = task.get("steps", [])

        if not url:
            raise ValueError("Task requires 'URL' parameter")

        logger.info(f"开始执行任务: {url}")

        # 打开初始URL
        await self.context.page.goto(url, wait_until="domcontentloaded", timeout=60000)
        self.context.current_url = url
        self.context.set_data(await self.context.page.content())

        # 执行步骤
        for i, step in enumerate(steps):
            step_type = step.get("type")

            if step_type not in self.processors:
                logger.warning(f"未知步骤类型: {step_type}")
                continue

            logger.info(f"执行步骤 {i+1}/{len(steps)}: {step_type}")

            try:
                processor = self.processors[step_type](self.context)
                result = await processor.process_with_logging(step)
                self.context.set_data(result)

            except Exception as e:
                logger.error(f"步骤 {step_type} 执行失败: {e}")
                raise

    async def run(self) -> str:
        """运行爬虫"""
        successful_tasks = 0
        failed_tasks = 0

        try:
            # 加载配置
            config = self.load_config()

            # 设置浏览器
            await self.setup_browser()

            # 执行所有任务
            for i, task in enumerate(config):
                logger.info(f"执行任务 {i+1}/{len(config)}")
                try:
                    await self.execute_task(task)
                    successful_tasks += 1
                except Exception as e:
                    failed_tasks += 1
                    logger.error(f"任务 {i+1} 执行失败: {e}")
                    logger.info(f"跳过失败的任务，继续执行下一个任务...")

            # 获取最终结果
            final_result = self.context.get_final_results()
            logger.info(f"爬取完成，成功: {successful_tasks}, 失败: {failed_tasks}")
            logger.info(f"共获得 {len(self.context.results)} 个结果")

            return final_result

        except Exception as e:
            logger.error(f"爬虫执行失败: {e}")
            raise
        finally:
            await self.context.cleanup()
            # 关闭 Playwright 以清理底层传输资源
            try:
                if self._playwright:
                    await self._playwright.stop()
            except Exception:
                pass

    def save_results(self, results: str, output_file: str = "../data/out/sub_out.txt"):
        """保存结果到文件"""
        try:
            # 确保输出目录存在
            script_dir = os.path.dirname(__file__)
            full_output_path = os.path.join(script_dir, output_file)
            output_dir = os.path.dirname(full_output_path)
            os.makedirs(output_dir, exist_ok=True)

            with open(full_output_path, "w", encoding="utf-8") as f:
                f.write(results)
            logger.info(f"结果已保存到: {full_output_path}")
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
            raise


async def main():
    """主函数"""
    crawler = NodeCrawlerPlaywright()

    try:
        results = await crawler.run()

        # 保存结果
        crawler.save_results(results)

        print("节点爬取完成！")
        print(f"共获取到 {len(results.split())} 行数据")

    except Exception as e:
        print(f"爬取失败: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(asyncio.run(main()))
