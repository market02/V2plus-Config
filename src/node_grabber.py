import asyncio
from typing import Any
import httpx
import json
import base64
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime
from pathlib import Path


def load_config():
    """加载JSON配置文件"""
    try:
        with open("sub_in.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        return []


def is_base64(content):
    """判断内容是否为base64编码"""
    try:
        # 移除空白字符
        content = content.strip()
        if not content:
            return False

        # 检查是否包含协议头，如果有则不是base64
        if any(
            protocol in content
            for protocol in [
                "vmess://",
                "vless://",
                "trojan://",
                "ss://",
                "ssr://",
                "hysteria2://",
            ]
        ):
            return False

        # 尝试base64解码
        decoded = base64.b64decode(content)
        # 检查解码后的内容是否包含协议头
        decoded_str = decoded.decode("utf-8", errors="ignore")
        if any(
            protocol in decoded_str
            for protocol in [
                "vmess://",
                "vless://",
                "trojan://",
                "ss://",
                "ssr://",
                "hysteria2://",
            ]
        ):
            return True

        return False
    except Exception:
        return False


def decode_base64_content(content):
    """解码base64内容"""
    try:
        decoded = base64.b64decode(content.strip())
        return decoded.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Base64解码失败: {e}")
        return content


def validate_node_content(content):
    """验证节点内容是否符合协议格式"""
    if not content:
        return False

    # 检查是否包含支持的协议头
    protocols = ["vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria2://"]
    return any(protocol in content for protocol in protocols)


async def fetch_subscription_content(url):
    """获取订阅链接的内容"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            content = response.text

            print(f"成功获取订阅内容，长度: {len(content)} 字符")

            # 判断是否为base64编码
            if is_base64(content):
                print("检测到Base64编码，正在解码...")
                content = decode_base64_content(content)
                print(f"解码后内容长度: {len(content)} 字符")

            # 验证内容是否包含有效节点
            if validate_node_content(content):
                return content
            else:
                print("内容不包含有效的节点信息")
                return None

    except Exception as e:
        print(f"获取订阅内容失败: {e}")
        return None


def save_nodes_to_file(content, website_name):
    """将节点内容追加到输出文件"""
    base_dir = Path(__file__).resolve().parent.parent
    out_file = base_dir / "sub_out.txt"

    try:
        # 标准化：按行拆分、去空格、移除所有空行
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        if not lines:
            print("无可保存的节点内容")
            return

        with open(out_file, "a", encoding="utf-8") as f:
            f.write(
                f"# {website_name} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            for ln in lines:
                f.write(ln + "\n")
        print(f"已将 {website_name} 的节点保存到 {out_file}")
    except Exception as e:
        print(f"保存节点到文件失败: {e}")


async def click_element_by_selector(page, selector):
    """通过选择器点击元素，支持XPath和CSS选择器"""
    try:
        # 判断是否为XPath（以//或/开头，或包含XPath特有语法）
        is_xpath = (
            selector.startswith(("/", "//"))
            or "contains(" in selector
            or "text()" in selector
            or "@" in selector
        )

        if is_xpath:
            # XPath选择器
            await page.wait_for_selector(f"xpath={selector}", timeout=10000)
            element = await page.query_selector(f"xpath={selector}")
        else:
            # CSS选择器
            await page.wait_for_selector(selector, timeout=10000)
            element = await page.query_selector(selector)

        if element:
            await element.click(force=True)
            return True
    except Exception as e:
        selector_type = "XPath" if is_xpath else "CSS"
        print(f"点击元素失败 ({selector_type}: {selector}): {e}")
    return False


async def search_content_by_rules(page, rules):
    """根据规则搜索页面内容"""
    try:
        content = await page.content()
        soup = BeautifulSoup(content, "html.parser")
        text_content = soup.get_text()

        # 分割规则（使用||分隔）
        search_terms = rules.split("||")

        for term in search_terms:
            if term.strip() in text_content:
                print(f"找到匹配内容: {term.strip()}")
                return True

        return False
    except Exception as e:
        print(f"搜索内容失败: {e}")
        return False


async def extract_urls_by_rules(page, rules, html_source=None):
    """根据规则提取URL"""
    try:
        content = await page.content()
        soup = BeautifulSoup(content, "html.parser")

        extracted_urls = []

        # 分割规则（使用||分隔）
        url_patterns = rules.split("||")

        for pattern in url_patterns:
            pattern = pattern.strip()

            # 将通配符模式转换为正则表达式
            if "*" in pattern:
                regex_pattern = pattern.replace("*", r"[^/\s]+")
                regex_pattern = regex_pattern.replace("http*://", r"https?://")

                print(f"使用正则模式匹配: {regex_pattern}")

                try:
                    text_content = str(soup)
                    matches = re.findall(regex_pattern, text_content)
                    extracted_urls.extend(matches)

                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag.get("href")
                        if re.search(regex_pattern, href):
                            if href.startswith("/"):
                                current_url = page.url
                                href = urljoin(current_url, href)
                            extracted_urls.append(href)

                    all_text = soup.get_text()
                    url_matches = re.findall(regex_pattern, all_text)
                    extracted_urls.extend(url_matches)

                except Exception as regex_error:
                    print(f"正则表达式处理失败 ({regex_pattern}): {regex_error}")

            elif pattern.startswith("http"):
                extracted_urls.append(pattern)
            else:
                try:
                    text_content = str(soup)
                    matches = re.findall(pattern, text_content)
                    extracted_urls.extend(matches)

                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag.get("href")
                        if re.search(pattern, href):
                            extracted_urls.append(href)

                except Exception as regex_error:
                    print(f"正则表达式处理失败 ({pattern}): {regex_error}")

        unique_urls = list(set(extracted_urls))
        valid_urls = []

        for url in unique_urls:
            if url and (url.startswith("http://") or url.startswith("https://")):
                valid_urls.append(url)

        return valid_urls

    except Exception as e:
        print(f"提取URL失败: {e}")
        return []


async def process_website_config(config):
    # 处理单个网站配置
    url = config.get("URL", "")
    website_name = urlparse(url).netloc

    print(f"\n{'='*50}")
    print(f"开始处理网站: {website_name}")
    print(f"URL: {url}")
    print(f"{'='*50}")

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=False)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
            page = await context.new_page()

            await page.goto(url, timeout=60000)
            await wait_for_page_ready(page)
            print(f"成功访问: {url}")
            subscription_urls = []
            steps = config.get("steps", [])
            for i, step in enumerate(steps, 1):
                step_type = step.get("type", "")
                step_id = step.get("id", f"{i:02d}")
                print(f"\n执行步骤 {step_id}: {step_type}")

                # 移除了dismiss步骤的处理逻辑

                if step_type == "click":
                    # 支持多种选择器格式
                    selectors = []

                    # 获取选择器列表
                    if "selectors" in step:
                        selectors = step["selectors"]
                    elif "xpath" in step:
                        xpath_list = step["xpath"]
                        if isinstance(xpath_list, str):
                            selectors = [xpath_list]
                        else:
                            selectors = xpath_list
                    elif "css" in step:
                        css_list = step["css"]
                        if isinstance(css_list, str):
                            selectors = [css_list]
                        else:
                            selectors = css_list

                    # 尝试每个选择器直到成功
                    success = False
                    for selector in selectors:
                        if selector:
                            success = await click_element_by_selector(page, selector)
                            if success:
                                await wait_for_page_ready(page)
                                print(f"点击成功，使用选择器: {selector}")
                                break
                            else:
                                print(f"选择器失败: {selector}")

                    if not success:
                        print("所有选择器都失败了")

                elif step_type == "search":
                    rules = step.get("rules", "")
                    if rules:
                        found = await search_content_by_rules(page, rules)
                        if found:
                            print("搜索成功（整页搜索）")
                        else:
                            print("未找到匹配内容（整页搜索）")

                elif step_type == "extract":
                    rules = step.get("rules", "")
                    if rules:
                        urls = await extract_urls_by_rules(
                            page, rules, html_source=None
                        )
                        subscription_urls.extend(urls)
                        print(f"提取到 {len(urls)} 个URL")
                        for u in urls:
                            print(f"  - {u}")

                elif step_type == "save":
                    target = step.get("target", step.get("rules", ""))
                    protocols = [
                        t.strip().replace("://", "")
                        for t in target.split("||")
                        if t.strip()
                    ]

                    if subscription_urls:
                        for sub_url in subscription_urls:
                            print(f"\n正在处理订阅链接: {sub_url}")
                            content = await fetch_subscription_content(sub_url)
                            if content:
                                nodes = extract_nodes_from_text(content, protocols)
                                if nodes:
                                    save_nodes_to_file("\n".join(nodes), website_name)
                                else:
                                    print("内容未提取到目标协议节点")
                            else:
                                print("获取订阅内容失败")
                    else:
                        page_html = await page.content()
                        soup = BeautifulSoup(page_html, "html.parser")
                        text = soup.get_text("\n")
                        nodes = extract_nodes_from_text(text, protocols)
                        if nodes:
                            save_nodes_to_file("\n".join(nodes), website_name)
                        else:
                            print("页面未提取到目标协议节点")

                elif step_type == "save":
                    # 按协议过滤并保存（打开订阅链接并自动解密）
                    target = step.get("target", step.get("rules", ""))
                    protocols = [
                        t.strip().replace("://", "")
                        for t in target.split("||")
                        if t.strip()
                    ]
                    if subscription_urls:
                        for sub_url in subscription_urls:
                            print(f"\n正在处理订阅链接: {sub_url}")
                            content = await fetch_subscription_content(sub_url)
                            if content:
                                nodes = extract_nodes_from_text(content, protocols)
                                if nodes:
                                    save_nodes_to_file("\n".join(nodes), website_name)
                                else:
                                    print("内容未提取到目标协议节点")
                            else:
                                print("获取订阅内容失败")
                    else:
                        # 无订阅链接时，直接从页面文本过滤并保存
                        page_html = await page.content()
                        soup = BeautifulSoup(page_html, "html.parser")
                        text = soup.get_text("\n")
                        nodes = extract_nodes_from_text(text, protocols)
                        if nodes:
                            save_nodes_to_file("\n".join(nodes), website_name)
                        else:
                            print("页面未提取到目标协议节点")

            await browser.close()

        except Exception as e:
            print(f"处理网站 {website_name} 时出错: {e}")
            try:
                await browser.close()
            except:
                pass


async def main():
    """主函数"""
    print("开始基于JSON配置爬取订阅链接...")

    # 清空输出文件
    try:
        with open("sub_out.txt", "w", encoding="utf-8") as f:
            f.write(f"# 订阅节点汇总\n")
            f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception as e:
        print(f"初始化输出文件失败: {e}")

    # 加载配置
    configs = load_config()
    if not configs:
        print("未找到有效配置，程序退出")
        return

    print(f"加载了 {len(configs)} 个网站配置")

    # 处理每个网站配置
    for i, config in enumerate(configs, 1):
        print(f"\n处理第 {i}/{len(configs)} 个网站配置")
        try:
            await process_website_config(config)
        except Exception as e:
            print(f"处理配置时出错: {e}")

    print(f"\n{'='*50}")
    print("所有网站处理完成！")
    print("节点已保存到 sub_out.txt 文件")
    print(f"{'='*50}")


# 新增：统一的节点提取工具函数（顶层可复用）
def extract_nodes_from_text(text, protocols):
    protocols = [p.strip() for p in protocols if p.strip()]
    if not protocols:
        protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2"]
    # 兼容 hy2 写法（部分站写成 hy2://）
    if "hysteria2" in protocols and "hy2" not in protocols:
        protocols.append("hy2")

    pattern = r"(?:%s)://[^\s]+" % "|".join(protocols)
    matches = re.findall(pattern, text)
    # 去重并保持插入顺序
    return list(dict.fromkeys(matches))


# 顶部新增：更稳健的页面加载等待
async def wait_for_page_ready(page):
    try:
        await page.wait_for_load_state("networkidle", timeout=45000)
    except Exception:
        try:
            await page.wait_for_load_state("load", timeout=15000)
        except Exception:
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
    await page.wait_for_timeout(300)


# 顶部新增：关闭广告/弹窗
if __name__ == "__main__":
    asyncio.run(main())
