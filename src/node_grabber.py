import asyncio
import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
import re
from urllib.parse import urljoin, urlparse


# 网站配置
WEBSITES = {
    "openclash": {
        "name": "OpenClash",
        "url": "https://openclash.cc/",
        "article_selectors": [
            "a[href*='free-node-subscribe-links']",  # 最新文章链接
            ".item-heading a",  # 文章标题链接
            "h3 a",  # 标题链接
        ],
        "subscription_patterns": [
            r"https://node\.openclash\.cc/uploads/\d+/\d+/\d+-\d+\.txt",  # v2ray订阅链接
        ],
        "subscription_selectors": [
            "a[href*='node.openclash.cc']",
        ],
    },
    "mlfenx": {
        "name": "米洛分享",
        "url": "https://www.mlfenx.com/freenode",
        "article_selectors": [
            ".post-title a",
            ".entry-title a",
            "h2 a",
        ],
        "subscription_patterns": [
            r"https://[^/]+/[^/]+\.txt",
        ],
        "subscription_selectors": [
            "a[href$='.txt']",
        ],
    },
    "ssrshare": {
        "name": "SSR分享网",
        "url": "https://ssrshare.net/",
        "article_selectors": [
            ".blog-sidebar-widget-post-title a",
            ".widget-content article a",
            ".post-title a",
        ],
        "subscription_patterns": [
            r"http://ssrshare\.cczzuu\.top/node/\d+-[a-z]+\.txt",  # 匹配 http://ssrshare.cczzuu.top/node/20251026-ssr.txt 格式
            r"https://ssrshare\.cczzuu\.top/node/\d+-[a-z]+\.txt",  # 同时支持 https
        ],
        "subscription_selectors": [
            "a[href*='ssrshare.cczzuu.top/node/']",  # 只匹配包含 ssrshare.cczzuu.top/node/ 的链接
            "a[href$='.txt'][href*='cczzuu.top']",  # .txt 结尾且包含 cczzuu.top 的链接
        ],
    },
    "dayssr": {
        "name": "节点分享网",
        "url": "https://www.dayssr.com/",
        "article_selectors": [
            ".post-title a",
            ".entry-title a",
            "h2 a",
        ],
        "subscription_patterns": [
            r"https://[^/]+/[^/]+\.txt",
        ],
        "subscription_selectors": [
            "a[href$='.txt']",
        ],
    },
    "surgenode": {
        "name": "Surge节点订阅",
        "url": "https://surgenode.github.io/",
        "article_selectors": [
            ".xclog-blog-title a",  # 根据图片中的HTML结构
            ".row .item a",
            "h3 a",
            "h2 a",
        ],
        "subscription_patterns": [
            r"https://node\.freeclashnode\.com/uploads/\d+/\d+/\d+-\d+\.txt",  # 根据图片中的链接格式
        ],
        "subscription_selectors": [
            "a[href*='freeclashnode.com']",
            "a[href*='node.freeclashnode.com']",
        ],
    },
    "v2rayfree": {
        "name": "V2ray免费节点",
        "url": "https://github.com/free-nodes/v2rayfree",
        "direct_scrape": True,
        "subscription_patterns": [
            r"https://raw\.githubusercontent\.com/free-nodes/v2rayfree/main/v2$",  # 精确匹配，避免重复
        ],
        "subscription_selectors": [
            "a[href='https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v2']",  # 精确匹配
        ],
    },
    "freenode": {
        "name": "Free Node订阅",
        "url": "https://github.com/Flikify/Free-Node",
        "direct_scrape": True,  # 直接爬取纯文本
        "subscription_patterns": [
            # 匹配 v2ray.txt 链接（支持带冒号或换行）
            r"https://raw\.githubusercontent\.com/a2470982985/getNode/main/v2ray\.txt",
            r"https://ghproxy\.com/https://raw\.githubusercontent\.com/a2470982985/getNode/main/v2ray\.txt",
            r"https://cdn\.jsdelivr\.net/gh/a2470982985/getNode@main/v2ray\.txt",
        ],
        "subscription_selectors": [],
    },
}


async def get_latest_article_url(page, site_config, base_url):
    """获取网站最新文章的URL"""
    print(f"正在查找 {site_config['name']} 的最新文章...")

    # 尝试不同的选择器来找到最新文章
    for selector in site_config["article_selectors"]:
        try:
            articles = await page.query_selector_all(selector)
            if articles:
                # 获取第一篇文章的链接
                article_url = await articles[0].get_attribute("href")
                if article_url:
                    # 处理相对链接
                    if not article_url.startswith("http"):
                        article_url = urljoin(base_url, article_url)
                    print(f"找到最新文章: {article_url}")
                    return article_url
        except Exception as e:
            print(f"选择器 {selector} 失败: {e}")
            continue

    # 如果没有找到文章链接，使用BeautifulSoup解析
    try:
        html_content = await page.content()
        soup = BeautifulSoup(html_content, "html.parser")

        for selector in site_config["article_selectors"]:
            # 转换CSS选择器为BeautifulSoup格式
            if selector.startswith("."):
                elements = soup.select(selector)
            else:
                elements = soup.select(selector)

            if elements:
                href = elements[0].get("href")
                if href:
                    if not href.startswith("http"):
                        href = urljoin(base_url, href)
                    print(f"通过BeautifulSoup找到文章: {href}")
                    return href
    except Exception as e:
        print(f"BeautifulSoup解析失败: {e}")

    print(f"未找到 {site_config['name']} 的最新文章，将在首页查找订阅链接")
    return base_url


async def extract_subscription_links(page, site_config, article_url):
    """从文章页面提取订阅链接"""
    print(f"正在从 {article_url} 提取订阅链接...")

    subscription_links = {}
    seen_urls = set()  # 用于去重

    try:
        # 获取页面内容
        html_content = await page.content()
        soup = BeautifulSoup(html_content, "html.parser")

        # 方法1: 通过选择器查找链接
        for selector in site_config.get("subscription_selectors", []):
            try:
                links = soup.select(selector)
                for link in links:
                    href = link.get("href")
                    if href and href not in seen_urls:
                        seen_urls.add(href)
                        link_text = (
                            link.get_text().strip()
                            or f"订阅链接_{len(subscription_links)+1}"
                        )
                        subscription_links[link_text] = href
            except Exception as e:
                print(f"选择器 {selector} 提取失败: {e}")

        # 方法2: 通过正则表达式查找链接
        for pattern in site_config.get("subscription_patterns", []):
            try:
                matches = re.findall(pattern, html_content)
                for match in matches:
                    if match and match not in seen_urls:
                        seen_urls.add(match)
                        link_name = f"订阅链接_{len(subscription_links)+1}"
                        subscription_links[link_name] = match
            except Exception as e:
                print(f"正则表达式 {pattern} 提取失败: {e}")

        # 方法3: 查找所有包含常见订阅链接特征的链接
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href")
            if any(
                keyword in href.lower()
                for keyword in [".txt", "subscribe", "sub", "node"]
            ):
                if any(
                    domain in href
                    for domain in [
                        "github.io",
                        "githubusercontent",
                        "openclash.cc",
                        "cczzuu.top",
                    ]
                ):
                    # 只匹配.txt文件，排除其他格式
                    if href.endswith(".txt") and href not in seen_urls:
                        seen_urls.add(href)
                        link_text = (
                            a_tag.get_text().strip()
                            or f"订阅链接_{len(subscription_links)+1}"
                        )
                        subscription_links[link_text] = href

        # 方法4: 从文本中提取链接（针对某些网站直接在文本中显示链接）
        text_content = soup.get_text()
        # 使用更精确的正则表达式，避免链接粘连
        url_pattern = r'https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9./_-]*\.txt(?=\s|$|https?://|[<>"\'()]|[^\w.-])'
        text_urls = re.findall(url_pattern, text_content)
        for url in text_urls:
            # 简单验证：只保留.txt文件且来自可信域名
            if (
                url.endswith(".txt")
                and any(
                    domain in url
                    for domain in [
                        "openclash.cc",
                        "freeclashnode.com",
                        "cczzuu.top",
                        "github.io",
                        "githubusercontent.com",
                        "ghproxy.com",
                        "jsdelivr.net",
                    ]
                )
                and url not in seen_urls
            ):
                seen_urls.add(url)
                subscription_links[f"文本链接_{len(subscription_links)+1}"] = url

        # 方法5: 从HTML源码中分割提取链接（处理粘连问题）
        html_text = str(soup)
        # 先找到所有可能的链接模式，然后分割
        potential_links = re.findall(
            r"https://[a-zA-Z0-9.-]+/[a-zA-Z0-9./_-]*\.txt", html_text
        )
        for url in potential_links:
            # 简单验证：只保留.txt文件且来自可信域名，避免重复
            if (
                url.endswith(".txt")
                and any(
                    domain in url
                    for domain in [
                        "openclash.cc",
                        "freeclashnode.com",
                        "cczzuu.top",
                        "github.io",
                        "githubusercontent.com",
                        "ghproxy.com",
                        "jsdelivr.net",
                    ]
                )
                and url not in seen_urls
            ):
                seen_urls.add(url)
                subscription_links[f"HTML链接_{len(subscription_links)+1}"] = url

    except Exception as e:
        print(f"提取订阅链接时出错: {e}")

    return subscription_links


async def scrape_website(site_key, site_config):
    """爬取单个网站的订阅链接"""
    print(f"\n{'='*50}")
    print(f"开始爬取 {site_config['name']} ({site_config['url']})")
    print(f"{'='*50}")

    subscription_links = {}

    async with async_playwright() as p:
        try:
            # 启动浏览器
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
            page = await context.new_page()

            # 访问网站首页
            await page.goto(site_config["url"], timeout=30000)
            print(f"已访问 {site_config['name']} 首页")

            # 等待页面加载
            await page.wait_for_load_state("networkidle", timeout=30000)

            # 检查是否为直接爬取模式
            if site_config.get("direct_scrape", False):
                # 直接从主页提取订阅链接
                subscription_links = await extract_subscription_links(
                    page, site_config, site_config["url"]
                )
            else:
                # 获取最新文章URL
                latest_article_url = await get_latest_article_url(
                    page, site_config, site_config["url"]
                )

                # 如果找到了不同的文章URL，访问该页面
                if latest_article_url != site_config["url"]:
                    await page.goto(latest_article_url, timeout=30000)
                    await page.wait_for_load_state("networkidle", timeout=30000)
                    print(f"已访问最新文章页面")

                # 提取订阅链接
                subscription_links = await extract_subscription_links(
                    page, site_config, latest_article_url
                )

            # 关闭浏览器
            await browser.close()

        except Exception as e:
            print(f"爬取 {site_config['name']} 时出错: {e}")
            try:
                await browser.close()
            except:
                pass

    return site_key, subscription_links


async def get_all_subscription_links():
    """获取所有网站的订阅链接"""
    print("开始爬取多个网站的订阅链接...")

    all_links = {}

    # 并发爬取所有网站
    tasks = []
    for site_key, site_config in WEBSITES.items():
        task = scrape_website(site_key, site_config)
        tasks.append(task)

    # 等待所有任务完成
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理结果
    for result in results:
        if isinstance(result, Exception):
            print(f"任务执行出错: {result}")
        else:
            site_key, links = result
            if links:
                all_links[site_key] = links
                print(f"\n{WEBSITES[site_key]['name']} 找到 {len(links)} 个订阅链接:")
                for name, url in links.items():
                    print(f"  {name}: {url}")
            else:
                print(f"\n{WEBSITES[site_key]['name']} 未找到订阅链接")

    # 保存所有订阅链接到文件
    if all_links:
        with open("subscription_links.txt", "w", encoding="utf-8") as f:
            f.write("# 订阅链接汇总\n")
            f.write(f"# 更新时间: {asyncio.get_event_loop().time()}\n\n")

            for site_key, links in all_links.items():
                f.write(f"## {WEBSITES[site_key]['name']}\n")
                for name, url in links.items():
                    f.write(f"{name}: {url}\n")
                f.write("\n")

        print(f"\n所有订阅链接已保存到 subscription_links.txt")
        print(f"总共从 {len(all_links)} 个网站获取了订阅链接")
    else:
        print("\n未找到任何订阅链接")

    return all_links


async def main():
    """主函数"""
    await get_all_subscription_links()


if __name__ == "__main__":
    asyncio.run(main())
