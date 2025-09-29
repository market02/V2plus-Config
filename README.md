# 🔒 V2plus-Config - 免费V2ray配置自动化管理系统 🌐
💻 这是一个自动化的V2ray配置文件收集管理、验证、分类和加密系统，提供高质量的免费V2ray配置文件，支持全球多地区节点分类和自动连通性检测，最后将加密后的配置文件上传到国内的gitcode和gitee，使得用户可以在没有代理的情况下也能获取配置文件。

![GitHub last commit](https://img.shields.io/github/last-commit/barry-far/V2ray-config.svg) [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/) [![GitHub stars](https://img.shields.io/github/stars/barry-far/V2ray-config.svg)](https://github.com/barry-far/V2ray-config/stargazers) [![Update Configs](https://github.com/barry-far/V2ray-config/actions/workflows/main.yml/badge.svg)](https://github.com/barry-far/V2ray-config/actions/workflows/main.yml) ![GitHub repo size](https://img.shields.io/github/repo-size/barry-far/V2ray-config)

## ✨ 功能特性

### 🔄 自动化配置管理
- **多源聚合**: 从多个开源项目自动收集V2ray配置
- **更新管理**: 判断url的可访问性，反写其状态到所在文件中的表格
- **智能去重**: 基于配置内容的智能去重算法
- **协议支持**: 支持vmess、vless、trojan、ss、ssr、hy2等主流协议
- **定时更新**: 每6小时自动更新配置文件

### 🌍 地理位置分类
- **智能分区**: 自动将节点按地理位置分类
- **US_CA**: 美国/加拿大节点
- **EU_JP_KR**: 欧洲/日本/韩国节点
- **Other**: 其他地区节点
- **IP地理定位**: 基于IP地址的精确地理位置识别

### 🔍 连通性检测
- **并行检测**: 高性能多线程连通性验证
- **超时控制**: 可配置的连接超时时间
- **有效性过滤**: 自动过滤无效和不可用的配置
- **实时状态**: 实时更新配置文件状态

### 🔐 安全加密
- **AES加密**: 使用AES-256-CBC加密算法
- **密钥管理**: 支持自定义加密密码
- **批量加密**: 自动加密所有配置文件
- **兼容性**: 与C#版本完全兼容的加密实现

### 📤 推送到 gitcode 和 gitee
- **自动同步**: 每6小时自动将加密后的配置文件同步到gitcode和gitee
- **镜像存储**: 国内用户可以直接从gitcode/gitee获取配置文件，无需代理

## 🔄 工作流程
1. **配置收集阶段** (`app.py`)
   - 从 `Resources.md` 加载配置源URL列表
   - 并行请求所有配置源
   - 自动检测base64编码和直接文本格式
   - 按协议类型解析和验证配置

2. **连通性检测阶段** (`connectivity_checker.py`)
   - 多线程并行检测配置连通性
   - 过滤无效和不可达的配置
   - 生成有效配置文件

3. **地理分类阶段** (`connectivity_checker.py`)
   - 基于IP地址进行地理位置查询
   - 按地区分类生成区域配置文件
   - 支持美国/加拿大、欧洲/日韩、其他地区

4. **加密处理阶段** (`encrypt_service.py`)
   - 使用AES-256-CBC算法加密所有配置文件
   - 生成加密版本供安全分发
   - 支持自定义加密密码

5. **自动化部署** (GitHub Actions)
   - 每6小时自动执行完整流程
   - 自动提交更新到仓库
   - 支持多平台镜像同步

## 📁 项目结构
├── .github/workflows/     # GitHub Actions 工作流
├── docs/                  # 项目文档
│   └── Resources.md       # 配置源管理
├── data/                  # 配置数据文件
├── src/                   # 源代码
│   ├── app.py            # 主程序
│   ├── connectivity_checker.py  # 连通性检测
│   ├── encrypt_service.py       # 加密服务
│   └── proxy_parsers.py         # 代理解析器
├── tests/                # 测试文件
└── requirements.txt      # 项目依赖

## 🚀 使用方法

### 📲 客户端配置

#### 💻 Windows 和 🐧 Linux
推荐使用 [Nekoray](https://github.com/MatsuriDayo/nekoray) 或 [V2rayN](https://github.com/2dust/v2rayN)：

**主配置订阅链接**:https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt

**区域分类订阅链接**:
- 美国/加拿大: `https://raw.githubusercontent.com/barry-far/V2ray-config/main/US_CA.txt`
- 欧洲/日韩: `https://raw.githubusercontent.com/barry-far/V2ray-config/main/EU_JP_KR.txt`
- 其他地区: `https://raw.githubusercontent.com/barry-far/V2ray-config/main/Other.txt`

#### 🤖 Android
推荐使用 [V2rayNG](https://github.com/2dust/v2rayNG) 或 [HiddifyNG](https://github.com/hiddify/HiddifyNG)

#### 🍎 Mac 和 📱 iOS
推荐使用 [Streisand](https://apps.apple.com/us/app/streisand/id6450534064) 或 [ShadowRocket](https://apps.apple.com/ca/app/shadowrocket/id932747118)

### 🛠️ 本地开发

#### 环境要求
- Python 3.11+
- pip 包管理器

#### 安装依赖
```bash
cd src
pip install -r requirements.txt
```

#### 运行程序
```bash
# 1. 收集和处理配置
python app.py

# 2. 连通性检测和分类
python connectivity_checker.py

# 3. 手动加密（可选）
python encrypt_service.py --input ../data/All_Configs_Sub_valid.txt
```

#### 环境变量配置
```bash
# 连接超时时间（秒）
export CONNECT_TIMEOUT=10

# 加密密码
export ENCRYPT_PASSWORD=your_password
```

## ⚙️ 配置文件

### 📋 配置源管理 (`docs/Resources.md`)
配置源列表采用Markdown表格格式：

```markdown
| available | responsibility | proxy count | updated every | url |
|:---------:|:--------------:|:-------------:|:-------------:|:----|
| ✅ | 5 | 68 | 4h | https://example.com/config.txt |
```

- `available`: 可用状态 (✅/❌)
- `responsibility`: 可靠性评分 (1-5)
- `proxy count`: 配置数量
- `updated every`: 更新频率
- `url`: 配置源URL

### 🔧 依赖包 (`requirements.txt`)
pybase64          # Base64编解码
requests          # HTTP请求
cryptography      # 加密算法
pytest            # 单元测试
proxyUtil         # 代理工具库
datetime          # 时间处理