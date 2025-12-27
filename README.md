# 算法助手日志解析器

用于解析[算法助手](https://github.com/Xposed-Modules-Repo/com.junge.algorithmaide)生成的日志文件, 将原始日志块转换为结构化数据类.

## 主要功能

### 解析所有日志块
`parse_all_blocks(log_path, limit=None, print_unparseable=False)` - 解析日志文件中的所有日志块, 返回结构化的 `LogBlock` 实例列表.

- 返回解析后的日志块列表
- 支持限制解析数量
- 可在解析过程中打印无法解析的块

### 查找无法解析的块
`print_all_unparseable_blocks(log_path, limit=None)` - 识别并打印所有无法解析的日志块, 用于发现新的日志类型.

- 按原因统计无法解析的块
- 格式化显示每个无法解析块的关键字段和完整内容
- 帮助识别需要添加解析支持的新日志类型

### 搜索结构化数据
`log_search.py` - 在解析后的结构化日志数据中搜索指定字符串.

- 支持完全匹配和子串匹配
- 搜索所有字段(包括参数、返回值、密钥、内容等)
- 显示匹配的块信息和上下文
- 支持限制解析数量以加快搜索速度

## 支持的日志类型

- 哈希算法: MD5, SHA1, SHA-256
- HMAC: HmacSHA256
- 加密算法: AES (CBC/ECB with PKCS5/PKCS7), RSA
- 数据库操作: 打开, 增(insert), 改(update), 删(delete), 查(query)
- 文件操作: 读入assets资源, 读入配置文件
- 方法Hook: 通用方法拦截

## 使用示例

### Python API

```python
from algorithmaide_log_parser import parse_all_blocks, print_all_unparseable_blocks

# 解析所有日志块
blocks = parse_all_blocks("log.txt", print_unparseable=True)

# 查找无法解析的块(新日志类型)
print_all_unparseable_blocks("log.txt", limit=100)
```

### 命令行搜索工具

```bash
# 完全匹配搜索
python log_search.py log.txt "search_string"

# 子串匹配搜索
python log_search.py log.txt "search_string" --substring

# 限制解析数量以加快搜索
python log_search.py log.txt "search_string" --limit 1000
```
