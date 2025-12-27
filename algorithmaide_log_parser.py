#!/usr/bin/env python3
"""
Log parser module
Parse different log types into structured data classes
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class LogType(Enum):
    """Supported log types"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA1_FULL = "sha-1"
    SHA256 = "sha-256"
    HMAC_SHA256 = "hmacsha256"
    AES_CBC_PKCS5 = "aes/cbc/pkcs5padding"
    AES_CBC_PKCS7 = "aes/cbc/pkcs7padding"
    AES_ECB_PKCS5 = "aes/ecb/pkcs5padding"
    RSA_ECB_PKCS1 = "rsa/ecb/pkcs1padding"
    DB_OPEN = "打开数据库"
    DB_INSERT = "增(insert)"
    DB_UPDATE = "改(update)"
    DB_DELETE = "删(delete)"
    DB_QUERY = "查(query)"
    READ_ASSETS = "读入assets资源"
    READ_CONFIG = "读入配置文件"


@dataclass
class LogBlock:
    """Base class for all log blocks"""
    timestamp: str
    log_type: str
    stack_trace: List[str] = field(default_factory=list)

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type}"


@dataclass
class HashLogBlock(LogBlock):
    """Hash algorithms (MD5, SHA1, SHA-1, SHA-256)"""
    content_string: Optional[str] = None
    content_base64: Optional[str] = None
    content_hex: Optional[str] = None
    result_string: Optional[str] = None
    result_base64: Optional[str] = None
    result_hex: Optional[str] = None

    def __repr__(self):
        preview = self.content_string[:50] if self.content_string else 'N/A'
        return f"[{self.timestamp}] {self.log_type} - Content: {preview}..."


@dataclass
class HmacLogBlock(LogBlock):
    """HMAC algorithms (HmacSHA256)"""
    key_type: Optional[str] = None
    key_string: Optional[str] = None
    key_base64: Optional[str] = None
    key_hex: Optional[str] = None
    content_string: Optional[str] = None
    content_base64: Optional[str] = None
    content_hex: Optional[str] = None
    result_string: Optional[str] = None
    result_base64: Optional[str] = None
    result_hex: Optional[str] = None

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - Key: {self.key_hex[:32] if self.key_hex else 'N/A'}..."


@dataclass
class AesCbcLogBlock(LogBlock):
    """AES CBC mode (PKCS5/PKCS7 padding)"""
    key_type: Optional[str] = None
    key_string: Optional[str] = None
    key_base64: Optional[str] = None
    key_hex: Optional[str] = None
    iv_string: Optional[str] = None
    iv_base64: Optional[str] = None
    iv_hex: Optional[str] = None
    content_string: Optional[str] = None
    content_base64: Optional[str] = None
    content_hex: Optional[str] = None
    result_string: Optional[str] = None
    result_base64: Optional[str] = None
    result_hex: Optional[str] = None
    operation: Optional[str] = None  # encrypt or decrypt

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - Op: {self.operation}, Key: {self.key_hex[:32] if self.key_hex else 'N/A'}..."


@dataclass
class AesEcbLogBlock(LogBlock):
    """AES ECB mode"""
    key_type: Optional[str] = None
    key_string: Optional[str] = None
    key_base64: Optional[str] = None
    key_hex: Optional[str] = None
    content_string: Optional[str] = None
    content_base64: Optional[str] = None
    content_hex: Optional[str] = None
    result_string: Optional[str] = None
    result_base64: Optional[str] = None
    result_hex: Optional[str] = None
    operation: Optional[str] = None  # encrypt or decrypt

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - Op: {self.operation}, Key: {self.key_hex[:32] if self.key_hex else 'N/A'}..."


@dataclass
class RsaLogBlock(LogBlock):
    """RSA encryption"""
    key_type: Optional[str] = None
    key_string: Optional[str] = None
    key_base64: Optional[str] = None
    key_hex: Optional[str] = None
    content_string: Optional[str] = None
    content_base64: Optional[str] = None
    content_hex: Optional[str] = None
    result_string: Optional[str] = None
    result_base64: Optional[str] = None
    result_hex: Optional[str] = None
    operation: Optional[str] = None  # encrypt or decrypt

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - Op: {self.operation}, Key: {self.key_hex[:32] if self.key_hex else 'N/A'}..."


@dataclass
class DatabaseLogBlock(LogBlock):
    """Database operations (open, insert, update, delete, query)"""
    params: Dict[str, str] = field(default_factory=dict)
    return_value: Optional[str] = None

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - Params: {len(self.params)}, Return: {self.return_value}"


@dataclass
class ReadAssetsLogBlock(LogBlock):
    """Read Assets resource"""
    target_file: Optional[str] = None
    return_value: Optional[str] = None

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - File: {self.target_file}"


@dataclass
class ReadConfigLogBlock(LogBlock):
    """Read config file (SharedPreferences)"""
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    config_file: Optional[str] = None
    return_value: Optional[str] = None

    def __repr__(self):
        return f"[{self.timestamp}] {self.log_type} - Config: {self.config_file}"


@dataclass
class MethodHookLogBlock(LogBlock):
    """Generic method hook"""
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    params: List[Dict[str, str]] = field(default_factory=list)  # [{type, value}]
    return_type: Optional[str] = None
    return_value: Optional[str] = None

    def __repr__(self):
        return f"[{self.timestamp}] {self.class_name}.{self.method_name} - Params: {len(self.params)}"


LOG_TYPE_MAP: Dict[str, type] = {
    LogType.MD5.value: HashLogBlock,
    LogType.SHA1.value: HashLogBlock,
    LogType.SHA1_FULL.value: HashLogBlock,
    LogType.SHA256.value: HashLogBlock,
    LogType.HMAC_SHA256.value: HmacLogBlock,
    LogType.AES_CBC_PKCS5.value: AesCbcLogBlock,
    LogType.AES_CBC_PKCS7.value: AesCbcLogBlock,
    LogType.AES_ECB_PKCS5.value: AesEcbLogBlock,
    LogType.RSA_ECB_PKCS1.value: RsaLogBlock,
    LogType.DB_OPEN.value: DatabaseLogBlock,
    LogType.DB_INSERT.value: DatabaseLogBlock,
    LogType.DB_UPDATE.value: DatabaseLogBlock,
    LogType.DB_DELETE.value: DatabaseLogBlock,
    LogType.DB_QUERY.value: DatabaseLogBlock,
    LogType.READ_ASSETS.value: ReadAssetsLogBlock,
    LogType.READ_CONFIG.value: ReadConfigLogBlock,
    "method_hook": MethodHookLogBlock,
}

# Filter keywords for stack traces
STACK_FILTER_KEYWORDS = [
    'JungeSpoxedBridge',
    'org.lsposed.lspd.impl.LSPosedBridge',
    'LSPHooker_',
    'XC_MethodReplacement'
]


def print_unparseable_block(block_text: str, reason: str = "Unknown"):
    """
    Format and print unparseable log block for debugging

    Args:
        block_text: Raw log block text
        reason: Reason why parsing failed
    """
    lines = block_text.strip().split('\n')
    
    print("=" * 80)
    print(f"UNPARSEABLE BLOCK - Reason: {reason}")
    print("=" * 80)
    
    timestamp = None
    log_type = None
    class_name = None
    method_name = None
    key_fields = {}
    in_stack = False
    
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith("时间:"):
            timestamp = line_stripped.split("时间:", 1)[1].strip()
            print(f"Timestamp: {timestamp}")
        elif line_stripped.startswith("日志名称:"):
            log_type = line_stripped.split("日志名称:", 1)[1].strip()
            print(f"Log Type: {log_type} (NOT SUPPORTED)")
        elif line_stripped.startswith("类名:"):
            class_name = line_stripped.split("类名:", 1)[1].strip()
            print(f"Class: {class_name}")
        elif line_stripped.startswith("方法名:"):
            method_name = line_stripped.split("方法名:", 1)[1].strip()
            print(f"Method: {method_name}")
        elif line_stripped.startswith("调用堆栈："):
            in_stack = True
        elif ":" in line_stripped and not in_stack and len(line_stripped) < 200:
            parts = line_stripped.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                if len(value) > 100:
                    value = value[:100] + "..."
                key_fields[key] = value
    
    if key_fields:
        print("\nKey Fields:")
        for key, value in key_fields.items():
            print(f"  {key}: {value}")
    
    print("\nFull Content:")
    print("-" * 80)
    for i, line in enumerate(lines, 1):
        print(f"{i:4d} | {line}")
    print("-" * 80)
    print()


def parse_block(block_text: str, print_unparseable: bool = False) -> Optional[LogBlock]:
    """
    Parse a single log block into structured data class

    Args:
        block_text: Raw log block text
        print_unparseable: If True, print unparseable blocks

    Returns:
        LogBlock subclass instance or None if parsing fails
    """
    lines = block_text.strip().split('\n')
    if len(lines) < 2:
        if print_unparseable:
            print_unparseable_block(block_text, "Too few lines")
        return None

    timestamp = None
    for line in lines:
        if line.startswith("时间:"):
            timestamp = line.split("时间:")[1].strip()
            break

    if not timestamp:
        if print_unparseable:
            print_unparseable_block(block_text, "Missing timestamp")
        return None

    log_type = None
    class_name = None
    method_name = None
    
    for line in lines:
        if line.startswith("日志名称:"):
            log_type = line.split("日志名称:")[1].strip()
            break
        elif line.startswith("类名:"):
            class_name = line.split("类名:")[1].strip()
        elif line.startswith("方法名:"):
            method_name = line.split("方法名:")[1].strip()
            if method_name == "读入配置文件":
                log_type = "读入配置文件"
            break

    # Custom method hook
    if not log_type and class_name and method_name:
        log_type = "method_hook"

    if not log_type:
        if print_unparseable:
            print_unparseable_block(block_text, "Missing log type")
        return None

    log_type_normalized = log_type.lower()

    if log_type_normalized not in LOG_TYPE_MAP:
        if print_unparseable:
            print_unparseable_block(block_text, f"Unsupported log type: {log_type}")
        return None

    log_class = LOG_TYPE_MAP[log_type_normalized]

    stack_trace = []
    in_stack = False
    for line in lines:
        if line.startswith("调用堆栈："):
            in_stack = True
            continue
        if in_stack and line.strip():
            frame = line.strip()
            if not any(keyword in frame for keyword in STACK_FILTER_KEYWORDS):
                stack_trace.append(frame)

    log_block = log_class(timestamp=timestamp, log_type=log_type, stack_trace=stack_trace)

    # Parse type-specific fields
    if isinstance(log_block, HashLogBlock):
        _parse_hash_fields(lines, log_block)
    elif isinstance(log_block, HmacLogBlock):
        _parse_hmac_fields(lines, log_block)
    elif isinstance(log_block, AesCbcLogBlock):
        _parse_aes_cbc_fields(lines, log_block)
    elif isinstance(log_block, AesEcbLogBlock):
        _parse_aes_ecb_fields(lines, log_block)
    elif isinstance(log_block, RsaLogBlock):
        _parse_rsa_fields(lines, log_block)
    elif isinstance(log_block, DatabaseLogBlock):
        _parse_db_fields(lines, log_block)
    elif isinstance(log_block, ReadAssetsLogBlock):
        _parse_read_assets_fields(lines, log_block)
    elif isinstance(log_block, ReadConfigLogBlock):
        _parse_read_config_fields(lines, log_block)
    elif isinstance(log_block, MethodHookLogBlock):
        _parse_method_hook_fields(lines, log_block)

    return log_block


def _parse_hash_fields(lines: List[str], log_block: HashLogBlock):
    """Parse hash algorithm fields (MD5, SHA1, SHA-1, SHA-256)"""
    for line in lines:
        line = line.strip()
        if line.startswith("签名内容(String):"):
            log_block.content_string = line.split("签名内容(String):")[1].strip()
        elif line.startswith("签名内容(Base64):"):
            log_block.content_base64 = line.split("签名内容(Base64):")[1].strip()
        elif line.startswith("签名内容(Hex):"):
            log_block.content_hex = line.split("签名内容(Hex):")[1].strip()
        elif line.startswith("签名结果(String):"):
            log_block.result_string = line.split("签名结果(String):")[1].strip()
        elif line.startswith("签名结果(Base64):"):
            log_block.result_base64 = line.split("签名结果(Base64):")[1].strip()
        elif line.startswith("签名结果(Hex):"):
            log_block.result_hex = line.split("签名结果(Hex):")[1].strip()


def _parse_hmac_fields(lines: List[str], log_block: HmacLogBlock):
    """Parse HMAC fields (HmacSHA256)"""
    for line in lines:
        line = line.strip()
        if line.startswith("key类型:"):
            log_block.key_type = line.split("key类型:")[1].strip()
        elif line.startswith("秘钥(String):"):
            log_block.key_string = line.split("秘钥(String):")[1].strip()
        elif line.startswith("秘钥(Base64):"):
            log_block.key_base64 = line.split("秘钥(Base64):")[1].strip()
        elif line.startswith("秘钥(Hex):"):
            log_block.key_hex = line.split("秘钥(Hex):")[1].strip()
        elif line.startswith("内容(String):"):
            log_block.content_string = line.split("内容(String):")[1].strip()
        elif line.startswith("内容(Base64):"):
            log_block.content_base64 = line.split("内容(Base64):")[1].strip()
        elif line.startswith("内容(Hex):"):
            log_block.content_hex = line.split("内容(Hex):")[1].strip()
        elif line.startswith("结果(String):"):
            log_block.result_string = line.split("结果(String):")[1].strip()
        elif line.startswith("结果(Base64):"):
            log_block.result_base64 = line.split("结果(Base64):")[1].strip()
        elif line.startswith("结果(Hex):"):
            log_block.result_hex = line.split("结果(Hex):")[1].strip()


def _parse_aes_cbc_fields(lines: List[str], log_block: AesCbcLogBlock):
    """Parse AES CBC mode fields"""
    for line in lines:
        line = line.strip()
        if line.startswith("key类型:"):
            log_block.key_type = line.split("key类型:")[1].strip()
        elif line.startswith("加密密钥(String):") or line.startswith("解密密钥(String):"):
            log_block.key_string = line.split("):")[1].strip()
            log_block.operation = "encrypt" if "加密" in line else "decrypt"
        elif line.startswith("加密密钥(Base64):") or line.startswith("解密密钥(Base64):"):
            log_block.key_base64 = line.split("):")[1].strip()
        elif line.startswith("加密密钥(Hex):") or line.startswith("解密密钥(Hex):"):
            log_block.key_hex = line.split("):")[1].strip()
        elif line.startswith("加密Iv(String):") or line.startswith("解密Iv(String):"):
            log_block.iv_string = line.split("):")[1].strip()
        elif line.startswith("加密Iv(Base64):") or line.startswith("解密Iv(Base64):"):
            log_block.iv_base64 = line.split("):")[1].strip()
        elif line.startswith("加密Iv(Hex):") or line.startswith("解密Iv(Hex):"):
            log_block.iv_hex = line.split("):")[1].strip()
        elif line.startswith("加密内容(String):") or line.startswith("解密内容(String):"):
            log_block.content_string = line.split("):")[1].strip()
        elif line.startswith("加密内容(Base64):") or line.startswith("解密内容(Base64):"):
            log_block.content_base64 = line.split("):")[1].strip()
        elif line.startswith("加密内容(Hex):") or line.startswith("解密内容(Hex):"):
            log_block.content_hex = line.split("):")[1].strip()
        elif line.startswith("加密结果(String):") or line.startswith("解密结果(String):"):
            log_block.result_string = line.split("):")[1].strip()
        elif line.startswith("加密结果(Base64):") or line.startswith("解密结果(Base64):"):
            log_block.result_base64 = line.split("):")[1].strip()
        elif line.startswith("加密结果(Hex):") or line.startswith("解密结果(Hex):"):
            log_block.result_hex = line.split("):")[1].strip()


def _parse_aes_ecb_fields(lines: List[str], log_block: AesEcbLogBlock):
    """Parse AES ECB mode fields"""
    for line in lines:
        line = line.strip()
        if line.startswith("key类型:"):
            log_block.key_type = line.split("key类型:")[1].strip()
        elif line.startswith("加密密钥(String):") or line.startswith("解密密钥(String):"):
            log_block.key_string = line.split("):")[1].strip()
            log_block.operation = "encrypt" if "加密" in line else "decrypt"
        elif line.startswith("加密密钥(Base64):") or line.startswith("解密密钥(Base64):"):
            log_block.key_base64 = line.split("):")[1].strip()
        elif line.startswith("加密密钥(Hex):") or line.startswith("解密密钥(Hex):"):
            log_block.key_hex = line.split("):")[1].strip()
        elif line.startswith("加密内容(String):") or line.startswith("解密内容(String):"):
            log_block.content_string = line.split("):")[1].strip()
        elif line.startswith("加密内容(Base64):") or line.startswith("解密内容(Base64):"):
            log_block.content_base64 = line.split("):")[1].strip()
        elif line.startswith("加密内容(Hex):") or line.startswith("解密内容(Hex):"):
            log_block.content_hex = line.split("):")[1].strip()
        elif line.startswith("加密结果(String):") or line.startswith("解密结果(String):"):
            log_block.result_string = line.split("):")[1].strip()
        elif line.startswith("加密结果(Base64):") or line.startswith("解密结果(Base64):"):
            log_block.result_base64 = line.split("):")[1].strip()
        elif line.startswith("加密结果(Hex):") or line.startswith("解密结果(Hex):"):
            log_block.result_hex = line.split("):")[1].strip()


def _parse_rsa_fields(lines: List[str], log_block: RsaLogBlock):
    """Parse RSA encryption fields"""
    for line in lines:
        line = line.strip()
        if line.startswith("key类型:"):
            log_block.key_type = line.split("key类型:")[1].strip()
        elif line.startswith("加密密钥(String):") or line.startswith("解密密钥(String):"):
            log_block.key_string = line.split("):")[1].strip()
            log_block.operation = "encrypt" if "加密" in line else "decrypt"
        elif line.startswith("加密密钥(Base64):") or line.startswith("解密密钥(Base64):"):
            log_block.key_base64 = line.split("):")[1].strip()
        elif line.startswith("加密密钥(Hex):") or line.startswith("解密密钥(Hex):"):
            log_block.key_hex = line.split("):")[1].strip()
        elif line.startswith("加密内容(String):") or line.startswith("解密内容(String):"):
            log_block.content_string = line.split("):")[1].strip()
        elif line.startswith("加密内容(Base64):") or line.startswith("解密内容(Base64):"):
            log_block.content_base64 = line.split("):")[1].strip()
        elif line.startswith("加密内容(Hex):") or line.startswith("解密内容(Hex):"):
            log_block.content_hex = line.split("):")[1].strip()
        elif line.startswith("加密结果(String):") or line.startswith("解密结果(String):"):
            log_block.result_string = line.split("):")[1].strip()
        elif line.startswith("加密结果(Base64):") or line.startswith("解密结果(Base64):"):
            log_block.result_base64 = line.split("):")[1].strip()
        elif line.startswith("加密结果(Hex):") or line.startswith("解密结果(Hex):"):
            log_block.result_hex = line.split("):")[1].strip()



def _parse_db_fields(lines: List[str], log_block: DatabaseLogBlock):
    """Parse database operation fields"""
    for line in lines:
        line = line.strip()
        if line.startswith("表名:"):
            log_block.params["table_name"] = line.split("表名:")[1].strip()
        elif line.startswith("数据:"):
            log_block.params["data"] = line.split("数据:")[1].strip()
        elif line.startswith("设置项:"):
            log_block.params["set_clause"] = line.split("设置项:")[1].strip()
        elif line.startswith("条件表达式:"):
            log_block.params["where_clause"] = line.split("条件表达式:")[1].strip()
        elif line.startswith("条件值:"):
            log_block.params["where_args"] = line.split("条件值:")[1].strip()
        elif line.startswith("参数") and ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                param_name = parts[0].strip()
                param_value = parts[1].strip()
                log_block.params[param_name] = param_value
        elif line.startswith("返回值") and ":" in line:
            log_block.return_value = line.split(":", 1)[1].strip()


def _parse_read_assets_fields(lines: List[str], log_block: ReadAssetsLogBlock):
    """Parse read assets fields"""
    for line in lines:
        line = line.strip()
        if line.startswith("目标文件:"):
            log_block.target_file = line.split("目标文件:")[1].strip()
        elif line.startswith("返回值"):
            log_block.return_value = line.split(":", 1)[1].strip()


def _parse_read_config_fields(lines: List[str], log_block: ReadConfigLogBlock):
    """Parse read config file fields"""
    for line in lines:
        line = line.strip()
        if line.startswith("类名:"):
            log_block.class_name = line.split("类名:")[1].strip()
        elif line.startswith("方法名:"):
            log_block.method_name = line.split("方法名:")[1].strip()
        elif line.startswith("配置文件名：:"):
            log_block.config_file = line.split("配置文件名：:")[1].strip()
        elif line.startswith("返回值"):
            log_block.return_value = line.split(":", 1)[1].strip()


def _parse_method_hook_fields(lines: List[str], log_block: MethodHookLogBlock):
    """Parse generic method hook fields"""
    import re
    
    current_param_idx = -1
    current_param = None
    
    for line in lines:
        line = line.strip()
        if line.startswith("类名:"):
            log_block.class_name = line.split("类名:")[1].strip()
        elif line.startswith("方法名:"):
            log_block.method_name = line.split("方法名:")[1].strip()
        elif re.match(r'^参数\d+\(', line):
            # e.g., "参数1(ContextImpl):android.app.ContextImpl@a32ba6"
            # or "参数4(String):{"preconnect":1}"
            # or "参数4(Base64):eyJwcmVjb25uZWN0IjoxfQ=="
            match = re.match(r'^参数(\d+)\(([^)]+)\):(.*)$', line)
            if match:
                param_idx = int(match.group(1))
                param_type = match.group(2).strip()
                param_value = match.group(3).strip()
                
                # Check if it's a new param or additional format of current param
                if param_idx != current_param_idx:
                    # New parameter
                    if current_param:
                        log_block.params.append(current_param)
                    current_param_idx = param_idx
                    current_param = {
                        'type': param_type,
                        'value': param_value
                    }
                else:
                    # Additional format for same param (Base64/Hex)
                    if current_param:
                        format_key = f'{param_type.lower()}_value'
                        current_param[format_key] = param_value
                        
        elif line.startswith("返回值("):
            # Save last param if exists
            if current_param:
                log_block.params.append(current_param)
                current_param = None
                
            # e.g., "返回值(void):null"
            match = re.match(r'^返回值\(([^)]+)\):(.*)$', line)
            if match:
                log_block.return_type = match.group(1).strip()
                log_block.return_value = match.group(2).strip()
    
    # Don't forget last param if we didn't encounter return value
    if current_param:
        log_block.params.append(current_param)




def parse_log_blocks(log_path: str) -> List[str]:
    """
    Split log file into individual blocks

    Args:
        log_path: Path to log file

    Returns:
        List of raw log block texts
    """
    with open(log_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    blocks = []
    current_block = []
    
    for line in content.split('\n'):
        if line.startswith("时间:"):
            if current_block:
                blocks.append('\n'.join(current_block))
            current_block = [line]
        elif current_block:
            current_block.append(line)
    
    if current_block:
        blocks.append('\n'.join(current_block))
    
    return blocks


def parse_all_blocks(log_path: str, limit: Optional[int] = None, print_unparseable: bool = False) -> List[LogBlock]:
    """
    Parse all log blocks from file

    Args:
        log_path: Path to log file
        limit: Optional limit on number of blocks to parse
        print_unparseable: If True, print unparseable blocks

    Returns:
        List of LogBlock instances
    """
    blocks_text = parse_log_blocks(log_path)

    if limit:
        blocks_text = blocks_text[:limit]

    parsed_blocks = []
    unparseable_count = 0
    
    for block_text in blocks_text:
        log_block = parse_block(block_text, print_unparseable=print_unparseable)
        if log_block:
            parsed_blocks.append(log_block)
        else:
            unparseable_count += 1
    
    if print_unparseable and unparseable_count > 0:
        print(f"\nTotal unparseable blocks: {unparseable_count} / {len(blocks_text)}")
    
    return parsed_blocks


def print_all_unparseable_blocks(log_path: str, limit: Optional[int] = None):
    """
    Find and print all unparseable blocks from log file

    Args:
        log_path: Path to log file
        limit: Optional limit on number of blocks to check
    """
    blocks_text = parse_log_blocks(log_path)
    
    if limit:
        blocks_text = blocks_text[:limit]
    
    unparseable_blocks = []
    
    for block_text in blocks_text:
        lines = block_text.strip().split('\n')
        if len(lines) < 2:
            unparseable_blocks.append((block_text, "Too few lines"))
            continue
        
        timestamp = None
        for line in lines:
            if line.startswith("时间:"):
                timestamp = line.split("时间:")[1].strip()
                break
        
        if not timestamp:
            unparseable_blocks.append((block_text, "Missing timestamp"))
            continue
        
        log_type = None
        class_name = None
        method_name = None
        
        for line in lines:
            if line.startswith("日志名称:"):
                log_type = line.split("日志名称:")[1].strip()
                break
            elif line.startswith("类名:"):
                class_name = line.split("类名:")[1].strip()
            elif line.startswith("方法名:"):
                method_name = line.split("方法名:")[1].strip()
                if method_name == "读入配置文件":
                    log_type = "读入配置文件"
                break
        
        if not log_type and class_name and method_name:
            log_type = "method_hook"
        
        if not log_type:
            unparseable_blocks.append((block_text, "Missing log type"))
            continue
        
        log_type_normalized = log_type.lower()
        if log_type_normalized not in LOG_TYPE_MAP:
            unparseable_blocks.append((block_text, f"Unsupported log type: {log_type}"))
            continue
    
    print(f"\nFound {len(unparseable_blocks)} unparseable blocks out of {len(blocks_text)} total blocks\n")
    
    seen_reasons = {}
    for block_text, reason in unparseable_blocks:
        if reason not in seen_reasons:
            seen_reasons[reason] = []
        seen_reasons[reason].append(block_text)
    
    print(f"Unparseable reasons breakdown:")
    for reason, blocks in seen_reasons.items():
        print(f"  {reason}: {len(blocks)} blocks")
    print()
    
    for i, (block_text, reason) in enumerate(unparseable_blocks, 1):
        print(f"[Block {i}/{len(unparseable_blocks)}]")
        print_unparseable_block(block_text, reason)


def print_sample_blocks(log_path: str):
    """Print one sample block for each log type"""
    blocks = parse_all_blocks(log_path)

    print(f"Total parsed blocks: {len(blocks)}\n")

    seen_types = set()

    for block in blocks:
        if block.log_type not in seen_types:
            seen_types.add(block.log_type)
            print("=" * 60)
            print(f"{block.log_type} Block Sample:")
            print("=" * 60)
            print(f"Timestamp: {block.timestamp}")
            print(f"Type: {block.log_type}")

            if isinstance(block, HashLogBlock):
                print(f"Content (String): {block.content_string}")
                print(f"Content (Base64): {block.content_base64[:80] if block.content_base64 else 'N/A'}...")
                print(f"Result (Hex): {block.result_hex}")
            elif isinstance(block, HmacLogBlock):
                print(f"Key Type: {block.key_type}")
                print(f"Key (Hex): {block.key_hex}")
                print(f"Content (String): {block.content_string}")
                print(f"Result (Hex): {block.result_hex}")
            elif isinstance(block, AesCbcLogBlock):
                print(f"Key Type: {block.key_type}")
                print(f"Operation: {block.operation}")
                print(f"Key (Hex): {block.key_hex}")
                print(f"IV (Hex): {block.iv_hex}")
                print(f"Content (Hex): {block.content_hex[:80] if block.content_hex else 'N/A'}...")
                print(f"Result (Hex): {block.result_hex[:80] if block.result_hex else 'N/A'}...")
            elif isinstance(block, AesEcbLogBlock):
                print(f"Key Type: {block.key_type}")
                print(f"Operation: {block.operation}")
                print(f"Key (Hex): {block.key_hex}")
                print(f"Content (String): {block.content_string[:80] if block.content_string else 'N/A'}...")
                print(f"Result (Hex): {block.result_hex[:80] if block.result_hex else 'N/A'}...")
            elif isinstance(block, RsaLogBlock):
                print(f"Key Type: {block.key_type}")
                print(f"Operation: {block.operation}")
                print(f"Key (Hex): {block.key_hex[:80] if block.key_hex else 'N/A'}...")
                print(f"Content (String): {block.content_string}")
                print(f"Result (Hex): {block.result_hex[:80] if block.result_hex else 'N/A'}...")
            elif isinstance(block, DatabaseLogBlock):
                print(f"Params: {block.params}")
                print(f"Return: {block.return_value}")
            elif isinstance(block, ReadAssetsLogBlock):
                print(f"Target File: {block.target_file}")
                print(f"Return: {block.return_value}")
            elif isinstance(block, ReadConfigLogBlock):
                print(f"Class: {block.class_name}")
                print(f"Method: {block.method_name}")
                print(f"Config File: {block.config_file}")
                print(f"Return: {block.return_value[:80] if block.return_value else 'N/A'}...")

            print(f"\nStack trace ({len(block.stack_trace)} frames):")
            for frame in block.stack_trace:
                print(f"  {frame}")
            
            print("=" * 60)
            print()

        if len(seen_types) == len(LOG_TYPE_MAP):
            break

    print(f"Found {len(seen_types)} unique log types")
