#!/usr/bin/env python3
"""
Log search tool
Search for specific strings in parsed log blocks
"""

import argparse
import sys
from typing import List, Dict, Any, Tuple
from algorithmaide_log_parser import (
    parse_all_blocks,
    LogBlock,
    HashLogBlock,
    HmacLogBlock,
    AesCbcLogBlock,
    AesEcbLogBlock,
    RsaLogBlock,
    DatabaseLogBlock,
    ReadAssetsLogBlock,
    ReadConfigLogBlock,
    MethodHookLogBlock,
)


def extract_all_fields(block: LogBlock) -> Dict[str, Any]:
    """
    Extract all string fields from a log block
    
    Args:
        block: LogBlock instance
        
    Returns:
        Dictionary mapping field names to values
    """
    fields = {}
    
    # Base fields
    fields['timestamp'] = block.timestamp
    fields['log_type'] = block.log_type
    
    # Type-specific fields
    if isinstance(block, HashLogBlock):
        fields['content_string'] = block.content_string
        fields['content_base64'] = block.content_base64
        fields['content_hex'] = block.content_hex
        fields['result_string'] = block.result_string
        fields['result_base64'] = block.result_base64
        fields['result_hex'] = block.result_hex
        
    elif isinstance(block, HmacLogBlock):
        fields['key_type'] = block.key_type
        fields['key_string'] = block.key_string
        fields['key_base64'] = block.key_base64
        fields['key_hex'] = block.key_hex
        fields['content_string'] = block.content_string
        fields['content_base64'] = block.content_base64
        fields['content_hex'] = block.content_hex
        fields['result_string'] = block.result_string
        fields['result_base64'] = block.result_base64
        fields['result_hex'] = block.result_hex
        
    elif isinstance(block, AesCbcLogBlock):
        fields['key_type'] = block.key_type
        fields['key_string'] = block.key_string
        fields['key_base64'] = block.key_base64
        fields['key_hex'] = block.key_hex
        fields['iv_string'] = block.iv_string
        fields['iv_base64'] = block.iv_base64
        fields['iv_hex'] = block.iv_hex
        fields['content_string'] = block.content_string
        fields['content_base64'] = block.content_base64
        fields['content_hex'] = block.content_hex
        fields['result_string'] = block.result_string
        fields['result_base64'] = block.result_base64
        fields['result_hex'] = block.result_hex
        fields['operation'] = block.operation
        
    elif isinstance(block, AesEcbLogBlock):
        fields['key_type'] = block.key_type
        fields['key_string'] = block.key_string
        fields['key_base64'] = block.key_base64
        fields['key_hex'] = block.key_hex
        fields['content_string'] = block.content_string
        fields['content_base64'] = block.content_base64
        fields['content_hex'] = block.content_hex
        fields['result_string'] = block.result_string
        fields['result_base64'] = block.result_base64
        fields['result_hex'] = block.result_hex
        fields['operation'] = block.operation
        
    elif isinstance(block, RsaLogBlock):
        fields['key_type'] = block.key_type
        fields['key_string'] = block.key_string
        fields['key_base64'] = block.key_base64
        fields['key_hex'] = block.key_hex
        fields['content_string'] = block.content_string
        fields['content_base64'] = block.content_base64
        fields['content_hex'] = block.content_hex
        fields['result_string'] = block.result_string
        fields['result_base64'] = block.result_base64
        fields['result_hex'] = block.result_hex
        fields['operation'] = block.operation
        
    elif isinstance(block, DatabaseLogBlock):
        for key, value in block.params.items():
            fields[f'params.{key}'] = value
        fields['return_value'] = block.return_value
        
    elif isinstance(block, ReadAssetsLogBlock):
        fields['target_file'] = block.target_file
        fields['return_value'] = block.return_value
        
    elif isinstance(block, ReadConfigLogBlock):
        fields['class_name'] = block.class_name
        fields['method_name'] = block.method_name
        fields['config_file'] = block.config_file
        fields['return_value'] = block.return_value
        
    elif isinstance(block, MethodHookLogBlock):
        fields['class_name'] = block.class_name
        fields['method_name'] = block.method_name
        for i, param in enumerate(block.params):
            for key, value in param.items():
                fields[f'params[{i}].{key}'] = value
        fields['return_type'] = block.return_type
        fields['return_value'] = block.return_value
    
    return fields


def format_value(label: str, value: Any, max_line_length: int = 100) -> str:
    """
    Format a label-value pair ensuring line doesn't exceed max_line_length
    
    Args:
        label: Label string (e.g., "Content (String):")
        value: Value to format
        max_line_length: Maximum line length (default 100)
        
    Returns:
        Formatted string, possibly with truncation
    """
    if value is None:
        return f"{label} None"
    
    value_str = str(value)
    label_len = len(label)
    
    # Calculate available space for value (label + space + ellipsis)
    available_space = max_line_length - label_len - 1  # -1 for space
    
    # If label itself is too long, truncate label
    if label_len >= max_line_length - 10:  # Leave at least 10 chars for value
        label = label[:max_line_length - 15] + "..."
        label_len = len(label)
        available_space = max_line_length - label_len - 1
    
    # If label + value fits in one line, return as is
    if label_len + len(value_str) + 1 <= max_line_length:
        return f"{label} {value_str}"
    
    # If value is too long, truncate it
    max_value_len = available_space - 3  # -3 for "..."
    if max_value_len < 0:
        max_value_len = 0
    if len(value_str) > max_value_len:
        truncated = value_str[:max_value_len]
        return f"{label} {truncated}..."
    
    return f"{label} {value_str}"


def extract_match_context(field_value: str, match_start: int, match_end: int, 
                         context_size: int = 150) -> Tuple[str, int, int]:
    """
    Extract context around match position (before and after)
    
    Args:
        field_value: Full field value string
        match_start: Start position of match
        match_end: End position of match
        context_size: Number of characters to show before and after match
        
    Returns:
        Tuple of (context_string, adjusted_match_start, adjusted_match_end)
    """
    if match_start is None or match_end is None:
        return field_value, 0, len(field_value)
    
    # Calculate context boundaries
    context_start = max(0, match_start - context_size)
    context_end = min(len(field_value), match_end + context_size)
    
    # Extract context
    context = field_value[context_start:context_end]
    
    # Adjust match positions relative to context
    adjusted_match_start = match_start - context_start
    adjusted_match_end = match_end - context_start
    
    # Add ellipsis if truncated
    prefix = "..." if context_start > 0 else ""
    suffix = "..." if context_end < len(field_value) else ""
    
    return prefix + context + suffix, len(prefix) + adjusted_match_start, len(prefix) + adjusted_match_end


def format_match_value(field_value: Any, match_start: int, match_end: int, 
                      search_string: str, match_type: str) -> str:
    """
    Format matched field value with context (no highlighting)
    
    Args:
        field_value: Original field value
        match_start: Start position of match
        match_end: End position of match
        search_string: The search string used
        match_type: Type of match (exact, contains, contained)
        
    Returns:
        Formatted string with context around match position (no highlighting)
    """
    if field_value is None:
        return "None"
    
    field_str = str(field_value)
    
    # For exact match, show full value
    if match_type == "exact":
        return field_str
    # For contains match, extract context around match position
    elif match_type == "contains":
        context, adj_start, adj_end = extract_match_context(field_str, match_start, match_end)
        return context
    # For contained match, show full value
    elif match_type == "contained":
        return field_str
    
    # Fallback: return value as is
    return field_str


def print_block_info(block: LogBlock):
    """
    Print complete block information with all fields
    
    Args:
        block: LogBlock instance to print
    """
    print(format_value("Timestamp:", block.timestamp))
    print(format_value("Log Type:", block.log_type))
    
    if isinstance(block, HashLogBlock):
        if block.content_string:
            print(format_value("Content (String):", block.content_string))
        if block.content_base64:
            print(format_value("Content (Base64):", block.content_base64))
        if block.content_hex:
            print(format_value("Content (Hex):", block.content_hex))
        if block.result_string:
            print(format_value("Result (String):", block.result_string))
        if block.result_base64:
            print(format_value("Result (Base64):", block.result_base64))
        if block.result_hex:
            print(format_value("Result (Hex):", block.result_hex))
            
    elif isinstance(block, HmacLogBlock):
        if block.key_type:
            print(format_value("Key Type:", block.key_type))
        if block.key_string:
            print(format_value("Key (String):", block.key_string))
        if block.key_base64:
            print(format_value("Key (Base64):", block.key_base64))
        if block.key_hex:
            print(format_value("Key (Hex):", block.key_hex))
        if block.content_string:
            print(format_value("Content (String):", block.content_string))
        if block.content_base64:
            print(format_value("Content (Base64):", block.content_base64))
        if block.content_hex:
            print(format_value("Content (Hex):", block.content_hex))
        if block.result_string:
            print(format_value("Result (String):", block.result_string))
        if block.result_base64:
            print(format_value("Result (Base64):", block.result_base64))
        if block.result_hex:
            print(format_value("Result (Hex):", block.result_hex))
            
    elif isinstance(block, AesCbcLogBlock):
        if block.key_type:
            print(format_value("Key Type:", block.key_type))
        if block.key_string:
            print(format_value("Key (String):", block.key_string))
        if block.key_base64:
            print(format_value("Key (Base64):", block.key_base64))
        if block.key_hex:
            print(format_value("Key (Hex):", block.key_hex))
        if block.iv_string:
            print(format_value("IV (String):", block.iv_string))
        if block.iv_base64:
            print(format_value("IV (Base64):", block.iv_base64))
        if block.iv_hex:
            print(format_value("IV (Hex):", block.iv_hex))
        if block.content_string:
            print(format_value("Content (String):", block.content_string))
        if block.content_base64:
            print(format_value("Content (Base64):", block.content_base64))
        if block.content_hex:
            print(format_value("Content (Hex):", block.content_hex))
        if block.result_string:
            print(format_value("Result (String):", block.result_string))
        if block.result_base64:
            print(format_value("Result (Base64):", block.result_base64))
        if block.result_hex:
            print(format_value("Result (Hex):", block.result_hex))
        if block.operation:
            print(format_value("Operation:", block.operation))
            
    elif isinstance(block, AesEcbLogBlock):
        if block.key_type:
            print(format_value("Key Type:", block.key_type))
        if block.key_string:
            print(format_value("Key (String):", block.key_string))
        if block.key_base64:
            print(format_value("Key (Base64):", block.key_base64))
        if block.key_hex:
            print(format_value("Key (Hex):", block.key_hex))
        if block.content_string:
            print(format_value("Content (String):", block.content_string))
        if block.content_base64:
            print(format_value("Content (Base64):", block.content_base64))
        if block.content_hex:
            print(format_value("Content (Hex):", block.content_hex))
        if block.result_string:
            print(format_value("Result (String):", block.result_string))
        if block.result_base64:
            print(format_value("Result (Base64):", block.result_base64))
        if block.result_hex:
            print(format_value("Result (Hex):", block.result_hex))
        if block.operation:
            print(format_value("Operation:", block.operation))
            
    elif isinstance(block, RsaLogBlock):
        if block.key_type:
            print(format_value("Key Type:", block.key_type))
        if block.key_string:
            print(format_value("Key (String):", block.key_string))
        if block.key_base64:
            print(format_value("Key (Base64):", block.key_base64))
        if block.key_hex:
            print(format_value("Key (Hex):", block.key_hex))
        if block.content_string:
            print(format_value("Content (String):", block.content_string))
        if block.content_base64:
            print(format_value("Content (Base64):", block.content_base64))
        if block.content_hex:
            print(format_value("Content (Hex):", block.content_hex))
        if block.result_string:
            print(format_value("Result (String):", block.result_string))
        if block.result_base64:
            print(format_value("Result (Base64):", block.result_base64))
        if block.result_hex:
            print(format_value("Result (Hex):", block.result_hex))
        if block.operation:
            print(format_value("Operation:", block.operation))
            
    elif isinstance(block, DatabaseLogBlock):
        if block.params:
            print(format_value("Params:", block.params))
        if block.return_value is not None:
            print(format_value("Return Value:", block.return_value))
            
    elif isinstance(block, ReadAssetsLogBlock):
        if block.target_file:
            print(format_value("Target File:", block.target_file))
        if block.return_value is not None:
            print(format_value("Return Value:", block.return_value))
            
    elif isinstance(block, ReadConfigLogBlock):
        if block.class_name:
            print(format_value("Class:", block.class_name))
        if block.method_name:
            print(format_value("Method:", block.method_name))
        if block.config_file:
            print(format_value("Config File:", block.config_file))
        if block.return_value is not None:
            print(format_value("Return Value:", block.return_value))
            
    elif isinstance(block, MethodHookLogBlock):
        if block.class_name:
            print(format_value("Class:", block.class_name))
        if block.method_name:
            print(format_value("Method:", block.method_name))
        if block.params:
            print(format_value("Params:", block.params))
        if block.return_type:
            print(format_value("Return Type:", block.return_type))
        if block.return_value is not None:
            print(format_value("Return Value:", block.return_value))
    
    if block.stack_trace:
        print(f"\nStack Trace ({len(block.stack_trace)} frames):")
        for frame in block.stack_trace:
            frame_str = str(frame)
            if len(frame_str) > 100:
                print(f"  {frame_str[:97]}...")
            else:
                print(f"  {frame_str}")


def search_blocks(blocks: List[LogBlock], search_string: str) -> List[Dict[str, Any]]:
    """
    Search for a string in all log blocks with automatic bidirectional matching
    
    Supports:
    - Exact match: field_value == search_string
    - Contains match: search_string in field_value
    - Contained match: field_value in search_string
    
    Args:
        blocks: List of parsed log blocks
        search_string: String to search for
        
    Returns:
        List of matches sorted by timestamp (chronological order), each containing 
        block index, field name, and matched value
    """
    matches = []
    
    for idx, block in enumerate(blocks):
        fields = extract_all_fields(block)
        
        for field_name, field_value in fields.items():
            if field_value is None:
                continue
            
            field_str = str(field_value)
            
            # Skip empty strings to avoid false matches
            if not field_str or not search_string:
                continue
                
            matched = False
            match_type = None
            
            # Try exact match first
            if field_str == search_string:
                matched = True
                match_type = "exact"
                match_start = 0
                match_end = len(field_str)
            # Then bidirectional substring match
            elif search_string in field_str:
                matched = True
                match_type = "contains"
                match_start = field_str.find(search_string)
                match_end = match_start + len(search_string)
            elif field_str in search_string and len(field_str) > 0:
                matched = True
                match_type = "contained"
                match_start = 0
                match_end = len(field_str)
            else:
                match_start = None
                match_end = None
            
            if matched:
                matches.append({
                    'block_index': idx,
                    'block': block,
                    'field_name': field_name,
                    'field_value': field_value,
                    'match_type': match_type,
                    'match_start': match_start,
                    'match_end': match_end,
                    'search_string': search_string
                })
    
    # Sort by timestamp to show chronological call relationship
    # This provides a simple call chain view ordered by execution time
    matches.sort(key=lambda x: x['block'].timestamp)
    
    return matches


def print_matches(matches: List[Dict[str, Any]], search_string: str):
    """
    Print search results in a formatted way
    
    Results are printed in chronological order (by timestamp) to show 
    the call relationship and execution flow over time.
    
    Args:
        matches: List of match dictionaries (already sorted by timestamp)
        search_string: The search string used
    """
    if not matches:
        print(f"No matches found for '{search_string}'")
        return
    
    print(f"Found {len(matches)} match(es) for '{search_string}'")
    print("Results are displayed in chronological order (by timestamp)\n")
    
    for i, match in enumerate(matches, 1):
        block = match['block']
        field_name = match['field_name']
        field_value = match['field_value']
        
        print("=" * 80)
        print(f"Match {i}/{len(matches)}")
        print("=" * 80)
        print(f"Block Index: {match['block_index']}")
        print()
        
        # Print complete block information first
        print("Block Information:")
        print("-" * 80)
        print_block_info(block)
        print("-" * 80)
        print()
        
        # Then print match information
        print("Match Information:")
        print("-" * 80)
        print(format_value("Matched Field:", field_name))
        
        # Format matched value with context and highlighting
        match_start = match.get('match_start')
        match_end = match.get('match_end')
        search_string = match.get('search_string', '')
        match_type = match.get('match_type', '')
        
        formatted_value = format_match_value(
            field_value, match_start, match_end, search_string, match_type
        )
        
        # Print with label, handle long values with line breaks
        label = "Matched Value:"
        max_line_len = 100
        label_len = len(label)
        
        # If value fits on one line with label, print directly
        if label_len + len(formatted_value) + 1 <= max_line_len:
            print(f"{label} {formatted_value}")
        else:
            # Print label on first line, then value on subsequent lines with indentation
            print(f"{label}")
            # Split value into chunks of max_line_len characters
            indent = " " * (label_len + 1)
            chunk_size = max_line_len - label_len - 1
            for i in range(0, len(formatted_value), chunk_size):
                chunk = formatted_value[i:i + chunk_size]
                print(f"{indent}{chunk}")
        
        if 'match_type' in match:
            match_type_desc = {
                'exact': 'Exact match',
                'contains': 'Search string is in field value',
                'contained': 'Field value is in search string'
            }
            match_type_str = match_type_desc.get(match['match_type'], match['match_type'])
            print(format_value("Match Type:", match_type_str))
        print("-" * 80)
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Search for strings in parsed log blocks (supports exact, contains, and contained matching)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search with automatic bidirectional matching
  python log_search.py log.txt "some_string"
  
  # Limit number of blocks to parse
  python log_search.py log.txt "some_string" --limit 1000
        """
    )
    
    parser.add_argument('log_path', help='Path to log file')
    parser.add_argument('search_string', help='String to search for')
    parser.add_argument('--limit', type=int, default=None,
                       help='Limit number of blocks to parse')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress parsing progress messages')
    
    args = parser.parse_args()
    
    # Parse all blocks
    if not args.quiet:
        print(f"Parsing log file: {args.log_path}")
        if args.limit:
            print(f"Limiting to first {args.limit} blocks")
        print()
    
    blocks = parse_all_blocks(args.log_path, limit=args.limit, print_unparseable=False)
    
    if not args.quiet:
        print(f"Parsed {len(blocks)} blocks\n")
    
    # Search with automatic bidirectional matching
    # Results are automatically sorted by timestamp to show chronological call relationship
    matches = search_blocks(blocks, args.search_string)
    
    # Print results in chronological order (by timestamp)
    print_matches(matches, args.search_string)


if __name__ == '__main__':
    main()

