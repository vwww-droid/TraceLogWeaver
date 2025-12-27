#!/usr/bin/env python3
"""
Log search tool
Search for specific strings in parsed log blocks
"""

import argparse
import sys
from typing import List, Dict, Any
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


def search_blocks(blocks: List[LogBlock], search_string: str, exact_match: bool = True) -> List[Dict[str, Any]]:
    """
    Search for a string in all log blocks
    
    Args:
        blocks: List of parsed log blocks
        search_string: String to search for
        exact_match: If True, require exact match; if False, use substring match
        
    Returns:
        List of matches, each containing block index, field name, and matched value
    """
    matches = []
    
    for idx, block in enumerate(blocks):
        fields = extract_all_fields(block)
        
        for field_name, field_value in fields.items():
            if field_value is None:
                continue
                
            field_str = str(field_value)
            
            if exact_match:
                if field_str == search_string:
                    matches.append({
                        'block_index': idx,
                        'block': block,
                        'field_name': field_name,
                        'field_value': field_value
                    })
            else:
                if search_string in field_str:
                    matches.append({
                        'block_index': idx,
                        'block': block,
                        'field_name': field_name,
                        'field_value': field_value
                    })
    
    return matches


def print_matches(matches: List[Dict[str, Any]], search_string: str, exact_match: bool):
    """
    Print search results in a formatted way
    
    Args:
        matches: List of match dictionaries
        search_string: The search string used
        exact_match: Whether exact match was used
    """
    if not matches:
        print(f"No matches found for '{search_string}' ({'exact' if exact_match else 'substring'} match)")
        return
    
    print(f"Found {len(matches)} match(es) for '{search_string}' ({'exact' if exact_match else 'substring'} match)\n")
    
    for i, match in enumerate(matches, 1):
        block = match['block']
        field_name = match['field_name']
        field_value = match['field_value']
        
        print("=" * 80)
        print(f"Match {i}/{len(matches)}")
        print("=" * 80)
        print(f"Block Index: {match['block_index']}")
        print(f"Timestamp: {block.timestamp}")
        print(f"Log Type: {block.log_type}")
        print(f"Matched Field: {field_name}")
        print(f"Matched Value: {field_value}")
        
        # Show additional context based on block type
        if isinstance(block, MethodHookLogBlock):
            print(f"Class: {block.class_name}")
            print(f"Method: {block.method_name}")
        elif isinstance(block, DatabaseLogBlock):
            print(f"Params: {block.params}")
        elif isinstance(block, ReadAssetsLogBlock):
            print(f"Target File: {block.target_file}")
        elif isinstance(block, ReadConfigLogBlock):
            print(f"Class: {block.class_name}")
            print(f"Method: {block.method_name}")
            print(f"Config File: {block.config_file}")
        
        # Show stack trace if available
        if block.stack_trace:
            print(f"\nStack Trace ({len(block.stack_trace)} frames):")
            for frame in block.stack_trace[:5]:  # Show first 5 frames
                print(f"  {frame}")
            if len(block.stack_trace) > 5:
                print(f"  ... and {len(block.stack_trace) - 5} more frames")
        
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Search for strings in parsed log blocks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Exact match search
  python log_search.py log.txt "some_string"
  
  # Substring match search
  python log_search.py log.txt "some_string" --substring
  
  # Limit number of blocks to parse
  python log_search.py log.txt "some_string" --limit 1000
        """
    )
    
    parser.add_argument('log_path', help='Path to log file')
    parser.add_argument('search_string', help='String to search for')
    parser.add_argument('--substring', action='store_true', 
                       help='Use substring match instead of exact match')
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
    
    # Search
    exact_match = not args.substring
    matches = search_blocks(blocks, args.search_string, exact_match=exact_match)
    
    # Print results
    print_matches(matches, args.search_string, exact_match)


if __name__ == '__main__':
    main()

