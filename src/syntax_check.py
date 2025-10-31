#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python语法检查工具
用于在调试前验证代码语法正确性
"""

import ast
import py_compile
import sys
import os
from pathlib import Path


def check_syntax(file_path):
    """检查单个文件的语法"""
    try:
        # 使用ast模块检查语法
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        ast.parse(source, file_path)
        print(f"[OK] {file_path}: 语法检查通过")
        return True
        
    except SyntaxError as e:
        print(f"[ERROR] {file_path}: 语法错误")
        print(f"   行 {e.lineno}: {e.text.strip() if e.text else ''}")
        print(f"   错误: {e.msg}")
        return False
    except Exception as e:
        print(f"[ERROR] {file_path}: 检查失败 - {e}")
        return False


def compile_check(file_path):
    """尝试编译Python文件"""
    try:
        py_compile.compile(file_path, doraise=True)
        print(f"[OK] {file_path}: 编译检查通过")
        return True
    except py_compile.PyCompileError as e:
        print(f"[ERROR] {file_path}: 编译错误")
        print(f"   {e}")
        return False


def main():
    """主函数"""
    target_file = "node_crawler.py"
    
    if not os.path.exists(target_file):
        print(f"[ERROR] 文件不存在: {target_file}")
        sys.exit(1)
    
    print("[INFO] 开始Python代码检查...")
    print("=" * 50)
    
    # 语法检查
    syntax_ok = check_syntax(target_file)
    
    # 编译检查
    compile_ok = compile_check(target_file)
    
    print("=" * 50)
    
    if syntax_ok and compile_ok:
        print("[SUCCESS] 所有检查通过！代码可以安全运行。")
        sys.exit(0)
    else:
        print("[ERROR] 检查失败！请修复错误后重试。")
        sys.exit(1)


if __name__ == "__main__":
    main()