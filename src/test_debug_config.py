#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试配置测试脚本
用于验证预编译检查和调试配置是否正常工作
"""

import subprocess
import sys
import os


def test_precompile_check():
    """测试预编译检查"""
    print("[TEST] 测试预编译检查...")
    try:
        # 获取当前脚本所在目录（src目录）
        current_dir = os.path.dirname(__file__)
        
        result = subprocess.run([
            sys.executable, "precompile_check.py"
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore', cwd=current_dir)
        
        if result.returncode == 0:
            print("[OK] 预编译检查测试通过")
            return True
        else:
            print(f"[ERROR] 预编译检查测试失败: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] 预编译检查测试异常: {e}")
        return False


def test_syntax_check():
    """测试语法检查"""
    print("[TEST] 测试语法检查...")
    try:
        # 获取当前脚本所在目录（src目录）
        current_dir = os.path.dirname(__file__)
        
        result = subprocess.run([
            sys.executable, "syntax_check.py"
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore', cwd=current_dir)
        
        if result.returncode == 0:
            print("[OK] 语法检查测试通过")
            return True
        else:
            print(f"[ERROR] 语法检查测试失败: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] 语法检查测试异常: {e}")
        return False


def test_py_compile():
    """测试py_compile"""
    print("[TEST] 测试py_compile...")
    try:
        # 获取当前脚本所在目录（src目录）
        current_dir = os.path.dirname(__file__)
        
        result = subprocess.run([
            sys.executable, "-m", "py_compile", "node_crawler.py"
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore', cwd=current_dir)
        
        if result.returncode == 0:
            print("[OK] py_compile测试通过")
            return True
        else:
            print(f"[ERROR] py_compile测试失败: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] py_compile测试异常: {e}")
        return False


def check_config_files():
    """检查配置文件"""
    print("[TEST] 检查配置文件...")
    
    # 获取当前脚本所在目录（src目录）
    current_dir = os.path.dirname(__file__)
    project_root = os.path.dirname(current_dir)  # 项目根目录
    
    required_files = [
        os.path.join(project_root, ".vscode/launch.json"),
        os.path.join(project_root, ".vscode/tasks.json"),
        os.path.join(current_dir, "precompile_check.py"),
        os.path.join(current_dir, "syntax_check.py"),
        os.path.join(current_dir, "node_crawler.py")
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(os.path.relpath(file_path, project_root))
    
    if missing_files:
        print(f"[ERROR] 缺少文件: {', '.join(missing_files)}")
        return False
    else:
        print("[OK] 所有配置文件存在")
        return True


def main():
    """主函数"""
    print("[INFO] 开始调试配置测试...")
    print("=" * 60)
    
    tests = [
        ("配置文件检查", check_config_files),
        ("py_compile测试", test_py_compile),
        ("语法检查测试", test_syntax_check),
        ("预编译检查测试", test_precompile_check),
    ]
    
    all_passed = True
    for test_name, test_func in tests:
        try:
            if not test_func():
                all_passed = False
        except Exception as e:
            print(f"[ERROR] {test_name}异常: {e}")
            all_passed = False
        print()
    
    print("=" * 60)
    
    if all_passed:
        print("[SUCCESS] 所有测试通过！调试配置已就绪。")
        print("\n[INFO] 使用说明:")
        print("1. 按F5开始调试")
        print("2. 选择 'Python: 预编译检查 + 调试运行'")
        print("3. 系统会自动进行预编译检查，然后启动调试")
        return True
    else:
        print("[ERROR] 部分测试失败！请检查配置。")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)