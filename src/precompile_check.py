#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python预编译检查工具
在调试运行前进行全面的代码检查
"""

import ast
import py_compile
import sys
import os
import importlib.util
from pathlib import Path


class PrecompileChecker:
    """预编译检查器"""

    def __init__(self, target_file="node_crawler.py"):
        self.target_file = target_file
        self.errors = []
        self.warnings = []

    def check_file_exists(self):
        """检查文件是否存在"""
        if not os.path.exists(self.target_file):
            self.errors.append(f"目标文件不存在: {self.target_file}")
            return False
        return True

    def check_syntax(self):
        """语法检查"""
        try:
            with open(self.target_file, "r", encoding="utf-8") as f:
                source = f.read()

            # 使用ast模块检查语法
            ast.parse(source, self.target_file)
            print(f"[OK] 语法检查: 通过")
            return True

        except SyntaxError as e:
            error_msg = f"语法错误 - 行 {e.lineno}: {e.msg}"
            if e.text:
                error_msg += f"\n   代码: {e.text.strip()}"
            self.errors.append(error_msg)
            return False
        except Exception as e:
            self.errors.append(f"语法检查失败: {e}")
            return False

    def check_compile(self):
        """编译检查"""
        try:
            py_compile.compile(self.target_file, doraise=True)
            print(f"[OK] 编译检查: 通过")
            return True
        except py_compile.PyCompileError as e:
            self.errors.append(f"编译错误: {e}")
            return False

    def check_imports(self):
        """导入检查"""
        try:
            with open(self.target_file, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)
            imports = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)

            missing_modules = []
            for module_name in set(imports):
                try:
                    if module_name.startswith("."):
                        continue  # 跳过相对导入

                    # 尝试查找模块
                    spec = importlib.util.find_spec(module_name.split(".")[0])
                    if spec is None:
                        missing_modules.append(module_name)
                except (ImportError, ModuleNotFoundError, ValueError):
                    missing_modules.append(module_name)

            if missing_modules:
                self.warnings.append(f"可能缺少的模块: {', '.join(missing_modules)}")

            print(f"[OK] 导入检查: 通过 (发现 {len(imports)} 个导入)")
            return True

        except Exception as e:
            self.warnings.append(f"导入检查失败: {e}")
            return True  # 不阻止运行

    def check_basic_structure(self):
        """基本结构检查"""
        try:
            with open(self.target_file, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)

            # 检查是否有函数或类定义
            has_functions = any(
                isinstance(node, ast.FunctionDef) for node in ast.walk(tree)
            )
            has_classes = any(isinstance(node, ast.ClassDef) for node in ast.walk(tree))

            if not has_functions and not has_classes:
                self.warnings.append("文件中没有发现函数或类定义")

            print(f"[OK] 结构检查: 通过")
            return True

        except Exception as e:
            self.warnings.append(f"结构检查失败: {e}")
            return True  # 不阻止运行

    def run_all_checks(self):
        """运行所有检查"""
        print("[INFO] 开始预编译检查...")
        print("=" * 60)

        checks = [
            ("文件存在检查", self.check_file_exists),
            ("语法检查", self.check_syntax),
            ("编译检查", self.check_compile),
            ("导入检查", self.check_imports),
            ("结构检查", self.check_basic_structure),
        ]

        all_passed = True
        for check_name, check_func in checks:
            try:
                if not check_func():
                    all_passed = False
                    if check_name in ["文件存在检查", "语法检查", "编译检查"]:
                        break  # 关键检查失败，停止后续检查
            except Exception as e:
                self.errors.append(f"{check_name}异常: {e}")
                all_passed = False

        print("=" * 60)

        # 显示警告
        if self.warnings:
            print("[WARNING] 警告:")
            for warning in self.warnings:
                print(f"   {warning}")
            print()

        # 显示错误
        if self.errors:
            print("[ERROR] 错误:")
            for error in self.errors:
                print(f"   {error}")
            print()

        if all_passed and not self.errors:
            print("[SUCCESS] 所有检查通过！代码可以安全运行。")
            return True
        else:
            print("[ERROR] 检查失败！请修复错误后重试。")
            return False


def main():
    """主函数"""
    checker = PrecompileChecker("node_crawler.py")
    success = checker.run_all_checks()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
