from pathlib import Path
import os
import sys
import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Files.encrypt_service import EncryptService


@pytest.fixture
def service() -> EncryptService:
    return EncryptService(password="v2plus")


@pytest.fixture
def sample_file_path() -> str:
    # 使用仓库内的固定样例，便于与已知期望值对比
    return str(Path(__file__).parent / "testfiles" / "sub_sample.txt")


@pytest.fixture
def expected_encrypted_result() -> str:
    # 直接从文件读取已知期望密文，避免把超长字符串写到代码里
    expected_path = Path(__file__).parent / "testfiles" / "sub_sample_expected_data.txt"
    with open(expected_path, "r", encoding="utf-8", newline="") as f:
        return f.read()


def test_encrypt_aes_with_known_vector(service: EncryptService, sample_file_path: str, expected_encrypted_result: str):
    # 保留原始换行（CRLF），与原行为统一
    with open(sample_file_path, "r", encoding="utf-8", newline="") as f:
        test_data = f.read()

    actual_result = service.encrypt_aes(test_data, "v2plus")
    assert actual_result == expected_encrypted_result


def test_encrypt_file_with_known_vector(  service: EncryptService,   sample_file_path: str,  expected_encrypted_result: str):
    expected_output_path = sample_file_path + ".encrypted"

    # 清理历史输出，避免干扰
    if os.path.exists(expected_output_path):
        os.remove(expected_output_path)

    # 执行文件加密
    output_path = service.encrypt_file(sample_file_path)

    # 断言输出路径与默认规则一致，且文件已生成
    assert output_path == expected_output_path
    assert os.path.exists(output_path)

    # 断言输出内容与已知期望密文一致（与 encrypt_aes(原文, "v2plus") 一致）
    with open(output_path, "r", encoding="utf-8", newline="") as f:
        written_encrypted = f.read()
    assert written_encrypted == expected_encrypted_result

    # 清理产物，避免污染仓库
    try:
        os.remove(output_path)
    except OSError:
        pass


if __name__ == "__main__":
    # 直接运行当前文件时，调用 pytest 执行本文件内用例
    raise SystemExit(pytest.main([__file__, "-q"]))