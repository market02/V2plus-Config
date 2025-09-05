from pathlib import Path
from encrypt_service import EncryptService

def test_encrypt_aes(sample_file_path: str, expected_encrypted_result: str) -> bool:
    # 保留原始换行（CRLF），与 C# 行为统一
    with open(sample_file_path, 'r', encoding='utf-8', newline='') as f:
        test_data = f.read()
    # 加密数据
    actual_result = EncryptService().encrypt_aes(test_data, "v2plus")
    # 断言一致
    assert actual_result == expected_encrypted_result, (
        f"加密结果不匹配！\n期待: {expected_encrypted_result}\n实际: {actual_result}"
    )
    print("✓ 测试通过！")
    return True

if __name__ == "__main__":
    sample_path = Path(__file__).parent / "testfiles" / "sub_sample.txt"
    expected_result = "rMISEWphLIhDId4cG3toy78mj88Mi/sRcHZ0F5lPyceXNJr1/At8FCtCm2+idltoypn1nbo+xKMh6AmNs2um5jLJuZz7G4zlsGYZMzaVmgO+wOMbV6dfWKD0gOow5/xwfQ7cxtFdB9PrKL7mzAHlOb/ogvr8ZwPQ8fyeQFOzX462pP5HgKJmCj8RWX01KbhtxQxfZzw25EXMhMxD16kgc/z01UMztstGlvc0HvfKojYgXJ2uV0k48cU5TxpD0U3V6MuznPMSC2bMs9AAk+lv9wrmr43oURiKfIMqe5YMxLsn4JZn8UmoMAdpe+efPBmRZN1vVVJ5s6SURC8lHxcZ5aZZQLTQzEQ8/s0EB0ymAVhKFXJaXNpMtTn+hkftz4UYipuMrJn7SFaMwPEePxZCNwRLuU3or3rPb+C/3++KxD6OQT0gZstPpboI108LXtjwaaN3M+kV7R1N+c0FFx+8kJ73KHBFBQfAU2kj3henEhpXzaQ4lTAtCzsyh7rCpNlphWLfD8/TGSpJdJ2U1xHvHw/VdErMXl3YYGC+xNaqqlj2njChAbKO8gs/ob2kzuINUMnRO1TdocDJ2t+29l/4gJIW0A4FozByPVpCcXRpeIj5x9TQtsOrq7UJht0GafzCxEYhNzihs2Jy7XUr/3HC/tMwlXYGqUyoghtIqmlKFjQi71O4Pixr5ckdSBtf0EjPemLZROXuBaZ4a1ztujjfi9eikmFemrrnuBkWZrOYl5iis3vbYo+r2sNYrhEzbF3Wu/nnzjD63rlvsL5TxPkdTg76INWXyu+OJljrW61lYUTg3YUt6FWJ8QPG4/HXQdpcihH/cptCABAjXhrVWUs7AXr7zxp10RRwM16nyyFHHlhgmcJI2A0G3dJymxcLoR/Yz4NOQXv67hpg8JaMxITn6K9kQff/AKIy6syeu6TaCBn2YvOmWcO9earUZ/pQUgcdgOaMA4XwEbk0Wi1II9C+R9DStmlh/o+oU83pNZPZfcyN/iCP4rtb951ZXkBnRW6s9DU8oUMlTTxXiLQ5kms7F+LREst3pIBkXb9fUMSkKoZFTuHwlNn0hIM9GtN7drOpVdl48Xx4DtC4t2es3CZmBBRIWbx/lVGnaJ1f1fsZ5rU="
    try:
        test_encrypt_aes(str(sample_path), expected_result)
    except AssertionError as e:
        print(f"✗ 测试失败: {e}")
    except Exception as e:
        print(f"✗ 运行错误: {e}")