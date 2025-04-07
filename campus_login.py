#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, parse_qs, quote, urljoin
from bs4 import BeautifulSoup
import time
import sys
import gzip
import io
import json
import argparse
import getpass

# --- 导入加密函数 ---
# 确保在同目录下有一个名为 security.py 的文件，
# 且该文件中包含 encryptPassword(password, exponent, modulus, mac) 函数
try:
    from security import encryptPassword
    print("[信息] 成功从 security.py 导入 encryptPassword 函数。")
except ImportError:
    print("\n" + "="*60)
    print(" critical error ".center(60, "!").upper())
    print(" 无法从 security.py 导入 encryptPassword 函数。 ".center(54))
    print(" 请确保 security.py 文件存在于脚本同目录下， ".center(54))
    print(" 且其中包含名为 encryptPassword 的函数。 ".center(54))
    print("="*60 + "\n")
    sys.exit(1) # 无法继续，退出脚本
except Exception as import_err:
    print(f"\n[错误] 导入 encryptPassword 时发生其他错误: {import_err}")
    sys.exit(1)

# --- 脚本配置 ---
INITIAL_CHECK_URL = "http://123.123.123.123" # 认证触发 IP
# 测试网络连通性的目标 URL (选择一个稳定、快速的外部网站)
INTERNET_CHECK_URL = "https://www.baidu.com"
# INTERNET_CHECK_URL = "https://cn.bing.com" # 备选

# --- 辅助函数：处理响应解压和解码 ---
def get_decoded_content(response):
    """
    手动处理 requests 响应，进行 gzip 解压（如果需要）和 GB18030/GBK 解码。
    Args: response (requests.Response): requests 响应对象
    Returns: str: 解码后的 HTML/文本内容，如果失败则返回 None。
    """
    content_encoding = response.headers.get('Content-Encoding', '').strip().lower()
    html_bytes = b'' # 初始化为空字节串

    if content_encoding == 'gzip':
        # print("[辅助] 检测到 gzip 压缩，尝试手动解压...") # 减少冗余打印
        try:
            buffer = io.BytesIO(response.content)
            gzip_file = gzip.GzipFile(fileobj=buffer)
            html_bytes = gzip_file.read()
            # print("[辅助] 手动解压成功。")
        except Exception as decomp_err:
            print(f"[错误] 手动 gzip 解压失败: {decomp_err}")
            html_bytes = response.content # 尝试使用原始内容
    else:
        # print("[辅助] 未检测到 gzip 压缩。")
        html_bytes = response.content # 直接使用原始字节

    # 尝试使用 GB18030 解码 (GBK 超集)
    try:
        # print("[辅助] 尝试使用 GB18030 解码...")
        decoded_text = html_bytes.decode('gb18030', errors='replace')
        return decoded_text
    except Exception:
        # print(f"[警告] 使用 GB18030 解码失败: {decode_err_18030}")
        # 尝试使用 GBK 作为备选
        try:
            # print("[辅助] 尝试使用 GBK 解码...")
            decoded_text_gbk = html_bytes.decode('gbk', errors='replace')
            return decoded_text_gbk
        except Exception as decode_err_gbk:
            print(f"[错误] 使用 GBK/GB18030 解码均失败: {decode_err_gbk}")
            return None # 所有解码尝试失败

# --- 网络连通性检查函数 ---
def check_internet_connection(check_url, timeout=5):
    """
    尝试访问外部 URL 以检查互联网连接。
    Args:
        check_url (str): 用于测试的 URL.
        timeout (int): 请求超时时间（秒）.
    Returns:
        bool: 如果连接成功则返回 True，否则返回 False。
    """
    print(f"[网络检查] 正在尝试访问 {check_url} 以检测互联网连接...")
    try:
        # 使用独立的 requests 调用，不依赖 session，设置短超时
        response = requests.get(check_url, timeout=timeout, allow_redirects=True)
        # 检查状态码是否成功 (2xx) 并且内容不为空
        if response.status_code >= 200 and response.status_code < 300 and response.content:
            # 可选：进一步检查内容是否符合预期，防止 captive portal 伪装成功
            # if "baidu" in response.url or "百度" in response.text: # 示例
            print(f"[网络检查] 成功访问 {check_url} (状态码: {response.status_code})。互联网已连接。")
            return True
        else:
            print(f"[网络检查] 访问 {check_url} 状态码异常: {response.status_code}。假定未连接。")
            return False
    except requests.exceptions.Timeout:
        print(f"[网络检查] 访问 {check_url} 超时 ({timeout}秒)。假定未连接。")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[网络检查] 访问 {check_url} 失败: {e}。假定未连接。")
        return False

# --- 主登录逻辑 ---
def login(username, password):
    """执行完整的校园网登录流程 (包含 pageInfo 请求)"""
    session = requests.Session()
    # 设置基础 Headers
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
    })
    print(f"\n[信息] 开始登录流程，使用用户名: {username} ...")

    try:
        # 1. 获取登录页面 URL (如果网络不通，访问此地址应该会成功或返回特定内容)
        print(f"\n[步骤 1] 正在访问认证触发地址: {INITIAL_CHECK_URL} ...")
        response_initial = session.get(INITIAL_CHECK_URL, timeout=15, allow_redirects=False)
        response_initial.raise_for_status() # 检查基础 HTTP 错误
        initial_page_text = get_decoded_content(response_initial)
        if initial_page_text is None:
            print("[错误] 无法获取或解码初始页面内容。")
            return False

        redirect_match = re.search(r"top\.self\.location\.href='(.*?)'", initial_page_text, re.IGNORECASE)
        if not redirect_match:
             print(f"[错误] 无法从 {INITIAL_CHECK_URL} 的响应中提取登录页面 URL (可能是认证服务器问题或页面变化)。")
             print("响应内容预览:")
             print(initial_page_text[:500] + "...")
             return False

        login_page_url = redirect_match.group(1)
        print(f"[+] 成功获取登录页面 URL: {login_page_url}")

        # 2. 解析登录 URL 参数
        print("\n[步骤 2] 正在解析登录页面 URL 参数...")
        parsed_login_url = urlparse(login_page_url)
        login_page_origin = f"{parsed_login_url.scheme}://{parsed_login_url.netloc}"
        query_params = parse_qs(parsed_login_url.query)
        original_query_string = parsed_login_url.query
        mac_address = query_params.get('mac', [None])[0]
        if not mac_address:
             print(f"[错误] 未能在登录 URL 中找到 'mac' 参数: {login_page_url}")
             return False
        print(f"[+] 提取到 MAC 地址: {mac_address}")
        encoded_query_string = quote(original_query_string) # 用于 POST 的 queryString
        print(f"[+] 准备好的 URL 编码查询字符串 (queryString): {encoded_query_string[:60]}...")

        # 3. 访问登录页面 (主要目的是设置 Cookies, 如 JSESSIONID)
        print(f"\n[步骤 3] 正在访问登录页面 (设置 Cookies): {login_page_url}...")
        response_login_page = session.get(login_page_url, timeout=15)
        response_login_page.raise_for_status()
        print("[+] 登录页面访问完成，Cookies 应已设置。")

        # 4. 发起 POST 请求获取 pageInfo (包含 publicKeyModulus)
        print("\n[步骤 4] 正在请求 pageInfo 获取公钥信息...")
        pageInfo_path = "/eportal/InterFace.do?method=pageInfo"
        pageInfo_url = urljoin(login_page_url, pageInfo_path)
        pageInfo_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': login_page_url, # 重要: 设置 Referer
            'Origin': login_page_origin, # 重要: 设置 Origin
            'Accept': '*/*', # 根据 curl
        }
        pageInfo_payload = {'queryString': encoded_query_string}

        print(f"POST URL: {pageInfo_url}")
        response_pageInfo = session.post(pageInfo_url, headers=pageInfo_headers, data=pageInfo_payload, timeout=15)
        response_pageInfo.raise_for_status()

        # 解析 pageInfo 的 JSON 响应
        try:
            pageInfo_data = response_pageInfo.json()
            print("[+] 成功解析 pageInfo JSON 响应。")
        except json.JSONDecodeError:
            print("[警告] 直接解析 JSON 失败，尝试手动解码...")
            pageInfo_text = get_decoded_content(response_pageInfo)
            if pageInfo_text:
                try:
                    pageInfo_data = json.loads(pageInfo_text)
                    print("[+] 手动解码后成功解析 pageInfo JSON。")
                except json.JSONDecodeError as json_err:
                    print(f"[错误] 手动解码后解析 JSON 仍然失败: {json_err}")
                    print("pageInfo 响应内容预览:", pageInfo_text[:500])
                    return False
            else:
                print("[错误] 无法解码 pageInfo 响应内容。")
                return False
        except Exception as e:
             print(f"[错误] 解析 pageInfo 响应时发生意外错误: {e}")
             return False

        # 从 JSON 中提取公钥信息
        public_key_modulus = pageInfo_data.get('publicKeyModulus')
        public_key_exponent = pageInfo_data.get('publicKeyExponent', "10001") # 提供备用值

        if not public_key_modulus:
            print("[错误] 未能在 pageInfo 响应中找到 'publicKeyModulus'。")
            print("pageInfo 数据:", pageInfo_data)
            return False
        print(f"[+] 提取到 publicKeyModulus: {public_key_modulus[:20]}...")
        print(f"[+] 提取到 publicKeyExponent: {public_key_exponent}")

        # 5. 调用导入的加密函数 (使用传入的 password)
        print("\n[步骤 5] 正在调用 encryptPassword 函数加密密码...")
        try:
            encrypted_password = encryptPassword(password, public_key_exponent, public_key_modulus, mac_address)
            if not encrypted_password:
                 print("[错误] encryptPassword 函数返回了空值或 None。")
                 return False
        except Exception as encrypt_err:
            print(f"[错误] 调用 encryptPassword 函数时出错: {encrypt_err}")
            import traceback
            traceback.print_exc() # 打印详细错误
            return False

        # 6. 构造最终登录 POST 请求 (使用传入的 username)
        print("\n[步骤 6] 准备发送最终登录 POST 请求...")
        login_action_path = "/eportal/InterFace.do?method=login"
        login_post_url = urljoin(login_page_url, login_action_path)
        print(f"POST URL: {login_post_url}")
        login_payload = {
            'userId': username, # <-- 使用传入的 username
            'password': encrypted_password,
            'service': query_params.get('service', [''])[0], # 从原始 URL 获取
            'queryString': encoded_query_string,
            'operatorPwd': '', 'operatorUserId': '', 'validcode': '',
            'passwordEncrypt': 'true' # 确认密码已加密
        }
        # 设置登录请求特定的 Headers
        login_headers = {
             'Referer': login_page_url,
             'Origin': login_page_origin,
             'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }

        # 7. 发送最终登录请求
        response_post_login = session.post(login_post_url, headers=login_headers, data=login_payload, timeout=20)
        response_post_login.raise_for_status() # 检查 HTTP 错误

        # 8. 分析登录响应
        print("\n[步骤 7] 正在分析最终登录响应...")
        post_response_text = get_decoded_content(response_post_login)
        if post_response_text is None:
             print("[错误] 无法获取或解码最终登录响应内容。登录状态未知。")
             # 检查状态码
             if response_post_login.status_code == 200:
                 print("[警告] POST 响应解码失败，但状态码为 200。可能登录成功，请手动验证。")
             return False # 谨慎起见，认为失败

        print(f"[+] 响应状态码: {response_post_login.status_code}")
        response_text_preview = post_response_text[:500].lower()
        print(f"[+] 解码后响应内容预览 (小写): {response_text_preview}...")

        # 9. 检查登录结果
        login_success = False
        # --- !!! 根据实际解码后的响应内容调整判断条件 !!! ---
        if '"result":"success"' in response_text_preview or '"msg":""' in response_text_preview or '认证成功' in response_text_preview or 'login_success' in response_text_preview or '登录成功' in response_text_preview:
             print("[+] 检测到明确的登录成功信息。")
             login_success = True
        elif '"result":"fail"' in response_text_preview or '密码错误' in response_text_preview or '用户名或密码无效' in response_text_preview or '账号或密码错误' in response_text_preview or 'error' in response_text_preview:
             print("[-] 检测到明确的登录失败信息。请检查用户名、密码或加密逻辑。")
             print(f"完整响应内容 (解码后): {post_response_text}")
             login_success = False
        else:
             # 无明确信息，进行网络检查确认
             print("[?] 未检测到明确的成功/失败信息，尝试再次访问外部网站验证...")
             time.sleep(3) # 登录后稍等片刻
             if check_internet_connection(INTERNET_CHECK_URL, timeout=7):
                 print("[+] 登录后网络连接测试成功。")
                 login_success = True
             else:
                 print("[-] 登录后网络连接测试失败。")
                 login_success = False

        return login_success

    except requests.exceptions.Timeout as e:
        print(f"[错误] 请求超时: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[错误] 网络请求过程中发生错误: {e}")
        if hasattr(e, 'response') and e.response is not None:
             print(f"响应状态码: {e.response.status_code}")
        return False
    except Exception as e:
        print(f"[错误] 脚本执行过程中发生意外错误: {e}")
        import traceback
        traceback.print_exc() # 打印详细的错误堆栈信息
        return False
    finally:
        if 'session' in locals(): # 确保 session 已定义
            print("\n[-] 关闭网络会话。")
            session.close()

# --- 脚本入口 ---
if __name__ == "__main__":
    print("="*30)
    print(" 校园网自动登录脚本 ".center(26))
    print("="*30)

    # --- 首先检查网络连通性 ---
    if check_internet_connection(INTERNET_CHECK_URL):
        print("\n[完成] 网络已连接，无需执行登录操作。")
        sys.exit(0) # 正常退出
    else:
        print("\n[信息] 检测到网络未连接或访问受限，准备执行登录流程。")

    # --- 网络未连接，继续获取凭证并登录 ---
    parser = argparse.ArgumentParser(description='校园网自动登录脚本')
    parser.add_argument('-u', '--username', type=str, help='校园网用户名')
    parser.add_argument('-p', '--password', type=str, help='校园网密码 (注意: 可能在命令行历史中可见)')
    args = parser.parse_args()

    # 获取用户名
    if args.username:
        input_username = args.username
    else:
        input_username = input("请输入校园网用户名: ")

    # 获取密码
    if args.password:
        input_password = args.password
        print("[警告] 从命令行参数读取密码，请注意安全风险。")
    else:
        # 使用 getpass 安全地获取密码 (输入时不回显)
        input_password = getpass.getpass("请输入校园网密码: ")

    if not input_username or not input_password:
        print("[错误] 用户名和密码不能为空。")
        sys.exit(1)

    # --- 执行登录 ---
    print("\n" + "="*30)
    print(" 开始执行登录流程 ".center(26))
    print("(含 pageInfo 请求, Gzip解压, GBK/GB18030解码)".center(50))
    print("(加密函数从 security.py 导入)".center(34))
    print("="*30)

    # 调用登录函数，传入获取到的用户名和密码
    if login(input_username, input_password):
        print("\n[成功] 登录流程执行完毕，结果：成功。")
        # 登录成功后可以再做一次网络检查确认
        print("正在进行登录后网络确认...")
        time.sleep(2) # 稍作等待
        if check_internet_connection(INTERNET_CHECK_URL, timeout=7):
             print("[确认] 登录后网络连接正常。")
        else:
             # 这种情况理论上不应发生，如果登录真的成功了
             print("[警告] 登录流程报告成功，但后续网络检查失败，可能存在认证延迟或未知问题。")
    else:
        print("\n[失败] 登录流程执行完毕，结果：失败。请检查用户名、密码、网络和脚本日志。")
        sys.exit(1) # 以非零状态码退出表示失败

    # input("按 Enter 键退出...") # 如果需要暂停查看结果，取消此行注释