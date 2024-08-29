import re
import sqlite3
import sys
import os
import argparse

# 颜色设置
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# 有趣的标识进入标记
def print_banner():
    banner = f"""
    {Colors.OKGREEN}
    ███████╗ █████╗ ██╗██╗     ███████╗██╗███╗   ██╗███████╗
    ██╔════╝██╔══██╗██║██║     ██╔════╝██║████╗  ██║██╔════╝
    ███████╗███████║██║██║     █████╗  ██║██╔██╗ ██║███████╗
    ╚════██║██╔══██║██║██║     ██╔══╝  ██║██║╚██╗██║╚════██║
    ███████║██║  ██║██║███████╗███████╗██║██║ ╚████║███████║
    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝
                                                  
           ██╗███████╗███╗   ███╗██████╗ 
           ██║██╔════╝████╗ ████║██╔══██╗
           ██║█████╗  ██╔████╔██║██║  ██║
           ██║██╔══╝  ██║╚██╔╝██║██║  ██║
           ██║███████╗██║ ╚═╝ ██║██████╔╝
           ╚═╝╚══════╝╚═╝     ╚═╝╚═════╝ 
    {Colors.ENDC}
    """
    print(banner)

def connect_to_db(db_path):
    try:
        conn = sqlite3.connect(db_path)
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def get_tables(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return cursor.fetchall()

def get_table_info(conn, table_name):
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name});")
    return cursor.fetchall()

def get_table_data(conn, table_name):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name};")
    return cursor.fetchall()

def detect_sensitive_data(columns):
    sensitive_keywords = [
        'password', 'pass', 'pwd', 'secret', 'token', 'key', 
        'user', 'username', 'login', 'email', 'phone', 'credit', 
        'ssn', 'social_security', 'ip', 'address', 'domain', 'url',
        'api', 'auth', 'jwt', 'bearer', 'oauth', 'connect', 'connect_str',
        'log', 'debug', 'trace', 'error', 'command', 'cmd', 'exec',
        # 添加云安全相关的敏感信息关键词
        'aws_access_key', 'aws_secret_key', 'azure_subscription_id', 
        'azure_client_id', 'azure_client_secret', 'google_api_key', 
        'gcp_project', 'kubeconfig', 'docker_password', 'docker_auth', 
        'cloud_sql', 'cloud_function', 'vm_instance', 'service_account'
    ]
    sensitive_columns = [column for column in columns if any(keyword in column.lower() for keyword in sensitive_keywords)]
    return sensitive_columns

def extract_urls(text):
    # URL匹配正则表达式，支持多种URL scheme
    url_regex = r'([a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+)'
    urls = re.findall(url_regex, text)
    return urls

def analyze_db(db_path):
    conn = connect_to_db(db_path)
    tables = get_tables(conn)
    sensitive_summary = []  # 用于记录存在敏感数据的表格、字段及内容
    url_summary = []  # 用于记录提取的 URL 信息

    print(f"{Colors.HEADER}Analyzing database: {db_path}{Colors.ENDC}")
    for table in tables:
        table_name = table[0]
        print(f"{Colors.OKCYAN}Table: {table_name}{Colors.ENDC}")
        
        # Get and display table structure
        table_info = get_table_info(conn, table_name)
        columns = [col[1] for col in table_info]
        print(f"{Colors.BOLD}Columns:{Colors.ENDC} {', '.join(columns)}")
        
        # Display table data without table formatting
        table_data = get_table_data(conn, table_name)
        for row in table_data:
            print(f"\n{Colors.UNDERLINE}Record:{Colors.ENDC}")
            for col, val in zip(columns, row):
                print(f"{Colors.OKBLUE}{col}:{Colors.ENDC} {val}")
                # 提取 URL 信息
                if isinstance(val, str):
                    urls = extract_urls(val)
                    if urls:
                        url_summary.append((table_name, col, urls))
            print("-" * 50)

        # Simple analysis for sensitive data
        sensitive_columns = detect_sensitive_data(columns)
        if sensitive_columns:
            sensitive_rows = []
            for row in table_data:
                sensitive_data = {col: row[columns.index(col)] for col in sensitive_columns if row[columns.index(col)]}
                if sensitive_data:
                    sensitive_rows.append(sensitive_data)
            if sensitive_rows:
                print(f"{Colors.WARNING}Warning: Potential sensitive data detected in table '{table_name}' (Columns: {', '.join(sensitive_columns)}, Rows: {len(sensitive_rows)}){Colors.ENDC}")
                sensitive_summary.append((table_name, sensitive_columns, sensitive_rows))
        
        print("\n" + "="*60 + "\n")

    conn.close()

    # 输出敏感数据总结
    if sensitive_summary:
        print(f"{Colors.HEADER}——————————————————{Colors.ENDC}")
        print(f"{Colors.HEADER}以下存在敏感数据的表格及敏感数据字段：{Colors.ENDC}")
        for table_name, columns, rows in sensitive_summary:
            print(f"{Colors.OKGREEN}Table: {table_name} | Columns: {', '.join(columns)}{Colors.ENDC}")
            for row in rows:
                print(f"\n{Colors.UNDERLINE}Sensitive Record:{Colors.ENDC}")
                for col, val in row.items():
                    print(f"{Colors.OKBLUE}{col}:{Colors.ENDC} {val}")
                print("-" * 50)
    else:
        print("未检测到敏感数据。")

    # 输出 URL 提取总结
    if url_summary:
        print(f"{Colors.HEADER}——————————————————{Colors.ENDC}")
        print(f"{Colors.HEADER}以下是从数据库中提取的 URL 链接：{Colors.ENDC}")
        for table_name, column, urls in url_summary:
            print(f"{Colors.OKCYAN}Table: {table_name} | Column: {column}{Colors.ENDC}")
            for url in urls:
                print(f"{Colors.OKBLUE}URL:{Colors.ENDC} {url}")
            print("-" * 50)

def main():
    # 打印标识进入标记
    print_banner()

    # 使用 argparse 解析命令行参数
    parser = argparse.ArgumentParser(description="Analyze SQLite databases for sensitive data.")
    parser.add_argument("--dir", type=str, help="Directory containing SQLite database files")
    parser.add_argument("--file", type=str, help="Single SQLite database file")

    args = parser.parse_args()

    # 判断是处理单个文件还是目录
    if args.file:
        if not os.path.exists(args.file):
            print(f"The provided file path does not exist: {args.file}")
            sys.exit(1)
        analyze_db(args.file)
    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"The provided directory path does not exist: {args.dir}")
            sys.exit(1)
        for root, dirs, files in os.walk(args.dir):
            for file in files:
                if file.endswith('.sqlite') or file.endswith('.db'):
                    db_path = os.path.join(root, file)
                    analyze_db(db_path)
    else:
        print("Please specify either a single file using --file or a directory using --dir.")
        sys.exit(1)

if __name__ == "__main__":
    main()
