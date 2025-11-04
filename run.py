import os
import subprocess
import argparse
import zipfile
from multiprocessing import Pool
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

EROFS_UTILS_PATH = "erofs-bins/bin/extract.erofs"
JADX_PATH = 'jadx/bin/jadx'

SUCCESS = 0
MALFORMED = 1
ERROR = 2

def setup_logging(output_path):
    # 确保日志目录存在
    os.makedirs(output_path, exist_ok=True)
    log_file = os.path.join(output_path, 'result.log')
    formatter = logging.Formatter('[%(asctime)s] %(message)s')
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    
    try:
        from rich.logging import RichHandler
        console_handler = RichHandler(show_time=False)
    except ImportError:
        console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, console_handler]
    )


# 移除了重复的 extract_erofs_images 函数

def extract_erofs_images(input_img, output_dir):
    command = [
        EROFS_UTILS_PATH,
        "-i", input_img,
        "-o", output_dir,
        "-x"
    ]
    try:
        subprocess.run(command, check=True)
        logger.info(f"[+] Successfully extracted {input_img} to {output_dir}")
    except subprocess.CalledProcessError as e:
        logger.info(f"[!] Failed to extract {input_img}: {e}")
 

def decompile(input_path, output_dir, decompile_dir_name="decompiled"):
    # 这个相对路径计算依赖 output_dir 是 fs 目录的父目录
    real_input_path = os.path.relpath(input_path, output_dir)[3:].replace("//", "_")
    decompile_dir = os.path.join(output_dir, decompile_dir_name, real_input_path)
    os.makedirs(decompile_dir, exist_ok=True)
    log_path = os.path.join(decompile_dir, "jadx.log")
    cmd = [JADX_PATH, "-j", "4", "--deobf", '-d', decompile_dir, input_path,]
    try:
        with open(log_path, "w") as log_file:
            subprocess.run(cmd,
                check=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text = True
            )
            return SUCCESS
    except subprocess.CalledProcessError as e:
        # 将 print 改为 logger.info 以保持一致
        logger.info(f"[!] Failed to decompile {input_path}: {e}")
        return ERROR
    

def get_all_files_with_extension(directory, extension):
    return [f for f in Path(directory).rglob(f"*.{extension}")]


def check_opt(path) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    return False
        return True
    except zipfile.BadZipFile:
        logger.warning(f"[!] Bad zip file, skipping check_opt: {path}")
        return True # 当作 malformed 处理


def check_symlink(path) -> bool:
    return os.path.islink(path)


def decompile_with_extention(fs_path, output_path, extension, decompile_dir_name="decompiled"):
    files = get_all_files_with_extension(fs_path, extension)
    # for file in files:
    #     print(file)
    # return
    files_count = len(files)
    if files_count:
        # 尝试从 args 读取 cores，如果失败则回退
        try:
            num_cores = args.cores if args.cores is not None else os.cpu_count()
        except NameError:
            num_cores = os.cpu_count() # Fallback if args not defined
            
        num_processes = max(num_cores // 4, 1)
        logger.info(f'[+] Using {num_processes} processes for decompilation of {extension}')

        malformed = 0 
        decompile_args = []
        for f in files:
            if check_symlink(f) :
                malformed += 1
                continue
            # 传递 decompile_dir_name
            decompile_args.append((str(f), output_path, decompile_dir_name))

        with Pool(num_processes) as pool:
            results = pool.starmap(decompile, decompile_args)

        success = results.count(SUCCESS)
        error = results.count(ERROR)
        logger.info(f'[+] Decompilation of {extension} completed')
        logger.info(f'[+] Total : {files_count}')
        logger.info(f'[+] Success : {success}')
        logger.info(f'[+] Malformed : {malformed}')
        logger.info(f'[+] Error : {error}')
    else:
        logger.info(f'[!] No {extension} files found to decompile')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OTA payload dumper and decompiler')

    # --- 模式选择 (互斥) ---
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-p', '--payloadfile', type=str,
                            help='运行完整提取模式: payload/ROM 文件名')
    mode_group.add_argument('-D', '--decompile-only', type=str,
                            help='运行仅反编译模式: "fs" 目录的路径')

    # --- 通用选项 ---
    parser.add_argument('-o', default='output',
                        help='输出目录 (default: output). 用于 --payloadfile 模式。')
    parser.add_argument('--cores', type=int, default=None,
                        help='使用的 CPU 核心数 (default: 系统可用核心数)')
    
    # --- 完整提取模式选项 (仅 --payloadfile relevant) ---
    parser.add_argument('--diff', action='store_true',
                        help='(完整模式) 提取差分 OTA, 你需要将原始镜像放入 old 目录')
    parser.add_argument('--old', default='old',
                        help='(完整模式) 存放原始镜像的目录 (default: old)')
    parser.add_argument('--images', default="",
                        help='(完整模式) 要提取的镜像 (default: empty)')
    parser.add_argument('--decompile', action='store_true',
                        help='(完整模式) 提取后反编译所有的 jar 和 apk')

    args = parser.parse_args()
    start_time = time.time()

    # 根据选择的模式执行
    
    if args.payloadfile:
        # --- 完整提取模式 ---
        if not os.path.exists(args.payloadfile):
            print(f"[!] Error: Payload file not found: {args.payloadfile}")
            exit(1)
            
        output_path = os.path.abspath(args.o)
        input_path = os.path.abspath(args.payloadfile)
        img_path = os.path.join(output_path, "images")
        fs_path = os.path.join(output_path, "fs")

        os.makedirs(output_path, exist_ok=True)
        os.makedirs(img_path, exist_ok=True)
        os.makedirs(fs_path, exist_ok=True)

        setup_logging(output_path) # 日志在主输出目录

        logger.info(f'[+] Starting to extract images from {input_path}')
        logger.info(f'[+] Output directory created: {output_path}')
        logger.info(f'[+] Start extracting images from payload')
        os.system(f'python3 payload_dumper/payload_dumper.py {input_path} --out {img_path}')
        logger.info(f'[+] Images extracted to {img_path}')

        logger.info(f'[+] Start extracting EROFS images')
        assert os.path.exists(EROFS_UTILS_PATH), f"[!] erofs-utils not found, please download erofs-utils and place it in {EROFS_UTILS_PATH}"
        extract_args = []
        for filename in os.listdir(img_path):
            if filename.endswith(".img"):
                extract_args.append((os.path.join(img_path, filename), fs_path))

        num_cores = args.cores if args.cores is not None else os.cpu_count()
        num_processes = max(num_cores // 4, 1)    
        with Pool(num_processes) as pool:
            results = pool.starmap(extract_erofs_images, extract_args)

        framework_path = os.path.join(fs_path, "system/system/framework/framework.jar")
        if os.path.exists(framework_path):
            isFrameworkOpt = check_opt(framework_path)
            logger.info(f'[+] Is framework.jar odexed: {isFrameworkOpt}') 
            assert(isFrameworkOpt == False), "framework.jar is odexed, please deodex it first"
        else:
            logger.warning(f"[!] framework.jar not found at {framework_path}, skipping deodex check.")


        if args.decompile:
            assert os.path.exists(JADX_PATH), f"[!] jadx not found, please download jadx and place it in {JADX_PATH}"
            logger.info(f'[+] Start decompiling all jar and apk')
            # code_path = os.path.join(output_path, "decompiled") # 这个目录由 decompile 函数自动创建
            # os.makedirs(code_path, exist_ok=True) # 不需要提前创建

            # 使用默认 "decompiled" 目录
            decompile_with_extention(fs_path, output_path, "jar")
            decompile_with_extention(fs_path, output_path, "apk")

    elif args.decompile_only:
        # --- 仅反编译模式 ---
        fs_path = os.path.abspath(args.decompile_only)
        if not os.path.isdir(fs_path):
            print(f"[!] Error: Path is not a directory: {fs_path}")
            exit(1)
            
        # 输出放在上一级的 decompile 目录
        output_base_dir = os.path.dirname(fs_path) # e.g., /path/to/output
        decompile_dir_name = "decompile" # 您要求的目录名
        decompile_log_path = os.path.join(output_base_dir, decompile_dir_name)
        
        # 日志放在新的 decompile 目录中
        setup_logging(decompile_log_path) 
        
        logger.info(f'[+] Starting decompile-only mode for {fs_path}')
        logger.info(f'[+] Output will be in {decompile_log_path}')
        
        assert os.path.exists(JADX_PATH), f"[!] jadx not found, please download jadx and place it in {JADX_PATH}"

        # 调用 decompile，并传入新的目录名
        decompile_with_extention(fs_path, output_base_dir, "jar", decompile_dir_name=decompile_dir_name)
        decompile_with_extention(fs_path, output_base_dir, "apk", decompile_dir_name=decompile_dir_name)


    end_time = time.time()
    logger.info(f'[+] completed in {end_time - start_time:.2f} seconds')