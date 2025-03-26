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


def extract_erofs_images(input_dir, output_dir):
    for filename in os.listdir(input_dir):
        if filename.endswith(".img"):
            img_path = os.path.join(input_dir, filename)
            command = [
                EROFS_UTILS_PATH,
                "-i", img_path,
                "-o", output_dir,
                "-x"
            ]
            try:
                subprocess.run(command, check=True)
                logger.info(f"[+] Successfully extracted {filename} to {subdir_path}")
            except subprocess.CalledProcessError as e:
                logger.info(f"[!] Failed to extract {filename}: {e}")


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
  

def decompile(input_path, output_dir):
    real_input_path = os.path.relpath(input_path, output_dir)[3:].replace("//", "_")
    decompile_dir = os.path.join(output_dir, "decompiled", real_input_path)
    os.makedirs(decompile_dir, exist_ok=True)
    log_path = os.path.join(decompile_dir, "jadx.log")
    cmd = [JADX_PATH, "-j", "4", '-d', decompile_dir, input_path,]
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
        print(f"[!] Failed to decompile {input_path}: {e}")
        return ERROR
    

def get_all_files_with_extension(directory, extension):
    return [f for f in Path(directory).rglob(f"*.{extension}")]


def check_opt(path) -> bool:
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                return False
    return True


def check_symlink(path) -> bool:
    return os.path.islink(path)


def decompile_with_extention(fs_path,output_path, extension):
    files = get_all_files_with_extension(fs_path, extension)
    files_count = len(files)
    if files_count:
        num_cores = args.cores if args.cores is not None else os.cpu_count()
        num_processes = max(num_cores // 4, 1)
        logger.info(f'[+] Using {num_processes} processes for decompilation')

        malformed = 0 
        decompile_args = []
        for f in files:
            if check_symlink(f) or check_opt(f) :
                malformed += 1
                continue
            decompile_args.append((str(f), output_path))

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
        logger.info('[!] No files found to decompile')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OTA payload dumper')
    parser.add_argument('payloadfile', type=argparse.FileType('rb'),
                        help='payload/ROM file name')
    parser.add_argument('-o', default='output',
                        help='output directory (default: output)')
    parser.add_argument('--diff', action='store_true',
                        help='extract differential OTA, you need put original images to old dir')
    parser.add_argument('--old', default='old',
                        help='directory with original images for differential OTA (default: old)')
    parser.add_argument('--images', default="",
                        help='images to extract (default: empty)')
    parser.add_argument('--decompile', action='store_true',
                        help='decompile all jar and apk')
    parser.add_argument('--cores', type=int, default=None,
                        help='number of CPU cores to use (default: system available cores)')

    args = parser.parse_args()
    start_time = time.time()
    
    output_path = os.path.abspath(args.o)
    input_path = os.path.abspath(args.payloadfile.name)
    img_path = os.path.join(output_path, "images")
    fs_path = os.path.join(output_path, "fs")

    os.makedirs(output_path, exist_ok=True)
    os.makedirs(img_path, exist_ok=True)
    os.makedirs(fs_path, exist_ok=True)

    setup_logging(output_path)

    logger.info(f'[+] Starting to extract images from {args.payloadfile}')
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


    framework_path = fs_path + "/system/system/framework/framework.jar"
    isFrameworkOpt = check_opt(framework_path)
    logger.info(f'[+] Is framework.jar odexed: {isFrameworkOpt}') 
    assert(isFrameworkOpt == False), "framework.jar is odexed, please deodex it first"

    if args.decompile:
        assert os.path.exists(JADX_PATH), f"[!] jadx not found, please download jadx and place it in {JADX_PATH}"
        logger.info(f'[+] Start decompiling all jar and apk')
        code_path = os.path.join(output_path, "decompiled")
        os.makedirs(code_path, exist_ok=True)

        decompile_with_extention(fs_path, output_path, "jar")
        decompile_with_extention(fs_path, output_path, "apk")


    end_time = time.time()
    logger.info(f'[+] completed in {end_time - start_time:.2f} seconds')


