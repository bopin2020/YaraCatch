#!/usr/python3
import sys
import json
import yara
import psutil

global_verbose = False

rules = yara.compile('checkkeyiv.yara')
 
processes = psutil.process_iter(['pid', 'name'])


def read_process_memory(pid, address, size):
    memory_file = f"/proc/{pid}/mem"
    
    try:
        with open(memory_file, 'rb') as f:
            # 定位到指定地址的偏移量
            f.seek(address)
            
            # 读取指定大小的内存内容
            memory_data = f.read(size)
            
        return memory_data
    except IOError:
        print(f"无法访问进程 {pid} 的内存")
        return None


def enum_process():
    for pro in psutil.process_iter(['pid', 'name']):
        # type semantic syntax error
        print(str(pro.info['pid']) + '\t' + pro.info['name'])

def find_process_byname(name):
    for pro in psutil.process_iter(['pid', 'name']):
        if pro.info['name'] == name:
            yield pro.info['pid']

def match_callback(data):
    print("callback" + data)
    return yara.CALLBACK_CONTINUE;

def scan_pid(pid):
    try:
        # 获取进程的内存信息
        process = psutil.Process(pid)
        #print("process metadata: pid: {} name: {}".format(process['pid'],process['name']))
        memory_regions = process.memory_maps()

        for region in memory_regions:
            print(region)
            # 读取内存数据
            data = region.rss
            # 调用YARA规则进行匹配
            matches = rules.match(data=data, callable=match_callback,fast=True)

            for match in matches:
                # 判断规则类型
                if 'strings' in match.meta:
                    # 如果是字符串规则，则打印字符串
                    print("String Match found in process {}: {}".format("sshd", match.strings[0]))
                elif 'int' in match.meta:
                    # 如果是整数规则，则打印整数
                    print("Integer Match found in process {}: {}".format("sshd", data))
                elif 'memory' in match.meta:
                    # 如果是内存规则，则读取内存数据并以hex显示
                    print("Memory Match found in process {}: {}".format("sshd", data.hex()))
    
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # contine scan process when exception
        print("error pid: {}".format(str(pid)))

def scan_pid2(process_id):
    global global_verbose
    proc = psutil.Process(process_id)
    # 获取进程的内存映射信息
    proc_maps = proc.memory_maps()
    
    # 执行匹配操作
    for proc_map in proc_maps:
        # only scan heap memory
        if proc_map.path == '[heap]':
            print("heap memory")
            #proc_range = range(proc_map.rss, proc_map.size - 1)
            #matches = rules.match(data=open(proc_map.path, 'rb'), mem_offset=proc_range)
            #matches = rules.match(data=data, callable=match_callback,fast=True) 
            matches = rules.match(pid= int(process_id))
            if global_verbose == True:
                print(json.dumps(matches,indent=4))

            result = matches['main'][0]['strings']
            #print(json.dumps(result,indent=4))
            for res in result:
                print(f"identifier: {res['identifier']}  data: {res['data']}  offset: {hex(res['offset'])}")
                memory = read_process_memory(int(process_id),int(res['offset']),48)
                print(memory)

        else:
            continue    

def scan_name(process_name):
    pass

def scan_all():
    for proc in processes:
        scan_pid(proc['pid'])

if __name__ == '__main__':
    print("[*] init...")
    #enum_process()
    #sys.argv[1] = "sshd"
    if "-v" in sys.argv:
        global_verbose = True
    sshdpids = find_process_byname(sys.argv[1])
    count = 0
    error_count = 0
    for pid in sshdpids:
        print("[*] start scan {} {} process with count: {}".format(sys.argv[1],str(pid),count))
        count += 1
        try:
            scan_pid2(pid)
        except Exception as e:
            print("[-] except {} {}".format(str(pid),e))
            error_count += 1

    # pids = find_process_byname(sys.argv[1])
    # print(sys.argv[1] + ":" + ','.join({str(pid) for pid in pids}))
