import subprocess
import re
import time
import csv
import sys

MALFORM_TYPES = [0, 1, 6, 7, 8]
MALFORM_TYPE_NAMES = ["NONE", "MALFORM_IP_CHECKSUM", "WRONG_IP_LENGTH", "WRONG_UDP_LENGTH", "JUMBO_CLAIM", "SIZE_MIXED"]
PERCENTAGES = [20, 40, 60, 80, 100]
TEST_DURATION = 30
L2FWD_CMD = "./examples/dpdk-rq3-l2fwd -l 0-1 --vdev net_ring0 --vdev=net_ring1 -- -p 0x3 -T 5"

def parse_l2fwd_output(output):

    # Using regex to match output
    throughput_match = re.search(r'Throughput Samples in Mpps\s*\n([\d\.\s]+)', output, re.DOTALL)
    throughput_samples = []
    sample_text = throughput_match.group(1).strip()
    throughput_samples = [float(x) for x in sample_text.split() if x]

    latency_match = re.search(r'Per Packet Latency Samples \(nanoseconds\):\s*\n([\d\.\s]+)', output, re.DOTALL)
    latency_samples = []
    sample_text = latency_match.group(1).strip()
    latency_samples = [float(x) for x in sample_text.split() if x]

    avg_throughput = sum(throughput_samples) / len(throughput_samples) if throughput_samples else 0
    avg_latency = sum(latency_samples) / len(latency_samples) if latency_samples else 0

    return {
        'avg_throughput_mpps': avg_throughput,
        'avg_latency_ns': avg_latency,
        'throughput_samples': throughput_samples,
        'latency_samples': latency_samples
    }

def parse_perf_output(output):
    metrics = {}
    patterns = {
        'cache_misses': r'([\d,]+)\s+cache-misses',
        'cache_references': r'([\d,]+)\s+cache-references',
        'llc_load_misses': r'([\d,]+)\s+LLC-load-misses',
        'llc_loads': r'([\d,]+)\s+LLC-loads',
        'dtlb_load_misses': r'([\d,]+)\s+dTLB-load-misses',
        'dtlb_loads': r'([\d,]+)\s+dTLB-loads',
        'l1_dcache_misses': r'([\d,]+)\s+L1-dcache-load-misses',
        'l1_dcache_loads': r'([\d,]+)\s+L1-dcache-loads',
        'instructions': r'([\d,]+)\s+instructions',
        'cycles': r'([\d,]+)\s+cycles',
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            # Remove commas and convert to int
            metrics[key] = int(match.group(1).replace(',', ''))
        else:
            metrics[key] = 0
    
    metrics['cache_miss_rate'] = (metrics['cache_misses'] / metrics['cache_references']) * 100
    metrics['llc_miss_rate'] = (metrics['llc_load_misses'] / metrics['llc_loads']) * 100
    metrics['dtlb_miss_rate'] = (metrics['dtlb_load_misses'] / metrics['dtlb_loads']) * 100
    metrics['l1_miss_rate'] = (metrics['l1_dcache_misses'] / metrics['l1_dcache_loads']) * 100
    metrics['ipc'] = metrics['instructions'] / metrics['cycles']
    return metrics

def run_test(malform_type, malform_perc, type_name):
    # print(f"Testing: {type_name} (type={malform_type}) at {malform_perc}%")
    
    cmd = f"sudo {L2FWD_CMD} -y {malform_type} -e {malform_perc}"
    
    print(f"Starting l2fwd: {cmd}")
    l2fwd_process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    time.sleep(2)
    
    # get l2fwd PID
    try:
        pid_output = subprocess.check_output("pgrep dpdk-rq3-l2fwd", shell=True, text=True)
        l2fwd_pid = pid_output.strip().split()[0]
        print(f"L2fwd PID: {l2fwd_pid}")
    except subprocess.CalledProcessError:
        print("Bad: Could not find l2fwd process")
        return None
    
    perf_cmd = f"sudo perf stat -e cache-misses,cache-references,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,L1-dcache-load-misses,L1-dcache-loads,instructions,cycles -p {l2fwd_pid} sleep {TEST_DURATION}"
    print(f"Running perf for {TEST_DURATION} seconds...")
    
    perf_result = subprocess.run(
        perf_cmd,
        shell=True,
        capture_output=True,
        text=True
    )
    
    perf_output = perf_result.stderr
    
    #subprocess.run(f"sudo kill -SIGINT {l2fwd_pid}", shell=True)
    
    # Wait for l2fwd to finish and capture output
    try:
        l2fwd_output, _ = l2fwd_process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        print("why it taking 120 seconds bruh")
        l2fwd_process.kill()
        l2fwd_output, _ = l2fwd_process.communicate()
    
    subprocess.run("sudo pkill -9 dpdk-rq3-l2fwd", shell=True, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    l2fwd_metrics = parse_l2fwd_output(l2fwd_output)
    perf_metrics = parse_perf_output(perf_output)
    
    result = {
        'malform_type': malform_type,
        'type_name': type_name,
        'malform_percentage': malform_perc,
        'avg_throughput_mpps': l2fwd_metrics['avg_throughput_mpps'],
        'avg_latency_ns': l2fwd_metrics['avg_latency_ns'],
        **perf_metrics
    }
    return result

def main():
    results = []
    for i, malform_type in enumerate(MALFORM_TYPES):
        type_name = MALFORM_TYPE_NAMES[i]
        
        for malform_perc in PERCENTAGES:
            result = run_test(malform_type, malform_perc, type_name)
            results.append(result)
    
    csv_file = 'malform_complete_results.csv'
    
    if results:
        fieldnames = results[0].keys()
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
    return 0

if __name__ == "__main__":
    main()
