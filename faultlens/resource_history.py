"""Checked Atop resource measurements with local administrator identities."""
import hashlib
import re

LABELS = {'DSK', 'NET', 'PRC', 'PRM'}
MAX_ROWS = 640


def integers(values, *, signed=False):
    pattern = r'-?[0-9]{1,20}' if signed else r'[0-9]{1,20}'
    if not all(re.fullmatch(pattern, value) for value in values):
        raise ValueError('Unsupported extended resource counter')
    return [int(value) for value in values]


def token(value):
    if not re.fullmatch(r'[^\s\x00-\x1f\x7f-\x9f]{1,64}', value):
        raise ValueError('Unsupported resource label')
    return value


def reference(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_row(label, fields):
    if not fields:
        raise ValueError('Missing extended resource fields')
    if label == 'DSK':
        if len(fields) != 10:
            raise ValueError('Unsupported disk prefix')
        token(fields[0])
        integers(fields[1:6])
        if any(value < -1 for value in integers(fields[6:9], signed=True)):
            raise ValueError('Unsupported disk counters')
        if not re.fullmatch(r'[0-9]{1,20}\.[0-9]{2}', fields[9]):
            raise ValueError('Unsupported queue measurement')
    elif label == 'NET':
        token(fields[0])
        if fields[0] == 'upper':
            if len(fields) != 18:
                raise ValueError('Unsupported network protocol prefix')
            integers(fields[1:])
        else:
            if len(fields) != 19:
                raise ValueError('Unsupported interface prefix')
            integers(fields[1:5] + fields[7:])
            integers(fields[5:7], signed=True)
    else:
        expected = 21 if label == 'PRC' else 23
        if len(fields) != expected:
            raise ValueError('Unsupported process prefix')
        pid, = integers(fields[:1])
        token(fields[1])
        if not 1 <= pid <= 2**31-1 or not re.fullmatch(r'[A-Za-z]', fields[2]):
            raise ValueError('Unsupported process identity/state')
        flag = 13 if label == 'PRC' else 16
        text = {1, 2, flag} | ({15} if label == 'PRC' else set())
        if fields[flag] not in {'y', 'n'}:
            raise ValueError('Missing process/thread distinction')
        tgid, = integers([fields[12 if label == 'PRC' else 15]])
        if not 1 <= tgid <= 2**31-1 or (fields[flag] == 'y' and tgid != pid):
            raise ValueError('Inconsistent process/thread identity')
        if label == 'PRC':
            token(fields[15])
        integers([value for index, value in enumerate(fields) if index not in text], signed=True)
        positive = (3, 4, 5, 12, 14, 16, 19, 20) if label == 'PRC' else (3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 17, 18)
        if any(int(fields[index]) < 0 for index in positive):
            raise ValueError('Negative process resource measurement')
    return fields


def normalize(rows, *, reset, interval, hz, page):
    disks, networks, processes, seen = [], [], {}, set()
    upper = None
    for label, fields in rows:
        identity = fields[0]
        key = label, identity
        if key in seen:
            raise ValueError('Duplicate extended resource record')
        seen.add(key)
        if label == 'DSK':
            if len(disks) >= 32:
                raise ValueError('Disk resource limit')
            values = integers(fields[1:6])
            disks.append({'device': identity, 'device_sha256': reference(identity), 'io_milliseconds': values[0],
                          'read_operations': values[1], 'read_bytes': values[2] * 512,
                          'write_operations': values[3], 'write_bytes': values[4] * 512})
        elif label == 'NET':
            if identity == 'upper':
                values = integers(fields[1:])
                upper = dict(zip(('tcp_in_segments', 'tcp_out_segments', 'udp_in_datagrams',
                    'udp_out_datagrams', 'ip_in_packets', 'ip_out_requests', 'ip_delivered_packets',
                    'ip_forwarded_packets', 'udp_input_errors', 'udp_no_port', 'tcp_active_opens',
                    'tcp_passive_opens', 'tcp_established_snapshot', 'tcp_retransmitted_segments',
                    'tcp_input_errors', 'tcp_output_resets', 'tcp_checksum_errors'), values))
            else:
                if len(networks) >= 32:
                    raise ValueError('Network interface limit')
                values = integers(fields[1:5] + fields[7:11])
                networks.append(dict(interface=identity, interface_sha256=reference(identity), **dict(zip(
                    ('received_packets', 'received_bytes', 'transmitted_packets', 'transmitted_bytes',
                     'receive_errors', 'transmit_errors', 'receive_drops', 'transmit_drops'), values))))
        else:
            if identity not in processes and len(processes) >= 256:
                raise ValueError('Process resource limit')
            if label == 'PRC' and int(fields[3]) != hz:
                raise ValueError('Inconsistent process clock units')
            if label == 'PRM' and int(fields[3]) != page:
                raise ValueError('Inconsistent process page units')
            processes.setdefault(identity, {})[label] = fields
    if upper is None or any(set(value) != {'PRC', 'PRM'} for value in processes.values()):
        raise ValueError('Incomplete extended resource sample')
    count, threads, exited, cpu_ticks, resident, swap, faults = 0, 0, 0, 0, 0, 0, 0
    details = []
    for pid, value in processes.items():
        cpu, memory = value['PRC'], value['PRM']
        if (cpu[2] != memory[2] or cpu[12] != memory[15] or cpu[13] != memory[16]
                or cpu[1] != memory[1]):
            raise ValueError('Mixed process measurements')
        scope = 'since_boot' if reset else 'exited_accounting_unlocalized' if cpu[2] == 'E' else 'recorded_interval'
        included = not reset and cpu[13] == 'y' and cpu[2] != 'E'
        details.append({'pid': int(pid), 'tgid': int(cpu[12]), 'name': cpu[1],
            'state': cpu[2], 'is_process': cpu[13] == 'y', 'wait_channel': cpu[15],
            'measurement_scope': scope, 'included_in_aggregate': included,
            'clock_ticks_per_second': hz, 'user_cpu_ticks': int(cpu[4]), 'system_cpu_ticks': int(cpu[5]),
            'reported_cpu_seconds': round((int(cpu[4])+int(cpu[5]))/hz, 6),
            'reported_virtual_bytes': int(memory[4])*1024, 'reported_resident_bytes': int(memory[5])*1024,
            'reported_swap_bytes': int(memory[14])*1024, 'reported_major_page_faults': int(memory[10])})
        if cpu[13] == 'n':
            threads += 1
            continue
        count += 1
        if cpu[2] == 'E':
            exited += 1
            continue
        cpu_ticks += int(cpu[4]) + int(cpu[5])
        faults += int(memory[10])
        resident += int(memory[5]) * 1024
        swap += int(memory[14]) * 1024
    if reset:
        return {'state': 'since_boot_aggregate_excluded', 'disks': [], 'interfaces': [],
                'network_protocols': None, 'processes': None, 'process_details': details}
    return {'state': 'available', 'disks': disks, 'interfaces': networks, 'network_protocols': upper,
            'processes': {'reported_processes': count, 'excluded_thread_rows': threads,
                'state': 'available' if processes else 'no_process_rows_reported',
                'reported_exited_processes': exited, 'cpu_seconds': round(cpu_ticks / hz, 6),
                'resident_bytes_sum_snapshot': resident, 'swap_bytes_sum_snapshot': swap,
                'major_page_faults': faults, 'coverage': 'reported_rows_only'},
            'disk_coverage': 'reported_devices_only' if disks else 'no_device_rows_reported',
            'interface_coverage': 'reported_interfaces_only' if networks else 'no_interface_rows_reported',
            'interval_s': interval, 'process_details': details}
