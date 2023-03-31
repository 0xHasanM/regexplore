import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
import os

COLUMNS = [
    ('Key', str),
    ('Program', str),
    ('Execution Time', str),
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    keys,
    hive_name,
    output_path='regexplore/BamDam.csv'
    ):
    
    os.makedirs('regexplore', exist_ok=True)
    
    entries = process_values(
            _registry_walker,
            kernel,
            hive_list,
            keys,
            hive_name
        )
    
    with open(output_path, 'w', encoding='utf-8') as file_handle:
        header = "Key,Program,Execution Time\n"
        file_handle.write(header)
        for entries in process_values(
            _registry_walker,
            kernel,
            hive_list,
            keys,
            hive_name
        ):
            file_handle.write(f'{entries[0]}, {entries[1]}, {entries[2]}\n')
    return

def ValuesOut(
    _registry_walker,
    kernel,
    hive_list,
    keys,
    hive_name,
    file_output=False
    ):
    
    for entries in process_values(
            _registry_walker,
            kernel,
            hive_list,
            keys,
            hive_name
        ):
            yield (0, (entries))

def process_values(
    _registry_walker,
    kernel,
    hive_list,
    keys,
    hive_name,
    file_output=False
    ):
    
    """
    Process registry values and return device name and data.
    """
    FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
    for i in range(1,5):
        for key in keys:
            walker_options = {
                'layer_name': kernel.layer_name,
                'symbol_table': kernel.symbol_table_name,
                'hive_list': hive_list,
                'key': key.replace('*', str(i)),
                'hive_name': hive_name,
                'recurse': True,
            }
            for subkey in _registry_walker(**walker_options):
                if subkey[1][2] == "Version" or subkey[1][2] == "SequenceNumber" or str(subkey[1][2]) == 'Key':
                    continue
                registry_key = subkey[1][1]
                registry_value = subkey[1][2]
                try:
                    registry_data = subkey[1][3]
                    timestamp = int.from_bytes(registry_data[:8], "little") / 10
                    last_execution_time = str(FILETIME_null_date + datetime.timedelta(microseconds=timestamp))
                except Exception as e:
                    continue
                result = (
                        f'{key.replace("*", str(i))}\{registry_key}',
                        registry_value,
                        last_execution_time,
                    )
                yield result

def BamDam(
    _registry_walker,
    kernel,
    hive_list,
    hive = None,
    file_output=False
    ):
    """
    Create a TreeGrid with device name and data.
    """
    
    keys = [r"ControlSet00*\Services\bam\UserSettings" ,r"ControlSet00*\Services\bam\State\UserSettings", r"ControlSet00*\Services\dam\UserSettings"]
    hive_name = 'SYSTEM'
        
    if file_output:
        write_result_to_csv(
            _registry_walker,
            kernel,
            hive_list,
            keys,
            hive_name
        )
        return
    else:
        generator = ValuesOut(
            _registry_walker,
            kernel,
            hive_list,
            keys,
            hive_name
        )
    
        return TreeGrid(
            columns=COLUMNS,
            generator=generator,
        )
