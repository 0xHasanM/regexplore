import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
import os
import codecs

COLUMNS = [
    ('Executable ', str),
    ('MRUPosition', str),
    ('OpenedOn', str),
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    key,
    hive_name,
    output_path='regexplore/CIDSizeMRU.csv'
    ):
    
    os.makedirs('regexplore', exist_ok=True) 
    
    with open(output_path, 'w', encoding='utf-8') as file_handle:
        header = "Executable,MRUPosition,OpenedOn\n"
        file_handle.write(header)
        for result in process_values(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        ):
            file_handle.write(f'{result[0]}, {result[1]}, {result[2]}\n')
    return

def ValuesOut(
    _registry_walker,
    kernel,
    hive_list,
    key,
    hive_name,
    file_output=False
    ):
    
    for result in process_values(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        ):
            yield (0, (result))

def process_values(
    _registry_walker,
    kernel,
    hive_list,
    key,
    hive_name,
    file_output=False
    ):
    
    """
    Process registry values and return device name and data.
    """
    walker_options = {
        'layer_name': kernel.layer_name,
        'symbol_table': kernel.symbol_table_name,
        'hive_list': hive_list,
        'key': key,
        'hive_name': hive_name,
        'recurse': False,
    }
    entries = {}
    LastWriteTime = ''
    for value in _registry_walker(**walker_options):
            entries[value[1][2]] = value[1][3]
            LastWriteTime = value[1][0]
    for result in process_mru(entries, LastWriteTime):
        yield result
            
def process_mru(entries, LastWriteTime):
    mruList = entries.get('MRUListEx', b'')
    mruPositions = {}
    i = 0
    index = 0
    
    while index < len(mruList) - 4:
        mruPos = int.from_bytes(mruList[index:index+4], byteorder='little', signed=False)
        if mruPos == 0xFFFFFFFF:
            break
        mruPositions[mruPos] = i
        i += 1
        index += 4

    for value_name, value_data in entries.items():
        if value_name == 'MRUListEx':
            continue
        
        mru = mruPositions.get(int(value_name), -1)
        
        chunks = value_data.decode('utf-16le').split('\x00')
        exeName = chunks[0]
        openedOn = LastWriteTime if mru == 0 else 'None'
        
        yield exeName, str(mru), openedOn

def CIDSizeMRU(
    _registry_walker,
    kernel,
    hive_list,
    hive = None,
    file_output=False
    ):
    """
    Create a TreeGrid with device name and data.
    """
    key = "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU"
    hive_name = "NTUSER.DAT"
    
    if file_output:
        write_result_to_csv(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        )
        return
    else:
        generator = ValuesOut(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        )
    
        return TreeGrid(
            columns=COLUMNS,
            generator=generator,
        )
