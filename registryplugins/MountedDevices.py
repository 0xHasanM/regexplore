import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
import os
import codecs

COLUMNS = [
    ('Device name', str),
    ('Device Data', str)
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    output_path='regexplore/MountedDevices.csv'
    ):
    
    walker_options = {
        'layer_name': kernel.layer_name,
        'symbol_table': kernel.symbol_table_name,
        'hive_list': hive_list,
        'key': key,
        'hive_name': hive_name,
        'recurse': False,
    }
    
    os.makedirs('regexplore', exist_ok=True)

    with open(output_path, 'w', encoding='utf-16le') as file_handle:
        header = 'Device Name, Device Data\n'
        file_handle.write(header)
        for value in _registry_walker(**walker_options):
            device_name = value[1][2]
            try:
                device_data = codecs.decode(value[1][3], "utf-16le")
            except:
                continue
            file_handle.write(f'{device_name.replace(",", ";")},{device_data.replace(",", ";")}\n')
    return

def process_values(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
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
        
    for value in _registry_walker(**walker_options):
        device_name = value[1][2]
        try:
            device_data = codecs.decode(value[1][3], "utf-16le")
        except:
            continue
        result = (
            0,
            (
                device_name,
                device_data.replace(",", ";")
            ),
        )
        yield result

def MountedDevices(
    _registry_walker,
    kernel,
    hive_list,
    hive = None,
    file_output=False
    ):
    """
    Create a TreeGrid with device name and data.
    """
    key = 'MountedDevices'
    hive_name = 'SYSTEM'
    
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
        generator = process_values(
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
