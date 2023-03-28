import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
import os
import codecs
COLUMNS = [
    ('Timestamp', str),
    ('Hive', str),
    ('FileName', str),
    ('Path1', str),
    ('Path2', str),
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    keys_hive_mapping,
    output_path='regexplore/AppPaths.csv'
    ):
    
    os.makedirs('regexplore', exist_ok=True)
    
    entries = process_values(
            _registry_walker,
            kernel,
            hive_list,
            keys_hive_mapping
        )
    
    with open(output_path, 'w', encoding='utf-8') as file_handle:
        header = "Timestamp,Hive,FileName,Path1,Path2\n"
        file_handle.write(header)
        for registry_key in entries.keys():
                        file_handle.write(
                            f'{entries[registry_key].get("Timestamp", "")},'
                            f'{entries[registry_key].get("hive_path", "")},'
                            f'{registry_key},'
                            f'{entries[registry_key].get("(Default)", "")},'
                            f'{entries[registry_key].get("Path", "")}\n'
                        )
    return

def ValuesOut(
    _registry_walker,
    kernel,
    hive_list,
    keys_hive_mapping,
    file_output=False
    ):

    entries = process_values(
            _registry_walker,
            kernel,
            hive_list,
            keys_hive_mapping
        )
    
    for registry_key in entries.keys():
        result = (
            0,
            (
                entries[registry_key].get("Timestamp", ""),
                entries[registry_key].get('hive_path', ''),
                registry_key,
                entries[registry_key].get("(Default)", ""),
                entries[registry_key].get("Path", ""),
            ),
        )
        yield result

def process_values(
    _registry_walker,
    kernel,
    hive_list,
    keys_hive_mapping,
    file_output=False
    ):
    
    """
    Process registry values and return device name and data.
    """
    entries = {}
    for hive_name, key in keys_hive_mapping.items():
        walker_options = {
            'layer_name': kernel.layer_name,
            'symbol_table': kernel.symbol_table_name,
            'hive_list': hive_list,
            'key': key,
            'hive_name': hive_name,
            'recurse': True,
        }
        for subkey in _registry_walker(**walker_options):
            if str(subkey[1][2]) != 'Key':
                hive_path = subkey[2]
                registry_key = subkey[1][1]
                registry_value = subkey[1][2]
                try:
                    registry_data = codecs.decode(subkey[1][3], "utf-16le")
                except:
                    continue
                # Initialize the registry key entry if it doesn't exist
                if registry_key not in entries:
                    entries[registry_key] = {'Timestamp': str(subkey[1][0])}
                    entries[registry_key]['hive_path'] = hive_path
                entries[registry_key][registry_value] = registry_data
                # Store the registry value and data
    return entries

def AppPaths(
    _registry_walker,
    kernel,
    hive_list,
    hive = None,
    file_output=False
    ):
    """
    Create a TreeGrid with device name and data.
    """
    if hive != None:
        if hive == "SOFTWARE":
            keys_hive_mapping = {
                'SOFTWARE':'Microsoft\Windows\CurrentVersion\App Paths'
            }
        elif hive == "ntuser":
            keys_hive_mapping = {
                'ntuser.dat':'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
            }
    else:
        keys_hive_mapping = {
            'SOFTWARE':'Microsoft\Windows\CurrentVersion\App Paths',
            'ntuser.dat':'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
        }
    
    if file_output:
        write_result_to_csv(
            _registry_walker,
            kernel,
            hive_list,
            keys_hive_mapping
        )
        return
    else:
        generator = ValuesOut(
            _registry_walker,
            kernel,
            hive_list,
            keys_hive_mapping
        )
    
        return TreeGrid(
            columns=COLUMNS,
            generator=generator,
        )
