import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
from volatility3.framework.interfaces import layers
import os

# Define the columns for the TreeGrid
COLUMNS = [
    ("Timestamp", str),
    ("Path", str)
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    output_path='regexplore/AmcacheInventoryApplicationShortcut.csv'
    ):
    
    os.makedirs('regexplore', exist_ok=True)
        
    entries = process_values(
        _registry_walker,
        kernel,
        hive_list,
        key,
        hive_name
    )
    
    with open(output_path, 'w', encoding='utf-8') as file_handle:
        header = "Timestamp,ShortcutPath\n"
        file_handle.write(header)
        for registry_key in entries.keys():
            if entries[registry_key].get("ShortcutPath", "") == "":
                continue
            file_handle.write(
                f'{entries[registry_key].get("Timestamp", "")},'
                f'{entries[registry_key].get("ShortcutPath", "").replace(",", ";")}\n'
            )
        
    return

def ValuesOut(
    _registry_walker,
    kernel,
    hive_list,
    key,
    hive_name
    ):

    entries = process_values(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        )
        
    for registry_key in entries.keys():
        if entries[registry_key].get("ShortcutPath", "") == "":
            continue
        result = (
            0,
            (
                entries[registry_key].get("Timestamp", ""),
                entries[registry_key].get("ShortcutPath", "").replace(",", ";"),
            ),
        )
        yield result

def process_values(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    file_output=False
    ):
    
    """
    Process registry values and return Programs data.
    """
    # Define options for the registry walker
    walker_options = {
        "layer_name": kernel.layer_name,
        "symbol_table": kernel.symbol_table_name,
        "hive_list": hive_list,
        "key": key,
        "hive_name": hive_name,
        "recurse": True,
    }

    # Iterate through the registry walker output
    entries = {}
    for subkey in _registry_walker(**walker_options):
            # Only process values, not keys
            if str(subkey[1][2]) != 'Key':
                registry_key = subkey[1][1]
                registry_value = subkey[1][2]
                try:
                    registry_data = subkey[1][3].replace(b'\x00', b'').decode('utf-8', errors='ignore')
                except:
                    continue

                # Initialize the registry key entry if it doesn't exist
                if registry_key not in entries:
                    entries[registry_key] = {'Timestamp': str(subkey[1][0])}

                # Store the registry value and data
                entries[registry_key][registry_value] = registry_data
    return entries
    
def AmcacheInventoryApplicationShortcut(
    _registry_walker,
    kernel,
    hive_list,
    hive = None,
    file_output=False
    ):
    """
    Create a TreeGrid with Programs data.
    """
    # Define the registry key and hive name to process
    key = 'ROOT\InventoryApplicationShortcut'
    hive_name = 'Amcache.hve'

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
            hive_name,
        )
    
        return TreeGrid(
            columns=COLUMNS,
            generator=generator,
        )