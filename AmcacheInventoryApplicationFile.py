import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
import os 

# Define the columns for the TreeGrid
COLUMNS = [
    ("Timestamp", str),
    ("Path", str),
    ("Name", str),
    ("Product", str),
    ("Publisher", str),
    ("Version", str),
    ("SHA1", str)
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    output_path='regexplore/AmcacheInventoryApplicationFile.csv'
    ):
    
    walker_options = {
        "layer_name": kernel.layer_name,
        "symbol_table": kernel.symbol_table_name,
        "hive_list": hive_list,
        "key": key,
        "hive_name": hive_name,
        "recurse": True,
    }
    
    os.makedirs('regexplore', exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as file_handle:
        header = "Timestamp,Path,Name,Product,Publisher,Version,SHA1\n"
        file_handle.write(header)
        entries = {}
        for subkey in _registry_walker(**walker_options):
            try:
                # Only process values, not keys
                if str(subkey[1][2]) != 'Key':
                    registry_key = subkey[1][1]
                    registry_value = subkey[1][2]
                    registry_data = subkey[1][3].replace(b'\x00', b'').decode('utf-8', errors='ignore')
    
                    # Initialize the registry key entry if it doesn't exist
                    if registry_key not in entries:
                        entries[registry_key] = {'Timestamp': str(subkey[1][0])}
    
                    # Store the registry value and data
                    entries[registry_key][registry_value] = registry_data
    
                    # Convert the entry into a tuple and yield it
                else:
                    file_handle.write(
                        f'{entries[registry_key]["Timestamp"]},'
                        f'{entries[registry_key].get("LowerCaseLongPath", "").replace(",", ";")},'
                        f'{entries[registry_key].get("Name", "").replace(",", ";")},'
                        f'{entries[registry_key].get("ProductName", "").replace(",", ";")},'
                        f'{entries[registry_key].get("Publisher", "").replace(",", ";")},'
                        f'{entries[registry_key].get("Version", "").replace(",", ";")},'
                        f'{entries[registry_key].get("FileId", "").replace(",", ";")}\n'
                    )
                    entries = {}
    
            except (KeyError, UnboundLocalError):
                continue

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
        try:
            # Only process values, not keys
            if str(subkey[1][2]) != 'Key':
                registry_key = subkey[1][1]
                registry_value = subkey[1][2]
                registry_data = subkey[1][3].replace(b'\x00', b'').decode('utf-8', errors='ignore')

                # Initialize the registry key entry if it doesn't exist
                if registry_key not in entries:
                    entries[registry_key] = {'Timestamp': str(subkey[1][0])}

                # Store the registry value and data
                entries[registry_key][registry_value] = registry_data

                # Convert the entry into a tuple and yield it
            else:
                result = (
                    0,
                    (
                        entries[registry_key].get("Timestamp", ""),
                        entries[registry_key].get("LowerCaseLongPath", ""),
                        entries[registry_key].get("Name", ""),
                        entries[registry_key].get("ProductName", ""),
                        entries[registry_key].get("Publisher", ""),
                        entries[registry_key].get("Version", ""),
                        str(entries[registry_key].get("FileId", "")).lstrip('0000')
                    ),
                )
                yield result
                entries = {}

        except (KeyError, UnboundLocalError):
            continue

    # Convert entries into a tuple format suitable for the TreeGrid

def AmcacheInventoryApplicationFile(
    _registry_walker,
    kernel,
    hive_list,
    file_output=False
    ):
    
    """
    Create a TreeGrid with Programs data.
    """
    # Define the registry key and hive name to process
    key = 'ROOT\InventoryApplicationFile'
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
        generator = process_values(
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