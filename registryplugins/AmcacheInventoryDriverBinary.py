import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
from volatility3.framework.interfaces import layers
import os
import codecs
# Define the columns for the TreeGrid
COLUMNS = [
    ("Timestamp", str),
    ("DriverLastWriteTime", str),
    ("DriverCompany", str),
    ("Product", str),
    ("ProductVersion", str),
    ("DriverName", str),
    ("DriverVersion", str),
    ("Path", str),
    ("SHA1", str),
]

def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    output_path='regexplore/AmcacheInventoryDriverBinary.csv'
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
        header = "Timestamp,DriverLastWriteTime,DriverCompany,DriverName,DriverVersion,Product,ProductVersion,Path,SHA1\n"
        file_handle.write(header)
        for registry_key in entries.keys():
            if entries[registry_key].get("DriverLastWriteTime", "") == "":
                continue
            file_handle.write(
                f'{entries[registry_key].get("Timestamp", "")},'
                f'{entries[registry_key].get("DriverLastWriteTime", "").replace(",", ";")},'
                f'{entries[registry_key].get("DriverCompany", "").replace(",", ";")},'
                f'{entries[registry_key].get("Product", "").replace(",", ";")},'
                f'{entries[registry_key].get("ProductVersion", "").replace(",", ";")},'
                f'{entries[registry_key].get("DriverName", "").replace(",", ";")},'
                f'{entries[registry_key].get("DriverVersion", "").replace(",", ";")},'
                f'{entries[registry_key].get("Path", "").replace(",", ";")},'
                f'{entries[registry_key].get("DriverId", "").replace("0000", "")}\n'
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
        if entries[registry_key].get("DriverLastWriteTime", "") == "":
            continue
        result = (
            0,
            (
                entries[registry_key].get("Timestamp", ""),
                entries[registry_key].get("DriverLastWriteTime", "").replace(",", ";"),
                entries[registry_key].get("DriverCompany", "").replace(",", ";"),
                entries[registry_key].get("Product", "").replace(",", ";"),
                entries[registry_key].get("ProductVersion", "").replace(",", ";"),
                entries[registry_key].get("DriverName", "").replace(",", ";"),
                entries[registry_key].get("DriverVersion", "").replace(",", ";"),
                entries[registry_key].get("Path", "").replace(",", ";"),
                entries[registry_key].get("DriverId", "").replace("0000", ""),
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
                registry_data = codecs.decode(subkey[1][3], "utf-16le")
            except:
                continue

            # Initialize the registry key entry if it doesn't exist
            if registry_key not in entries:
                entries[registry_key] = {'Timestamp': str(subkey[1][0])}

            # Store the registry value and data
            entries[registry_key]['Path'] = registry_key
            entries[registry_key][registry_value] = registry_data

    return entries

def AmcacheInventoryDriverBinary(
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
    key = 'ROOT\InventoryDriverBinary'
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