import datetime
from volatility3.framework.renderers import TreeGrid, format_hints

# Define the columns for the TreeGrid
COLUMNS = [
    ("Timestamp", str),
    ("Name", str),
    ("Version", str),
    ("Publisher", str),
    ("Source", str),
    ("RootDirPath", str),
    ("UninstallString", str)
]

def process_values(_registry_walker, kernel, offset, key=None, hive_name=None):
    """
    Process registry values and return Programs data.
    """
    # Define options for the registry walker
    walker_options = {
        "layer_name": kernel.layer_name,
        "symbol_table": kernel.symbol_table_name,
        "hive_offsets": [offset] if offset is not None else None,
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
                        entries[registry_key].get("Name", ""),
                        entries[registry_key].get("Version", ""),
                        entries[registry_key].get("Publisher", ""),
                        entries[registry_key].get("Source", ""),
                        entries[registry_key].get("RootDirPath", ""),
                        entries[registry_key].get("UninstallString", ""),
                    ),
                )
                yield result
                entries = {}

        except KeyError:
            continue

def AmcacheInventoryApplication(_registry_walker, kernel, offset):
    """
    Create a TreeGrid with Programs data.
    """
    # Define the registry key and hive name to process
    key = 'ROOT\InventoryApplication'
    hive_name = 'Amcache.hve'

    # Generate the TreeGrid data using process_values function
    generator = process_values(
        _registry_walker,
        kernel,
        offset,
        key,
        hive_name
    )

    # Return the TreeGrid with the specified columns and generator
    return TreeGrid(
        columns=COLUMNS,
        generator=generator,
    )
