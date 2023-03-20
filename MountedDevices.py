import datetime
from volatility3.framework.renderers import TreeGrid, format_hints

COLUMNS = [
    ("Device name", str),
    ("Device Data", str)
]

def process_values(_registry_walker, kernel, offset, key=None, hive_name=None, recurse=None):
    """
    Process registry values and return device name and data.
    """
    walker_options = {
        "layer_name": kernel.layer_name,
        "symbol_table": kernel.symbol_table_name,
        "hive_offsets": None if offset is None else [offset],
        "key": key,
        "hive_name": hive_name,
        "recurse": recurse,
    }

    for value in _registry_walker(**walker_options):
        device_name = value[1][2]
        device_data = value[1][3].replace(b'\x00', b'')
        result = (
            0,
            (
                device_name,
                device_data.decode('utf-8', errors='ignore')
            ),
        )
        yield result


def MountedDevices(_registry_walker, kernel, offset):
    """
    Create a TreeGrid with device name and data.
    """
    key = 'MountedDevices'
    hive_name = 'SYSTEM'

    generator = process_values(
        _registry_walker,
        kernel,
        offset,
        key,
        hive_name
    )

    return TreeGrid(
        columns=COLUMNS,
        generator=generator,
    )
