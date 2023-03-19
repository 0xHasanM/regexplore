import datetime
from volatility3.framework.renderers import TreeGrid, format_hints

COLUMNS = [
    ("Device name", str),
    ("Device Data", str)
]

def processvalues(_registry_walker,
                  kernel,
                  offset,
                  key: str = None,
                  hive_name: str = None):
    """
    Process registry values and return device name and data.
    """
    for value in _registry_walker(
        kernel.layer_name,
        kernel.symbol_table_name,
        hive_offsets=None if offset is None else [offset],
        key=key,
        hive_name=hive_name,
        recurse=None,
    ):
        device_name = value[1][1]
        device_data = value[1][2].replace(b'\x00', b'')
        result = (
            0,
            (
                device_name,
                device_data.decode('utf-8', errors='replace')
            ),
        )
        yield result

def MountedDevices(_registry_walker,
                   kernel,
                   offset):
    """
    Create a TreeGrid with device name and data.
    """
    key = 'MountedDevices'
    hive_name = 'SYSTEM'
    
    generator = processvalues(
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
