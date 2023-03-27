import datetime
from volatility3.framework.renderers import TreeGrid, format_hints
import os
from volatility3.plugins.windows.registry.regexplore.registryplugins.AppCompatCacheDep import *
from enum import Enum, Flag, auto

COLUMNS = [
    ('ControlSet', int),
    ('CacheEntryPosition', int),
    ('Path', str),
    ('LastModifiedTimeUTC', str),
    ('Executed', str),
    ('Duplicate', str),
    
]
    
def write_result_to_csv(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    output_path='regexplore/AppCompatCache.csv'
    ):
    
    os.makedirs('regexplore', exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as file_handle:
        header = 'ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate\n'
        file_handle.write(header)
        for result in process_values(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        ):
            file_handle.write(f'{result[0]},{result[1]},{result[2]},{result[3]},{result[4]},{result[5]}\n')
    return
    
def ValuesOut(
    _registry_walker,
    kernel,
    hive_list,
    key=None,
    hive_name=None,
    file_output=False
    ):
    
    for result in process_values(
            _registry_walker,
            kernel,
            hive_list,
            key,
            hive_name
        ):
        
            yield (
                0,
                (
                    result
                ),
            )
            
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
    paths_set = set()
    
    for i in range(1,5):
        try:
            walker_options = {
                'layer_name': kernel.layer_name,
                'symbol_table': kernel.symbol_table_name,
                'hive_list': hive_list,
                'key': key.replace('*', str(i)),
                'hive_name': hive_name,
                'recurse': False,
            }
            
            controlSetId = i
            
            if kernel.get_type("pointer").size == 4:
                is32bit = "x86"
            else:
                is32bit = False
            for value in _registry_walker(**walker_options):
                if str(value[1][2]) == "AppCompatCache":
                    rawBytes = value[1][3]
                    for result in AppCompatCacheParser(rawBytes, is32bit, controlSetId):
                        if result[2] in paths_set:
                            result += ('TRUE', )
                        else:
                            result += ('FALSE', )
                            paths_set.add(result[2])
                        yield result
        except Exception as e:
            print(e)
def AppCompatCacheParser(rawBytes, is32bit, controlSetId):
    
    sigNum = int.from_bytes(rawBytes[:4], byteorder='little', signed=False)
    signature = rawBytes[128:132].decode('ascii')

    if sigNum == 0xDEADBEEF and is32bit: #XP
        for result in WindowsXP.WindowsXP(rawBytes, is32bit, controlSetId):
            yield result
    elif sigNum == 0xbadc0ffe: #Win2k3Win2k8
        for result in VistaWin2k3Win2k8.VistaWin2k3Win2k8(rawBytes, is32bit, controlSetId):
            yield result
    elif sigNum == 0xbadc0fee: #7x86
        for result in Windows7.Windows7(rawBytes, is32bit, controlSetId):
            yield result
    elif signature == "00ts" or signature == "10ts" : #8.0, server2012, 8.1, server2012r2
        for result in Windows8.Windows8(rawBytes, signature, controlSetId):
            yield result
    else: #10,11
        offsetToEntries = int.from_bytes(rawBytes[:4], byteorder='little')
        signature = rawBytes[offsetToEntries:offsetToEntries+4].decode('ascii')
        if signature == "10ts":
            for result in Windows10.Windows10(rawBytes, controlSetId):
                yield result
            
def AppCompatCache(
    _registry_walker,
    kernel,
    hive_list,
    hive = None,
    file_output=False
    ):
    """
    Create a TreeGrid with device name and data.
    """
    key = 'ControlSet00*\Control\Session Manager\AppCompatCache'
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
