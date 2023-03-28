# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import List, Sequence, Iterable, Tuple, Union

from volatility3.framework import objects, renderers, exceptions, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.registry import RegistryHive, RegistryFormatException
from volatility3.framework.renderers import TreeGrid, conversion, format_hints
from volatility3.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility3.plugins.windows.registry import hivelist
from volatility3.plugins.windows.registry.regexplore.registryplugins import *

vollog = logging.getLogger(__name__)
hive_list = []

class regexplore(interfaces.plugins.PluginInterface):
    """Registry Explorer plugins from EZsuite to volatility3"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="regplg", description="Specify plugin to run {run_all, MountedDevices, AmcacheInventoryApplication" 
                "AmcacheInventoryDeviceContainer, AmcacheInventoryApplicationFile, AmcacheInventoryApplicationShortcut,"
                "AmcacheInventoryInventoryDevicePnp, AppCompatCache, AppPaths, BamDam, CIDSizeMRU}"
                , default=None, optional=True
            ),
            requirements.StringRequirement(
                name="hive", description="Specify hive to run all plugins related to that hive {SYSTEM, AMCACHE, NTUSER, SOFTWARE}"
                , default=None, optional=True
            )
        ]

    @classmethod
    def key_iterator(
        cls,
        hive: RegistryHive,
        node_path: Sequence[objects.StructType] = None,
        recurse: bool = False,
    ) -> Iterable[
        Tuple[
            int, bool, datetime.datetime, str, bool, interfaces.objects.ObjectInterface
        ]
    ]:
        """Walks through a set of nodes from a given node (last one in
        node_path). Avoids loops by not traversing into nodes already present
        in the node_path.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level

        Yields:
            A tuple of results (depth, is_key, last write time, path, volatile, and the node).
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return
        node = node_path[-1]
        key_path_items = [hive] + node_path[1:]
        if node.vol.type_name.endswith(constants.BANG + "_CELL_DATA"):
            raise RegistryFormatException(
                hive.name, "Encountered _CELL_DATA instead of _CM_KEY_NODE"
            )
        last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)

        for key_node in node.get_subkeys():
            result = (
                len(node_path),
                True,
                last_write_time,
                key_node,
            )
            yield result

            if recurse:
                if key_node.vol.offset not in [x.vol.offset for x in node_path]:
                    try:
                        key_node.get_name()
                    except exceptions.InvalidAddressException as excp:
                        vollog.debug(excp)
                        continue

                    yield from cls.key_iterator(
                        hive, node_path + [key_node], recurse=recurse
                    )

        for value_node in node.get_values():
            result = (
                len(node_path),
                False,
                last_write_time,
                value_node,
            )
            yield result

    def _printkey_iterator(
        self,
        hive: RegistryHive,
        node_path: Sequence[objects.StructType] = None,
        recurse: bool = False,
    ):
        """Method that wraps the more generic key_iterator, to provide output
        for printkey specifically.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level

        Yields:
            The depth, and a tuple of results (last write time, hive offset, type, path, name, data and volatile)
        """
        for (
            depth,
            is_key,
            last_write_time,
            node,
        ) in self.key_iterator(hive, node_path, recurse):
            if is_key:
                try:
                    key_node_name = node.get_name()
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    key_node_name = renderers.UnreadableValue()

                yield (
                    depth,
                    (
                        last_write_time,
                        renderers.format_hints.Hex(hive.hive_offset),
                        "Key",
                        key_node_name,
                        renderers.NotApplicableValue(),
                    ),
                )
            else:
                try:
                    value_node_name = node.get_name() or "(Default)"
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    value_node_name = renderers.UnreadableValue()

                try:
                    value_type = RegValueTypes(node.Type).name
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    value_type = renderers.UnreadableValue()

                if isinstance(value_type, renderers.UnreadableValue):
                    vollog.debug(
                        "Couldn't read registry value type, so data is unreadable"
                    )
                    value_data: Union[
                        interfaces.renderers.BaseAbsentValue, bytes
                    ] = renderers.UnreadableValue()
                else:
                    try:
                        value_data = node.decode_data()

                        if isinstance(value_data, int):
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-8"
                            )
                        elif RegValueTypes(node.Type) == RegValueTypes.REG_BINARY:
                            value_data = format_hints.MultiTypeData(
                                value_data, show_hex=True
                            )
                        elif RegValueTypes(node.Type) == RegValueTypes.REG_MULTI_SZ:
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-16-le", split_nulls=True
                            )
                        else:
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-16-le"
                            )
                    except (
                        ValueError,
                        exceptions.InvalidAddressException,
                        RegistryFormatException,
                    ) as excp:
                        vollog.debug(excp)
                        value_data = renderers.UnreadableValue()

                result = (
                    depth,
                    (
                        last_write_time,
                        key_node_name if 'key_node_name' in locals() else renderers.UnreadableValue(),
                        value_node_name,
                        value_data
                    ),
                )
                yield result

    def _hives_walker(
        self, 
        kernel,
    ):
        hives = {}
        for hive in hivelist.HiveList.list_hives(
                self.context,
                self.config_path,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name
        ):
            hives[hive.get_name()] = hive
        return hives

    def _registry_walker(
        self,
        layer_name: str,
        symbol_table: str,
        hive_list: List[hivelist.HiveList],
        key: str = None,
        hive_name: str = None,
        recurse: bool = False,
    ):
    
        for hive_path in [hive for hive in hive_list.keys() if hive_name.lower() in hive.split('\\')[-1].lower()]:
            try:
                try:
                    node_path = hive_list[hive_path].get_key(key, return_list=True) if key else [hive_list[hive_path].get_node(hive.root_cell_offset)]
                except Exception as e:
                    continue
                for x, y in self._printkey_iterator(hive_list[hive_path], node_path, recurse=recurse):
                    yield (x - len(node_path), y, hive_path)
            except (exceptions.InvalidAddressException, KeyError, RegistryFormatException) as excp:
                self.handle_exceptions(excp, key, hive_list[hive_path])

    @staticmethod
    def handle_exceptions(exception: Exception, key: str, hive: hivelist.HiveList) -> None:
        if isinstance(exception, KeyError):
            vollog.debug(f"Key '{key}' not found in Hive at offset {hex(hive.hive_offset)}.")
        elif isinstance(exception, RegistryFormatException):
            vollog.debug(exception)
        elif isinstance(exception, exceptions.InvalidAddressException):
            vollog.debug(f"Invalid address identified in Hive: {hex(exception.invalid_address)}")

        yield (0, (renderers.UnreadableValue(),) * 4)

    def run_all(
        self,
        module_mapping,
        _registry_walker,
        kernel,
        hive_list: List[hivelist.HiveList],
        hive,
    ):
        progress = 0
        for module_name, module_function in module_mapping.items():
            progress += 1
            module_function(_registry_walker, kernel, hive_list=hive_list, hive=hive, file_output=True)
            yield (0, (module_name, f'regexplore/{module_name}.csv', f'{progress}/{len(module_mapping)}'))

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        regplg = self.config.get("regplg", None)
        hive = self.config.get("hive", None)

        # Define module and hive mappings
        module_mapping = {
            "mounteddevices": MountedDevices.MountedDevices,
            "amcacheinventoryapplication": AmcacheInventoryApplication.AmcacheInventoryApplication,
            "amcacheinventoryapplicationfile": AmcacheInventoryApplicationFile.AmcacheInventoryApplicationFile,
            "amcacheinventoryapplicationshortcut": AmcacheInventoryApplicationShortcut.AmcacheInventoryApplicationShortcut,
            "amcacheinventorydevicecontainer": AmcacheInventoryDeviceContainer.AmcacheInventoryDeviceContainer,
            "amcacheinventorydevicepnp": AmcacheInventoryDevicePnp.AmcacheInventoryDevicePnp,
            "amcacheinventorydriverbinary": AmcacheInventoryDriverBinary.AmcacheInventoryDriverBinary,
            "appcompatcache": AppCompatCache.AppCompatCache,
            "apppaths": AppPaths.AppPaths,
            "bamdam": BamDam.BamDam,
            "cidsizemru": CIDSizeMRU.CIDSizeMRU
        }
        
        hive_mapping = {
            "system": {
                "mounteddevices": module_mapping["mounteddevices"],
                "appcompatcache": module_mapping["appcompatcache"],
                "bamdam": module_mapping["bamdam"]
            },
            "software": {
                "apppaths": module_mapping["apppaths"],
            },
            "amcache": {
                "amcacheinventoryapplication": module_mapping["amcacheinventoryapplication"],
                "amcacheinventoryapplicationfile": module_mapping["amcacheinventoryapplicationfile"],
                "amcacheinventoryapplicationshortcut": module_mapping["amcacheinventoryapplicationshortcut"],
                "amcacheinventorydevicecontainer": module_mapping["amcacheinventorydevicecontainer"],
                "amcacheinventorydevicepnp": module_mapping["amcacheinventorydevicepnp"],
                "amcacheinventorydriverbinary": module_mapping["amcacheinventorydriverbinary"],
            },
            "ntuser": {
                "apppaths": module_mapping["apppaths"],
                "cidsizemru": module_mapping["cidsizemru"]
            }
        }
    
        # Get the list of hives using the generator function
        hive_list = self._hives_walker(kernel)
        # Check if either hive or regplg is specified
        if regplg and not hive:
            if regplg.lower() == 'run_all':
                return TreeGrid(
                    columns=[
                        ("Module name", str),
                        ("Output path", str),
                        ("Progress", str),
                    ],
                    generator=self.run_all(module_mapping, self._registry_walker, kernel, hive_list, hive),
                )
            else:
                if regplg.lower() not in module_mapping:
                    allowed_values = ', '.join(module_mapping.keys())
                    raise ValueError(f"Invalid regplg value. Allowed values are {allowed_values}")
    
                module_function = module_mapping[regplg.lower()]
                return module_function(self._registry_walker, kernel, hive_list)
    
        elif hive and not regplg:
            if hive.lower() not in hive_mapping:
                allowed_values = ', '.join(hive_mapping.keys())
                raise ValueError(f"Invalid hive value. Allowed values are {allowed_values}")
    
            return TreeGrid(
                columns=[
                    ("Module name", str),
                    ("Output path", str),
                    ("Progress", str),
                ],
                generator=self.run_all(hive_mapping[hive.lower()], self._registry_walker, kernel, hive_list, hive),
            )
    
        else:
                raise ValueError(f"You need to specify either hive or regplg")