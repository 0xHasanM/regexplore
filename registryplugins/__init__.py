# Import registry plugins
from volatility3.plugins.windows.registry.regexplore.registryplugins import (
    AmcacheInventoryApplication,
    AmcacheInventoryApplicationFile,
    AmcacheInventoryApplicationShortcut,
    AmcacheInventoryDeviceContainer,
    AmcacheInventoryDevicePnp,
    AmcacheInventoryDriverBinary,
    AppCompatCache,
    AppPaths,
    BamDam,
    MountedDevices,
    CIDSizeMRU
)

# Purpose of each module:
# AmcacheInventoryApplication - retrieve information about installed applications
# AmcacheInventoryApplicationFile - retrieve information about files related to installed applications
# AmcacheInventoryApplicationShortcut - retrieve information about shortcuts related to installed applications
# AmcacheInventoryDeviceContainer - retrieve information about PnP device containers
# AmcacheInventoryDevicePnp - retrieve information about PnP devices
# AmcacheInventoryDriverBinary - retrieve information about installed drivers
# AppCompatCache - retrieve information about application compatibility settings
# AppPaths - retrieve information about registered application paths
# BamDam - retrieve information about Bam and Dam registry keys
# MountedDevices - retrieve information about mounted devices
