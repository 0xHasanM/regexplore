# Regexplore

Regexplore is a Volatility plugin designed to mimic the functionality of the Registry Explorer plugins in EZsuite and regripper plugins in volatility. It allows users to list different types of registry information in memory, such as runkeys, connected devices, and more.

## Usage

1. Place the plugin folder in Volatility `volatility3/volatility3/framework/plugins/windows/registry`. 

2. Run the plugin using the command `python vol.py windows.registry.regexplore -h` to display the available options and commands.

![image](https://user-images.githubusercontent.com/51376376/227634534-0801b47a-95be-45a9-ba1b-20e8954da444.png)

## Available Commands

### regplg parameter
- `run_all`: export all information in csv files to be feed to splunk, or TimeLineExplorer
- `MountedDevices`: Displays mounted devices including GUIDs and device information
- `AmcacheInventoryApplication`: Amcache-InventoryApplication
- `AmcacheInventoryApplicationFile`: Amcache-InventoryApplicationFile
- `AmcacheInventoryApplicationShortcut`: Amcache-InventoryApplicationShortcut
- `AmcacheInventoryDeviceContainer`: Amcache-InventoryApplicationDeviceContainer
- `AmcacheInventoryDevicePnp`: Amcache-InventoryApplicationDevicePnp
- `AmcacheInventoryDriverBinary`: Amcache-InventoryApplicationDriverBinary
- `AppCompatCache`: Tracks application compatibility. The cache data tracks file path, size, and last modified time. In some cases, an executed flag is also available.
- `AppPaths`: AppPaths Information
- `BamDam`: Extracts program information and last run times from bam and dam keys
- `services`: Lists the services that are automatically started when the system boots up (to-do)
- `devices`: Lists the connected devices on the system (to-do)
- `userassist`: Lists the programs that have been run by the user (to-do)
- `mru`: Lists the most recently used files and applications (to-do)
- `uninstall`: Lists the programs that have been uninstalled on the system (to-do)
- `network`: Lists the network information and connections on the system (to-do)
- `html`: html output (to-do)

### hive parameter
- `SYSTEM`: run all plugins related to SYSTEM hive and extract information in respective csv files.
- `SOFTWARE`: run all plugins related to SOFTWARE hive and extract information in respective csv files.
- `Amcache`: run all plugins related to Amcache hive and extract information in respective csv files.
- `NTUSER`: run all plugins related to NTUSER.dat hive and extract information in respective csv files.

## Contributing

If you find any issues or have suggestions for new features, please feel free to create an issue or submit a pull request. We appreciate your contributions and recommendations to improve the Regexplore plugin!
