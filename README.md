# Regexplore

Regexplore is a Volatility plugin designed to mimic the functionality of the Registry Explorer plugins in EZsuite. It allows users to list different types of registry information in memory, such as runkeys, connected devices, and more.

## Usage

1. Load the plugin in Volatility using the command `volatility3 -p /path/to/plugins -f memory_dump.raw windows.registry.regexplore`. 

2. Run the plugin using the command `python vol.py windows.registry.regexplore -h` to display the available options and commands.

![image](https://user-images.githubusercontent.com/51376376/226187226-374b9d53-026e-43d6-8b87-e7cce2170779.png)

## Available Commands

- `MountedDevices`: Lists mounted devices information
- `AmcacheInventoryApplication`: Amcache-InventoryApplication
- `services`: Lists the services that are automatically started when the system boots up (to-do)
- `devices`: Lists the connected devices on the system (to-do)
- `userassist`: Lists the programs that have been run by the user (to-do)
- `mru`: Lists the most recently used files and applications (to-do)
- `uninstall`: Lists the programs that have been uninstalled on the system (to-do)
- `network`: Lists the network information and connections on the system (to-do)

## Contributing

If you find any issues or have suggestions for new features, please feel free to create an issue or submit a pull request. We appreciate your contributions and recommendations to improve the Regexplore plugin!
