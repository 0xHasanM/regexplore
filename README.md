# Regexplore

Regexplore is a Volatility plugin designed to mimic the functionality of the Registry Explorer plugins in EZsuite. It allows the user to list different types of registry information by taking input from the user, such as runkeys, connected devices, etc.

## Usage

1. Load the plugin in Volatility using the command `volatility3 --plugins=/path/to/plugins -f memory_dump.raw windows.registry.regexplore`. 

2. Run the plugin using the command `python vol.py windows.registry.regexplore -h` to display the available options and commands.

## Available Commands

- `MountedDevices`: Lists Mounted devices information
- `services`: Lists the services that are automatically started when the system boots up. (to-do)
- `devices`: Lists the connected devices on the system. (to-do)
- `userassist`: Lists the programs that have been run by the user. (to-do)
- `mru`: Lists the most recently used files and applications. (to-do)
- `uninstall`: Lists the programs that have been uninstalled on the system. (to-do)
- `network`: Lists the network information and connections on the system. (to-do)

## Contributing

If you find any issues or have suggestions for new features, please feel free to create an issue or submit a pull request.
