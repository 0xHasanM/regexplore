# Regexplore

Regexplore is a Volatility plugin designed to mimic the functionality of the Registry Explorer plugin in EZsuite. It allows the user to list different types of registry information by taking input from the user, such as runkeys, connected devices, etc.

## Usage

1. Load the plugin in Volatility using the command `volatility --plugins=/path/to/plugins -f memory_dump.raw pluginname`. 

2. Run the plugin using the command `python vol.py regexplore -h` to display the available options and commands.

## Available Commands

- `runkeys`: Lists the programs that are launched automatically when the system starts up.
- `services`: Lists the services that are automatically started when the system boots up.
- `devices`: Lists the connected devices on the system.
- `userassist`: Lists the programs that have been run by the user.
- `mru`: Lists the most recently used files and applications.
- `uninstall`: Lists the programs that have been uninstalled on the system.
- `network`: Lists the network information and connections on the system.
- `all`: Lists all available information in the registry.

## Contributing

If you find any issues or have suggestions for new features, please feel free to create an issue or submit a pull request.
