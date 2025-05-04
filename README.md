# MAC Address Changer

A Python utility for Windows that allows users to view and change MAC addresses on network interfaces.

## Features

- List all available network interfaces with their current MAC addresses
- Change MAC addresses manually or generate random ones
- User-friendly GUI interface
- Command-line interface for automation
- Interactive mode for easier adapter selection
- Administrator privilege check
- Support for both wired and wireless adapters

## Requirements

- Windows operating system
- Python 3.6 or higher
- Administrative privileges (required to modify network settings)

## Installation

1. Clone or download this repository
2. No additional Python packages are required as the program uses only standard library modules

## Usage

### Graphical User Interface (GUI)

Run the program without any arguments to launch the GUI:

```
python macchanger.py
```

The GUI allows you to:
- View all network interfaces
- Select an interface to modify
- Enter a custom MAC address or generate a random one
- Apply changes with a click of a button

### Command Line Interface (CLI)

The program supports the following command-line arguments:

```
Options:
  -h, --help       Show this help message and exit
  -l, --list       List all network interfaces
  -i INTERFACE, --interface INTERFACE
                   Specify the interface to change MAC address
  -m MAC, --mac MAC
                   Specify the new MAC address
  -r, --random     Generate a random MAC address
  -I, --interactive
                   Interactive mode - select network adapter from a list
```

#### Examples:

List all network interfaces:
```
python macchanger.py -l
```

Change MAC address to a specific value:
```
python macchanger.py -i "Wi-Fi" -m 00112233AABB
```

Generate and apply a random MAC address:
```
python macchanger.py -i "Wi-Fi" -r
```

Use interactive mode to select adapter:
```
python macchanger.py -I
```

Show help information:
```
python macchanger.py -h
```

## Important Notes

- This program requires administrative privileges to modify network interfaces
- Some network adapters (particularly certain USB or built-in Wi-Fi adapters) may have hardware limitations that prevent MAC address changes
- Changes to MAC addresses will temporarily disconnect the network interface
- For the changes to take effect, the interface will be disabled and then re-enabled
- In some cases, you may need to restart your computer for changes to persist

## Troubleshooting

If you encounter issues:

1. Make sure you're running the program as Administrator
2. Check that the interface name is correct (use `-l` to list interfaces)
3. Try the interactive mode (`-I`) for easier adapter selection
4. Some adapters may require vendor-specific tools to change MAC addresses
5. If changes don't appear to work, try restarting your computer

## License

This software is provided as-is, without warranty of any kind.

## Author

[Your Name/Organization]
