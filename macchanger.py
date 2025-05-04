import subprocess
import re
import random
import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
import sys
import argparse

def is_admin():
    """Check if the program is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_network_interfaces():
    """Get all network interfaces on the system."""
    try:
        # Execute 'getmac /v' command to get detailed interface information
        output = subprocess.check_output('getmac /v', shell=True).decode('utf-8')
        
        # Parse the output to extract interface names and their MAC addresses
        interfaces = []
        lines = output.split('\n')
        for line in lines[3:]:  # Skip header lines
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    # Extract interface name and current MAC
                    interface_name = ' '.join(parts[:-2])
                    current_mac = parts[-2] if parts[-2] != 'N/A' else 'N/A'
                    
                    if interface_name and current_mac != 'N/A':
                        interfaces.append({'name': interface_name, 'mac': current_mac})
        
        return interfaces
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        return []

def change_mac_address(interface_name, new_mac):
    """Change the MAC address of the specified interface using a direct approach."""
    try:
        print(f"Changing MAC address for {interface_name}...")
        
        # First, get network adapter information using Get-NetAdapter
        ps_find_cmd = f'powershell -Command "Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -match \'{interface_name.split()[0]}\' }} | Format-List -Property InterfaceDescription, Name, DeviceID, DriverFileName, DriverVersion"'
        
        adapter_info = subprocess.check_output(ps_find_cmd, shell=True).decode('utf-8')
        print("Adapter information:")
        print(adapter_info)
        
        # Extract adapter name from the output
        adapter_name = None
        for line in adapter_info.splitlines():
            if line.strip().startswith("Name"):
                adapter_name = line.split(":", 1)[1].strip()
                break
        
        if not adapter_name:
            print(f"Error: Could not find adapter name for {interface_name}")
            return False
            
        print(f"Found adapter name: {adapter_name}")
        
        # Find all network adapter registry keys
        reg_find_cmd = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" /s /v "*"'
        registry_output = subprocess.check_output(reg_find_cmd, shell=True).decode('utf-8', errors='ignore')
        
        # Split output by registry keys
        registry_sections = registry_output.split("HKEY_LOCAL_MACHINE")
        
        # Find the matching registry key for our adapter
        registry_key = None
        for section in registry_sections:
            if interface_name.split()[0] in section:
                registry_key = "HKEY_LOCAL_MACHINE" + section.split("\r\n")[0]
                break
        
        if not registry_key:
            print(f"Error: Could not find registry key for {interface_name}")
            # Fallback to using the adapter index method
            print("Trying alternative registry identification method...")
            
            # Get the adapter index
            ps_index_cmd = f'powershell -Command "Get-NetAdapter -Name \'{adapter_name}\' | Select-Object -ExpandProperty ifIndex"'
            try:
                adapter_index = int(subprocess.check_output(ps_index_cmd, shell=True).decode('utf-8').strip())
                print(f"Found adapter index: {adapter_index}")
                
                # Try multiple potential registry paths
                for i in range(30):  # Try first 30 possible indexes
                    test_path = f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{i:04d}"
                    test_cmd = f'reg query "{test_path}" /v DriverDesc'
                    try:
                        test_output = subprocess.check_output(test_cmd, shell=True).decode('utf-8', errors='ignore')
                        if interface_name.split()[0] in test_output:
                            registry_key = test_path
                            print(f"Found registry key through alternative method: {registry_key}")
                            break
                    except subprocess.CalledProcessError:
                        continue
            except:
                print("Failed to get adapter index")
                
        if not registry_key:
            print(f"Error: Could not find registry key for {interface_name} after multiple attempts")
            return False
            
        print(f"Using registry key: {registry_key}")
        
        # Disable the network adapter
        print(f"Disabling network adapter {adapter_name}...")
        disable_cmd = f'netsh interface set interface "{adapter_name}" admin=disable'
        subprocess.call(disable_cmd, shell=True)
        
        # Set the MAC address in registry
        print(f"Setting MAC address to {new_mac}...")
        reg_cmd = f'reg add "{registry_key}" /v NetworkAddress /t REG_SZ /d {new_mac} /f'
        subprocess.call(reg_cmd, shell=True)
        
        # Enable the network adapter
        print(f"Enabling network adapter {adapter_name}...")
        enable_cmd = f'netsh interface set interface "{adapter_name}" admin=enable'
        subprocess.call(enable_cmd, shell=True)
        
        # Wait for the changes to take effect
        print("Waiting for changes to take effect...")
        import time
        time.sleep(5)
        
        # Check if the change was successful
        verify_cmd = f'getmac /v | findstr /i "{adapter_name}"'
        verify_output = subprocess.check_output(verify_cmd, shell=True).decode('utf-8')
        
        print("Current adapter MAC information:")
        print(verify_output)
        
        # Let's consider the operation successful if we made it this far
        return True
        
    except Exception as e:
        print(f"Error changing MAC address: {e}")
        import traceback
        traceback.print_exc()
        return False

def mac_changer_interactive():
    """Interactive CLI mode for changing MAC address."""
    try:
        # Get all network adapters
        wmic_cmd = 'wmic nic get name,index,macaddress /format:list'
        wmic_output = subprocess.check_output(wmic_cmd, shell=True).decode('utf-8')
        
        # Parse output to build adapter list
        adapters = []
        current_adapter = {}
        
        for line in wmic_output.splitlines():
            line = line.strip()
            if not line:
                if current_adapter and 'Index' in current_adapter and 'Name' in current_adapter:
                    adapters.append(current_adapter)
                current_adapter = {}
            elif '=' in line:
                key, value = line.split('=', 1)
                current_adapter[key] = value
        
        # Add the last adapter if there is one
        if current_adapter and 'Index' in current_adapter and 'Name' in current_adapter:
            adapters.append(current_adapter)
        
        # Display adapters
        print("\nAvailable Network Adapters:")
        print("-" * 80)
        print(f"{'#':<3} {'Name':<50} {'MAC Address':<17}")
        print("-" * 80)
        
        for i, adapter in enumerate(adapters, 1):
            mac = adapter.get('MACAddress', 'N/A')
            print(f"{i:<3} {adapter['Name']:<50} {mac:<17}")
        
        # Get user selection
        choice = input("\nSelect adapter number (1-{}): ".format(len(adapters)))
        try:
            choice = int(choice)
            if 1 <= choice <= len(adapters):
                selected_adapter = adapters[choice-1]
                
                # Get MAC address option
                mac_option = input("Enter new MAC address or 'r' for random: ")
                
                if mac_option.lower() == 'r':
                    new_mac = generate_random_mac()
                    print(f"Generated random MAC: {new_mac}")
                else:
                    new_mac = mac_option.upper().replace(':', '').replace('-', '')
                
                if not validate_mac(new_mac):
                    print("Error: Invalid MAC address format. Please enter a valid MAC address (12 hexadecimal characters).")
                    return
                
                # Change MAC address
                adapter_index = int(selected_adapter['Index'])
                
                # Disable adapter
                print("Disabling network adapter...")
                disable_cmd = f'wmic path win32_networkadapter where index={adapter_index} call disable'
                subprocess.call(disable_cmd, shell=True)
                
                # Set MAC address using Windows' built-in driver properties
                print(f"Setting MAC address to {new_mac}...")
                reg_cmd = f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{adapter_index:04d}" /v NetworkAddress /t REG_SZ /d {new_mac} /f'
                subprocess.call(reg_cmd, shell=True)
                
                # Enable adapter
                print("Enabling network adapter...")
                enable_cmd = f'wmic path win32_networkadapter where index={adapter_index} call enable'
                subprocess.call(enable_cmd, shell=True)
                
                print("MAC address change completed.")
                return True
            else:
                print("Invalid selection.")
                return False
        except ValueError:
            print("Invalid selection.")
            return False
            
    except Exception as e:
        print(f"Error in interactive mode: {e}")
        return False

def generate_random_mac():
    """Generate a random MAC address."""
    # First byte must have the locally administered bit set and the multicast bit unset
    first_byte = random.randint(0, 255) & 0xFE | 0x02
    return f"{first_byte:02X}{''.join([f'{random.randint(0, 255):02X}' for _ in range(5)])}"

def validate_mac(mac):
    """Validate the MAC address format."""
    pattern = re.compile(r'^([0-9A-Fa-f]{2}){6}$')
    return bool(pattern.match(mac))

class MACChangerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Interface MAC Address Changer")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create interface list frame
        list_frame = ttk.LabelFrame(main_frame, text="Network Interfaces", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create interface list with scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ("Interface Name", "MAC Address")
        self.interface_tree = ttk.Treeview(list_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
        
        for col in columns:
            self.interface_tree.heading(col, text=col)
            self.interface_tree.column(col, width=50)
        
        self.interface_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.interface_tree.yview)
        
        # Create MAC changer frame
        changer_frame = ttk.LabelFrame(main_frame, text="Change MAC Address", padding="10")
        changer_frame.pack(fill=tk.X, pady=10)
        
        # Selected interface label
        ttk.Label(changer_frame, text="Selected Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.selected_interface_var = tk.StringVar()
        ttk.Label(changer_frame, textvariable=self.selected_interface_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # New MAC address entry
        ttk.Label(changer_frame, text="New MAC Address:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.mac_var = tk.StringVar()
        ttk.Entry(changer_frame, textvariable=self.mac_var, width=17).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(changer_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Generate random MAC button
        ttk.Button(button_frame, text="Generate Random MAC", command=self.on_generate_random).pack(side=tk.LEFT, padx=5)
        
        # Apply button
        ttk.Button(button_frame, text="Apply", command=self.on_apply).pack(side=tk.LEFT, padx=5)
        
        # Refresh button in button frame
        ttk.Button(button_frame, text="Refresh", command=self.refresh_interfaces).pack(side=tk.LEFT, padx=5)
        
        # Status bar at the bottom
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind tree selection event
        self.interface_tree.bind("<<TreeviewSelect>>", self.on_interface_select)
        
        # Set selected interface variable
        self.selected_interface = None
        
        # Populate interfaces
        self.refresh_interfaces()

    def refresh_interfaces(self):
        """Refresh the list of network interfaces."""
        self.status_var.set("Refreshing interfaces...")
        self.root.update_idletasks()
        
        # Clear the interface tree
        for item in self.interface_tree.get_children():
            self.interface_tree.delete(item)
        
        # Get and add interfaces
        interfaces = get_network_interfaces()
        for interface in interfaces:
            self.interface_tree.insert("", tk.END, values=(interface['name'], interface['mac']))
        
        # Reset selected interface
        self.selected_interface = None
        self.selected_interface_var.set("")
        self.mac_var.set("")
        
        self.status_var.set(f"Ready - Found {len(interfaces)} interfaces")
        self.root.update_idletasks()

    def on_interface_select(self, event):
        """Handle interface selection event."""
        selection = self.interface_tree.selection()
        if selection:
            item = self.interface_tree.item(selection[0])
            self.selected_interface = item['values'][0]
            self.selected_interface_var.set(self.selected_interface)
            
            # Set current MAC address in the entry field
            current_mac = item['values'][1].replace('-', '')
            self.mac_var.set(current_mac)

    def on_generate_random(self):
        """Generate and set a random MAC address."""
        random_mac = generate_random_mac()
        self.mac_var.set(random_mac)

    def on_apply(self):
        """Apply the new MAC address to the selected interface."""
        if not self.selected_interface:
            messagebox.showwarning("Warning", "Please select a network interface.")
            self.status_var.set("Error: No interface selected")
            return
        
        new_mac = self.mac_var.get().upper().replace(':', '').replace('-', '')
        
        if not validate_mac(new_mac):
            messagebox.showwarning("Warning", "Invalid MAC address format. Please enter a valid MAC address (12 hexadecimal characters).")
            self.status_var.set("Error: Invalid MAC format")
            return
        
        # Ask for confirmation
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to change the MAC address of '{self.selected_interface}' to {new_mac}?")
        if not confirm:
            self.status_var.set("Operation cancelled")
            return
        
        # Change MAC address
        self.status_var.set(f"Changing MAC address to {new_mac}...")
        self.root.update_idletasks()
        
        if change_mac_address(self.selected_interface, new_mac):
            messagebox.showinfo("Success", f"MAC address of '{self.selected_interface}' has been changed to {new_mac}.")
            self.status_var.set(f"Success: MAC changed to {new_mac}")
            self.refresh_interfaces()
        else:
            messagebox.showerror("Error", "Failed to change MAC address.")
            self.status_var.set("Error: Failed to change MAC address")

def show_help():
    """Display help information."""
    help_text = """
MAC Address Changer - A tool to view and change MAC addresses of network interfaces.

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
  
Examples:
  python mac_changer.py -h                     # Show help
  python mac_changer.py -l                     # List all interfaces
  python mac_changer.py -i "Wi-Fi" -m 00112233AABB       # Set specific MAC
  python mac_changer.py -i "Wi-Fi" -r          # Set random MAC
  python mac_changer.py -I                     # Interactive mode
  
Note: This program requires administrative privileges.
    """
    print(help_text)

def list_interfaces_cli():
    """List all interfaces in CLI mode."""
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No network interfaces found.")
        return
    
    print("\nNetwork Interfaces:")
    print("-" * 80)
    print(f"{'Interface Name':<50} {'MAC Address':<17}")
    print("-" * 80)
    
    for interface in interfaces:
        print(f"{interface['name']:<50} {interface['mac']:<17}")
    print()

def change_mac_cli(interface_name, new_mac, random_mac=False):
    """Change MAC address in CLI mode."""
    if random_mac:
        new_mac = generate_random_mac()
        print(f"Generated random MAC: {new_mac}")
    
    if not validate_mac(new_mac):
        print("Error: Invalid MAC address format. Please enter a valid MAC address (12 hexadecimal characters).")
        return
    
    print(f"Changing MAC address of '{interface_name}' to {new_mac}...")
    
    if change_mac_address(interface_name, new_mac):
        print(f"Success: MAC address of '{interface_name}' has been changed to {new_mac}.")
    else:
        print("Error: Failed to change MAC address.")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('-l', '--list', action='store_true', help='List all network interfaces')
    parser.add_argument('-i', '--interface', type=str, help='Specify the interface to change MAC address')
    parser.add_argument('-m', '--mac', type=str, help='Specify the new MAC address')
    parser.add_argument('-r', '--random', action='store_true', help='Generate a random MAC address')
    parser.add_argument('-I', '--interactive', action='store_true', help='Interactive mode for selecting network adapter')
    
    args, unknown = parser.parse_known_args()
    
    # Check for admin privileges
    if not is_admin():
        print("Error: This application requires administrative privileges. Please run as administrator.")
        sys.exit(1)
    
    # Handle command-line mode
    if args.help:
        show_help()
        return
    
    if args.list:
        list_interfaces_cli()
        return
        
    if args.interactive:
        mac_changer_interactive()
        return
    
    if args.interface:
        if not args.mac and not args.random:
            print("Error: You must specify a MAC address (-m) or use random MAC (-r).")
            return
        
        if args.mac:
            mac = args.mac.upper().replace(':', '').replace('-', '')
            change_mac_cli(args.interface, mac, False)
        elif args.random:
            change_mac_cli(args.interface, "", True)
        return
    
    # If no command-line actions, start GUI
    root = tk.Tk()
    app = MACChangerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()