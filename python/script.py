import csv
import os
import ipaddress
import sys
import json


def check_files_in_folder(folder_path):
    """Check if the required files are present in the specified folder."""
    files_to_check = [
        "ip_sets.csv",
        "port_sets.csv",
        "rules_dev.csv",
        "rules_prod.csv",
        "rules_shared.csv",
        "rules_uat.csv",
    ]
    missing_files = [file_name for file_name in files_to_check if not os.path.isfile(os.path.join(folder_path, file_name))]

    if missing_files:
        raise FileNotFoundError(f'The following files are missing: {missing_files} in folder "{folder_path}"')


def process_set_files(path):
    """Process CSV files and ensure data is correctly formatted."""
    set_files = ["ip_sets.csv", "port_sets.csv"]
    ports, ips = [], []

    for file in set_files:
        file_path = os.path.join(path, file)
        
        with open(file_path, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL, skipinitialspace=True)
            next(reader)  # Skip header row
            for row in reader:
                key = row[0]
                list_of_values = row[1:]
                list_of_values = [value for value in list_of_values if value]  # Remove empty values

                if file == 'ip_sets.csv':
                    list_of_values = validate_values(list_of_values, False, 0, 'cidr')
                    formatted_values = ','.join(f'"{value}"' for value in list_of_values)
                    ips.append([key, f'[{formatted_values}]'])
                elif file == 'port_sets.csv':
                    list_of_values = validate_values(list_of_values, False, 0, 'port')
                    formatted_values = ','.join(f'"{value}"' for value in list_of_values)
                    ports.append([key, f'[{formatted_values}]'])

    save_to_csv(os.path.join(path, 'f_ip_sets.csv'), ips, 'cidr')
    save_to_csv(os.path.join(path, 'f_port_sets.csv'), ports, 'port')

    return ips, ports

def process_rules_files(path, ip_sets_keys, port_sets_keys):
    """Process rules CSV files according to the requirements."""
    rules_files = ["rules_dev.csv", "rules_prod.csv", "rules_shared.csv", "rules_uat.csv"]

    for file in rules_files:
        file_path = os.path.join(path, file)
        output_path = os.path.join(path, f'f_{file}')
        
        with open(file_path, 'r', newline='') as infile:
            reader = csv.DictReader(infile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL, skipinitialspace=True)
            fieldnames = reader.fieldnames

            with open(output_path, 'w', newline='') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()

                for row in reader:
                    row['source'] = check_and_transform(row['source'], 'source', ip_sets_keys)
                    row['destination'] = check_and_transform(row['destination'], 'destination', ip_sets_keys)
                    row['destination_port'] = check_and_transform(row['destination_port'], 'destination_port', port_sets_keys)
                    is_valid_protocol(row['protocol'])
                    writer.writerow(row)

def check_and_transform(value, field_name, keys):
    """Check and transform the value based on field name and keys."""
    parts = value.split(',')
    if field_name in ['source', 'destination']:
        if all(is_valid_cidr(part) for part in parts):
            return f'[{value}]'
        elif value.startswith('$') and value.lstrip('$') in keys:
            return value
        else:
            raise ValueError(f"Invalid {field_name} value: {value}. Must be a CIDR block or key from IP sets prefixed with $.")
    elif field_name == 'destination_port':
        if all(is_valid_port(part) for part in parts):
            if ':' in value:
                return value
            return f'[{value}]'
        elif value.startswith('$') and value.lstrip('$') in keys:
            return value
        else:
            raise ValueError(f"Invalid {field_name} value: {value}. Must be a port number or key from Port sets prefixed with $.")
    return value

def validate_values(values, is_first_row, max_columns, value_type):
    """Validate values for IP sets or port sets."""
    def value_validator(value):
        if value_type == 'cidr':
            return is_valid_cidr(value)
        elif value_type == 'port':
            return is_valid_port(value)
        else:
            raise ValueError(f"Unknown value type: {value_type}")

    def get_default_label(index):
        if value_type == 'cidr':
            return f'cidr{index + 1}'
        elif value_type == 'port':
            return f'port{index + 1}'

    if not is_first_row:
        for value in values:
            if not value_validator(value):
                raise ValueError(f"Invalid {value_type} '{value}'")
    else:
        for idx in range(max_columns):
            if idx < len(values):
                values[idx] = get_default_label(idx)
            else:
                values.append(get_default_label(idx))
    return values

def save_to_csv(file_path, data, column_name):
    """Save data to CSV file."""
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['key', column_name])  # Write the header
        writer.writerows(data)


def is_valid_cidr(cidr):
    """Check if a CIDR block is valid."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_port(port):
    """Check if the provided value is a valid application port number or port range."""
    if ':' in port:
        try:
            start_port, end_port = map(int, port.split(':'))
            return 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port
        except ValueError:
            return False
    else:
        try:
            port_number = int(port)
            return 0 <= port_number <= 65535
        except ValueError:
            return False


def is_valid_protocol(protocol):
    """Check if the provided value is a valid application protocol."""
    valid_protocols = [
        'IP', 'TCP', 'UDP', 'ICMP', 'HTTP', 'FTP', 'TLS', 'SMB', 'DNS',
        'DCERPC', 'SSH', 'SMTP', 'IMAP', 'MSN', 'KRB5', 'IKEV2', 'TFTP',
        'NTP', 'DHCP'
    ]
    if protocol not in valid_protocols:
        raise ValueError(f"Invalid protocol value: {protocol}. Must be one of: {valid_protocols}")


def main(path):
    """Main function to execute the processing."""

    check_files_in_folder(path)
    ips, ports = process_set_files(path)
    ip_sets_keys = [row[0] for row in ips]
    port_sets_keys = [row[0] for row in ports]
    process_rules_files(path, ip_sets_keys, port_sets_keys)
    print(json.dumps({
        'ip_sets_formated_file': os.path.join(path, 'f_ip_sets.csv'),
        'port_sets_formated_file': os.path.join(path, 'f_port_sets.csv'),
        'rules_dev_formated_file': os.path.join(path, 'f_rules_dev.csv'),
        'rules_prod_formated_file': os.path.join(path, 'f_rules_prod.csv'),
        'rules_shared_formated_file': os.path.join(path, 'f_rules_shared.csv'),
        'rules_uat_formated_file': os.path.join(path, 'f_rules_uat.csv'),
    }))


if __name__ == "__main__":
    input = sys.stdin.read()
    input_json = json.loads(input)

    main(path=input_json.get('path_to_csv_files_folder'))