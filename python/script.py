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
        max_columns = 0
        file_path = os.path.join(path, file)
        
        with open(file_path, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=';')
            for row in reader:
                num_columns = len(row[1].split(','))
                if num_columns > max_columns:
                    max_columns = num_columns

            csvfile.seek(0)
            is_first_row = True
            for row in reader:
                key = row[0]
                list_of_values = row[1].split(',')

                if file == 'ip_sets.csv':
                    list_of_values = validate_values(list_of_values, is_first_row, max_columns, 'cidr')
                elif file == 'port_sets.csv':
                    list_of_values = validate_values(list_of_values, is_first_row, max_columns, 'port')

                while len(list_of_values) < max_columns:
                    list_of_values.append('')

                new_row = [key] + list_of_values
                if file == 'port_sets.csv':
                    ports.append(new_row)
                else:
                    ips.append(new_row)
                is_first_row = False

    save_to_csv(os.path.join(path, 'f_port_sets.csv'), ports)
    save_to_csv(os.path.join(path, 'f_ip_sets.csv'), ips)

    return ips, ports

def process_rules_files(path, ip_sets_keys, port_sets_keys):
    """Process rules CSV files according to the requirements."""
    rules_files = ["rules_dev.csv", "rules_prod.csv", "rules_shared.csv", "rules_uat.csv"]

    for file in rules_files:
        file_path = os.path.join(path, file)
        output_path = os.path.join(path, f'f_{file}')
        
        with open(file_path, 'r', newline='') as infile:
            reader = csv.DictReader(infile, delimiter=';')
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

def save_to_csv(file_path, data):
    """Save data to CSV file."""
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerows(data)


def is_valid_cidr(cidr):
    """Check if a CIDR block is valid."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_port(port):
    """Check if the provided value is a valid application port number."""
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
        'ip_sets_formated_file': os.path.join(path, f'f_ip_sets.csv'),
        'port_sets_formated_file': os.path.join(path, f'f_port_sets.csv'),
        'rules_dev_formated_file': os.path.join(path, f'f_rules_dev.csv'),
        'rules_prod_formated_file': os.path.join(path, f'f_rules_prod.csv'),
        'rules_shared_formated_file': os.path.join(path, f'f_rules_shared.csv'),
        'rules_uat_formated_file': os.path.join(path, f'f_rules_uat.csv'),
        }))


if __name__ == "__main__":
    input = sys.stdin.read()
    input_json = json.loads(input)

    main(path=input_json.get('path_to_csv_files_folder'))