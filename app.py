import os
import sys
import json
import time
import select
import signal
import termios
import struct
import fcntl
import threading
import subprocess
import pty
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import yaml
import boto3
import botocore.exceptions
from collections import defaultdict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active sessions
sessions = {}  # Key: session_id, Value: SSMSession object

class SSMSession:
    def __init__(self, instance_id, session_id):
        self.instance_id = instance_id
        self.session_id = session_id
        self.process = None
        self.master_fd = None
        self.running = False
        self.output_thread = None

    def start_session(self):
        try:
            # Get AWS configuration and check instance status first
            config = get_instance_config(self.instance_id)
            if not config:
                print(f"No AWS configuration found for instance {self.instance_id}")
                return False
                
            aws_profile = config['aws_profile']
            aws_region = config['region']
                
            # Check if instance is connected before attempting to start session
            if not check_instance_status(self.instance_id, aws_profile, aws_region):
                print(f"Instance {self.instance_id} is not connected to SSM")
                return False
            
            master_fd, slave_fd = pty.openpty()
            self.master_fd = master_fd
            
            # Get current environment and update AWS settings
            env = os.environ.copy()
            env['AWS_PROFILE'] = aws_profile
            env['AWS_DEFAULT_REGION'] = aws_region
            print(f"Using AWS_PROFILE={aws_profile}, AWS_DEFAULT_REGION={aws_region} for instance {self.instance_id}")
            
            # Start the SSM session with the updated environment
            command = ["aws", "ssm", "start-session", "--target", self.instance_id]
            self.process = subprocess.Popen(
                command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=os.setsid,
                env=env
            )
            
            os.close(slave_fd)  # Close slave fd after process started
            
            self.running = True
            self.output_thread = threading.Thread(target=self.read_output)
            self.output_thread.daemon = True
            self.output_thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting session: {str(e)}")
            self.close()
            return False

    def read_output(self):
        try:
            while self.running and self.process and self.process.poll() is None:
                try:
                    r, w, e = select.select([self.master_fd], [], [], 0.1)
                    if self.master_fd in r:
                        try:
                            data = os.read(self.master_fd, 1024)
                            if data:
                                text = data.decode('utf-8', errors='replace')
                                if 'Starting session with SessionId' in text:
                                    print(f"Session established for {self.instance_id} (session {self.session_id})")
                                elif 'Exiting session with sessionId' in text:
                                    print(f"Session disconnected for {self.instance_id} (session {self.session_id})")
                                socketio.emit('terminal_output', {
                                    'instance_id': self.instance_id,
                                    'session_id': self.session_id,
                                    'output': text
                                })
                            else:
                                break
                        except (OSError, IOError) as e:
                            if e.errno == 9:  # Bad file descriptor
                                break
                            print(f"Error reading from terminal: {str(e)}")
                            break
                except select.error:
                    break
        except Exception as e:
            print(f"Error in output thread: {str(e)}")
        finally:
            # Log disconnection if we haven't already
            if self.running:
                socketio.emit('terminal_output', {
                    'instance_id': self.instance_id, 
                    'session_id': self.session_id,
                    'output': f"\r\nSession disconnected for {self.instance_id}\r\n"
                })
            self.running = False

    def write_input(self, data):
        if self.master_fd is not None and self.running:
            try:
                os.write(self.master_fd, data.encode())
            except (OSError, IOError) as e:
                print(f"Error writing to terminal: {str(e)}")
                self.close()

    def resize_terminal(self, rows, cols):
        if self.master_fd is not None and self.running:
            try:
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            except (OSError, IOError) as e:
                print(f"Error resizing terminal: {str(e)}")

    def close(self):
        self.running = False
        
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except (OSError, IOError):
                pass  # Ignore errors on close
            self.master_fd = None
        
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=1)  # Wait for process to terminate
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            except Exception as e:
                print(f"Error terminating process: {str(e)}")
            self.process = None
        
        if (self.output_thread and 
            self.output_thread.is_alive() and 
            threading.current_thread() != self.output_thread):
            try:
                self.output_thread.join(timeout=1)
            except RuntimeError:
                pass  # Ignore if we can't join the thread
            self.output_thread = None

def get_instance_config(instance_id):
    try:
        with open('instances_list.yaml', 'r') as file:
            data = yaml.safe_load(file)
            for customer, customer_data in data.items():
                for env_name, instances in customer_data.get('instances', {}).items():
                    if isinstance(instances, list):  # Direct list of instances
                        for instance in instances:
                            if instance.get('instance_id') == instance_id:
                                # Use instance-specific region/profile if available, otherwise fallback to customer level
                                return {
                                    'aws_profile': instance.get('aws_profile', customer_data.get('aws_profile')),
                                    'region': instance.get('region', customer_data.get('region'))
                                }
                    else:  # Nested environment structure
                        for instance in instances:
                            if instance.get('instance_id') == instance_id:
                                # Use instance-specific region/profile if available, otherwise fallback to customer level
                                return {
                                    'aws_profile': instance.get('aws_profile', customer_data.get('aws_profile')),
                                    'region': instance.get('region', customer_data.get('region'))
                                }
        print(f"Warning: No configuration found for instance {instance_id}")
        return None
    except Exception as e:
        print(f"Error finding instance configuration: {str(e)}")
        return None

def check_instance_status(instance_id, profile, region):
    try:
        # Use the specified AWS profile and region
        session = boto3.Session(profile_name=profile, region_name=region)
        ssm_client = session.client('ssm')
        
        # Check instance connection status
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        
        if response['InstanceInformationList']:
            instance_info = response['InstanceInformationList'][0]
            status = instance_info['PingStatus']
            print(f"Instance {instance_id} status: {status} (region: {region})")
            return status == 'Online'
        else:
            print(f"Instance {instance_id} not found in SSM (region: {region})")
            return False
            
    except botocore.exceptions.ClientError as e:
        print(f"AWS Error checking instance status: {str(e)}")
        return False
    except Exception as e:
        print(f"Error checking instance status: {str(e)}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/instances')
def get_instances():
    try:
        print("Loading instances from YAML...")
        with open('instances_list.yaml', 'r') as file:
            data = yaml.safe_load(file)
        
        print(f"Loaded YAML data: {data}")
        
        tree = []
        for customer, customer_data in data.items():
            customer_node = {
                'name': customer,
                'type': 'customer',
                'environments': []
            }
            
            if 'instances' in customer_data:
                environments = customer_data['instances']
                for env_name, instances in environments.items():
                    env_node = {
                        'name': env_name,
                        'type': 'environment',
                        'instances': []
                    }
                    
                    for instance in instances:
                        instance_node = {
                            'name': instance['name'],
                            'id': instance['instance_id'],
                            'type': 'instance'
                        }
                        env_node['instances'].append(instance_node)
                    
                    customer_node['environments'].append(env_node)
            
            tree.append(customer_node)
        
        return jsonify(tree)
    except Exception as e:
        print(f"Error loading instances: {str(e)}")
        return jsonify([])

@app.route('/scan-instances')
def scan_instances():
    """
    Scan EC2 instances from all AWS profiles and regions
    """
    try:
        # Get environment variables for tag names
        tag1_name = os.environ.get('TAG1', 'Customer')
        tag2_name = os.environ.get('TAG2', 'Environment')
        
        print(f"Scanning instances with TAG1={tag1_name}, TAG2={tag2_name}")
        
        # Get all AWS profiles and regions
        profiles = get_aws_profiles()
        regions = get_all_aws_regions()
        
        # Initialize scan stats
        all_instances = []
        scanned_combinations = 0
        successful_scans = 0
        scan_stats = {
            'total_regions': len(regions),
            'total_profiles': len(profiles),
            'total_combinations': len(regions) * len(profiles),
            'scanned_combinations': 0,
            'successful_regions': 0,
            'total_instances': 0,
            'results': [],
            'status': 'scanning'
        }
        
        # Emit initial scan status
        socketio.emit('scan_status', scan_stats)
        
        # Scan instances from all profiles and regions
        for profile in profiles:
            for region in regions:
                scanned_combinations += 1
                scan_stats['scanned_combinations'] = scanned_combinations
                
                # Prepare result entry
                result = {
                    'profile': profile,
                    'region': region,
                    'status': 'scanning'
                }
                scan_stats['results'].append(result)
                
                # Emit progress update
                socketio.emit('scan_status', scan_stats)
                
                try:
                    instances = fetch_ec2_instances(profile, region, tag1_name, tag2_name)
                    if instances:
                        result['status'] = 'success'
                        result['instance_count'] = len(instances)
                        print(f"Found {len(instances)} instances in profile {profile}, region {region}")
                        all_instances.extend(instances)
                        successful_scans += 1
                        scan_stats['successful_regions'] = successful_scans
                        scan_stats['total_instances'] += len(instances)
                    else:
                        result['status'] = 'empty'
                        result['instance_count'] = 0
                except Exception as e:
                    error_msg = str(e)
                    result['status'] = 'error'
                    result['error'] = error_msg
                    
                    # Only log errors for profiles that should exist
                    if "InvalidClientTokenId" in error_msg:
                        result['status'] = 'access_denied'
                        print(f"Error fetching instances from {profile}/{region}: {error_msg}")
                    elif "InvalidUserID.NotFound" not in error_msg and "UnauthorizedOperation" not in error_msg:
                        print(f"Error scanning profile {profile}, region {region}: {error_msg}")
                    continue
                
                # Emit updated result
                socketio.emit('scan_status', scan_stats)
        
        print(f"Scanned {scanned_combinations} profile-region combinations, {successful_scans} successful")
        
        # Update final scan status
        scan_stats['status'] = 'completed'
        socketio.emit('scan_status', scan_stats)
        
        # Organize instances by tags
        tree = organize_instances_by_tags(all_instances, tag1_name, tag2_name)
        
        # Auto-save discovered instances to YAML
        if all_instances:
            yaml_data = convert_instances_to_yaml_format(all_instances, tag1_name, tag2_name)
            with open('instances_list.yaml', 'w') as file:
                yaml.dump(yaml_data, file, default_flow_style=False, sort_keys=False)
            
            print(f"Auto-saved {len(all_instances)} instances to instances_list.yaml")
        else:
            print("No instances found to save")
        
        return jsonify(tree)
    except Exception as e:
        print(f"Error scanning instances: {str(e)}")
        socketio.emit('scan_status', {'status': 'error', 'error': str(e)})
        return jsonify({'error': str(e)}), 500

def get_all_aws_regions():
    """
    Fetch all available AWS regions using AWS CLI
    """
    try:
        import subprocess
        
        # Try with default profile first
        result = subprocess.run([
            'aws', 'ec2', 'describe-regions', 
            '--all-regions', 
            '--query', 'Regions[].RegionName', 
            '--output', 'text',
            '--profile', 'dev'  # Use a known working profile
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            regions = result.stdout.strip().split()
            print(f"Found {len(regions)} AWS regions")
            return regions
        else:
            print(f"Error fetching regions: {result.stderr}")
            return get_fallback_regions()
        
    except Exception as e:
        print(f"Error fetching AWS regions: {str(e)}")
        return get_fallback_regions()

def get_fallback_regions():
    """
    Fallback list of common AWS regions
    """
    return [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
        'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
        'ca-central-1', 'sa-east-1'
    ]

def get_aws_profiles():
    """
    Get known AWS profiles (hardcoded based on your setup)
    """
    # Use the known profiles from your setup
    profiles = ['dev', 'prod']
    print(f"Using AWS profiles: {profiles}")
    return profiles

def get_aws_profiles_and_regions():
    """
    Get all combinations of AWS profiles and regions for comprehensive scanning
    """
    profiles = get_aws_profiles()
    regions = get_all_aws_regions()
    
    # Create all combinations of profiles and regions
    profiles_regions = []
    for profile in profiles:
        for region in regions:
            profiles_regions.append((profile, region))
    
    print(f"Will scan {len(profiles_regions)} profile-region combinations")
    return profiles_regions

def fetch_ec2_instances(aws_profile, aws_region, tag1_name, tag2_name):
    """
    Fetch EC2 instances from AWS with their tags and metadata
    """
    try:
        # Create boto3 session with the specified profile
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        ec2 = session.client('ec2')
        sts = session.client('sts')
        
        # Get AWS Account ID
        account_info = sts.get_caller_identity()
        account_id = account_info['Account']
        
        # Describe all instances
        response = ec2.describe_instances()
        
        instances = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Extract tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                
                # Get instance metadata
                instance_data = {
                    'instance_id': instance['InstanceId'],
                    'name': tags.get('Name', instance['InstanceId']),
                    'state': instance['State']['Name'],
                    'platform': instance.get('Platform', 'linux'),  # 'windows' or defaults to 'linux'
                    'instance_type': instance['InstanceType'],
                    'aws_profile': aws_profile,
                    'region': aws_region,
                    'account_id': account_id,
                    'tags': tags,
                    tag1_name.lower(): tags.get(tag1_name, 'Unknown'),
                    tag2_name.lower(): tags.get(tag2_name, 'Unknown')
                }
                
                instances.append(instance_data)
        
        return instances
    except Exception as e:
        print(f"Error fetching instances from {aws_profile}/{aws_region}: {str(e)}")
        return []

def organize_instances_by_tags(instances, tag1_name, tag2_name):
    """
    Organize instances into a tree structure based on AWS Account ID, Region, then TAG1 and TAG2
    """
    # Group instances by Account ID first, then Region, then TAG1, then TAG2
    account_groups = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    
    for instance in instances:
        account_id = instance.get('account_id', 'Unknown')
        region = instance.get('region', 'Unknown')
        tag1_value = instance.get(tag1_name.lower(), 'Unknown')
        tag2_value = instance.get(tag2_name.lower(), 'Unknown')
        account_groups[account_id][region][tag1_value][tag2_value].append(instance)
    
    # Build tree structure
    tree = []
    
    for account_id, region_groups in account_groups.items():
        # Create account-level node
        account_node = {
            'name': f'AWS Account: {account_id}',
            'type': 'account',
            'regions': []
        }
        
        for region, tag1_groups in region_groups.items():
            # Create region-level node
            region_node = {
                'name': f'Region: {region}',
                'type': 'region',
                'customers': []
            }
            
            for tag1_value, tag2_groups in tag1_groups.items():
                tag1_node = {
                    'name': tag1_value,
                    'type': 'customer',
                    'environments': []
                }
                
                for tag2_value, instances_list in tag2_groups.items():
                    tag2_node = {
                        'name': tag2_value,
                        'type': 'environment',
                        'instances': []
                    }
                    
                    for instance in instances_list:
                        instance_node = {
                            'name': instance['name'],
                            'id': instance['instance_id'],
                            'type': 'instance',
                            'state': instance['state'],
                            'platform': instance['platform'],
                            'instance_type': instance['instance_type'],
                            'aws_profile': instance['aws_profile'],
                            'region': instance['region'],
                            'account_id': instance['account_id']
                        }
                        tag2_node['instances'].append(instance_node)
                    
                    tag1_node['environments'].append(tag2_node)
                
                region_node['customers'].append(tag1_node)
            
            account_node['regions'].append(region_node)
        
        tree.append(account_node)
    
    return tree



def convert_instances_to_yaml_format(instances, tag1_name, tag2_name):
    """
    Convert scanned instances to the YAML format expected by the application
    Groups instances by customer and account, merging all regions under each customer
    """
    yaml_data = {}
    
    # Group instances by customer and account (not by region)
    customer_groups = defaultdict(lambda: defaultdict(list))
    
    for instance in instances:
        tag1_value = instance.get(tag1_name.lower(), 'Unknown')
        tag2_value = instance.get(tag2_name.lower(), 'Unknown')
        account_id = instance.get('account_id', 'Unknown')
        
        # Group by customer and account only (merge all regions)
        customer_key = f"{tag1_value}_{account_id}"
        customer_groups[customer_key][tag2_value].append(instance)
    
    # Convert to YAML structure
    for customer_key, tag2_groups in customer_groups.items():
        # Extract customer name and account from key
        parts = customer_key.rsplit('_', 1)
        if len(parts) >= 2:
            customer_name = parts[0]
            account_id = parts[1]
        else:
            customer_name = customer_key
            account_id = 'Unknown'
        
        # Use the first instance to get AWS profile and determine primary region
        first_instance = next(iter(next(iter(tag2_groups.values()))))
        
        # Find the most common region for this customer (for backward compatibility)
        region_counts = defaultdict(int)
        for instances_list in tag2_groups.values():
            for instance in instances_list:
                region_counts[instance['region']] += 1
        primary_region = max(region_counts.keys(), key=region_counts.get) if region_counts else 'us-east-1'
        
        yaml_data[customer_key] = {
            'region': primary_region,  # Most common region for backward compatibility
            'aws_profile': first_instance['aws_profile'],
            'account_id': account_id,
            'instances': {}
        }
        
        # Add all instances from all regions under each environment
        for tag2_value, instances_list in tag2_groups.items():
            if tag2_value not in yaml_data[customer_key]['instances']:
                yaml_data[customer_key]['instances'][tag2_value] = []
            
            for instance in instances_list:
                yaml_data[customer_key]['instances'][tag2_value].append({
                    'name': instance['name'],
                    'instance_id': instance['instance_id'],
                    'region': instance['region'],  # Store actual region per instance
                    'aws_profile': instance['aws_profile']  # Store profile per instance
                })
    
    return yaml_data

@socketio.on('connect')
def handle_connect():
    # Just log the connection, don't start any sessions
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    # Clean up any existing sessions for this client
    for session_id, session in list(sessions.items()):
        try:
            session.close()
            del sessions[session_id]
        except Exception as e:
            print(f'Error cleaning up session {session_id}: {e}')

@socketio.on('start_session')
def handle_start_session(data):
    instance_id = data.get('instance_id')
    session_id = data.get('session_id')
    
    if not instance_id or not session_id:
        emit('session_error', {'error': 'Invalid instance or session ID'})
        return

    try:
        session = SSMSession(instance_id, session_id)
        if session.start_session():
            sessions[session_id] = session
            emit('session_started', {
                'instance_id': instance_id,
                'session_id': session_id
            })
        else:
            emit('session_error', {
                'instance_id': instance_id,
                'session_id': session_id,
                'error': 'Failed to start session'
            })
    except Exception as e:
        emit('session_error', {
            'instance_id': instance_id,
            'session_id': session_id,
            'error': str(e)
        })

@socketio.on('terminal_input')
def handle_terminal_input(data):
    session_id = data.get('session_id')
    input_data = data.get('input')
    
    if not session_id or not input_data:
        return
        
    session = sessions.get(session_id)
    if session:
        session.write_input(input_data)

@socketio.on('terminal_interrupt')
def handle_terminal_interrupt(data):
    session_id = data.get('session_id')
    if session_id in sessions:
        session = sessions[session_id]
        # Send Ctrl+C signal to the process group
        if session.process:
            try:
                os.killpg(os.getpgid(session.process.pid), signal.SIGINT)
            except ProcessLookupError:
                pass

@socketio.on('terminal_resize')
def handle_terminal_resize(data):
    session_id = data.get('session_id')
    rows = data.get('rows')
    cols = data.get('cols')
    
    if not all([session_id, rows, cols]):
        return
        
    session = sessions.get(session_id)
    if session:
        session.resize_terminal(rows, cols)

@socketio.on('close_session')
def handle_close_session(data):
    session_id = data.get('session_id')
    if session_id in sessions:
        session = sessions[session_id]
        session.close()
        del sessions[session_id]

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)