import pandas as pd
import random

# Columns and their typical values based on NSL-KDD / sample
protocols = ['tcp', 'udp', 'icmp']
services = ['http', 'smtp', 'ftp', 'ftp_data', 'domain_u', 'private', 'telnet', 'ssh', 'exec', 'shell', 'smtp', 'other']
flags = ['SF', 'S0', 'REJ', 'RSTR', 'RSTO', 'SH', 'S1', 'S2', 'S3', 'OTH']
labels = ['normal', 'dos', 'probe', 'r2l', 'u2r']

def generate_case(label):
    if label == 'normal':
        return {
            'duration': random.randint(0, 10),
            'src_bytes': random.randint(100, 5000),
            'dst_bytes': random.randint(100, 20000),
            'count': random.randint(1, 10),
            'srv_count': random.randint(1, 10),
            'same_srv_rate': round(random.uniform(0.8, 1.0), 2),
            'diff_srv_rate': round(random.uniform(0.0, 0.2), 2),
            'dst_host_count': random.randint(1, 50),
            'dst_host_srv_count': random.randint(1, 50),
            'protocol_type': random.choice(['tcp', 'udp']),
            'service': random.choice(['http', 'smtp', 'domain_u']),
            'flag': 'SF',
            'label': 'normal'
        }
    elif label == 'dos':
        return {
            'duration': 0,
            'src_bytes': random.randint(0, 10),
            'dst_bytes': 0,
            'count': random.randint(100, 255),
            'srv_count': random.randint(1, 20),
            'same_srv_rate': round(random.uniform(0.0, 0.1), 2),
            'diff_srv_rate': round(random.uniform(0.8, 1.0), 2),
            'dst_host_count': 255,
            'dst_host_srv_count': random.randint(1, 20),
            'protocol_type': 'tcp',
            'service': random.choice(['http', 'smtp', 'ftp']),
            'flag': 'S0',
            'label': 'dos'
        }
    elif label == 'probe':
        return {
            'duration': random.randint(0, 5),
            'src_bytes': random.randint(0, 100),
            'dst_bytes': 0,
            'count': random.randint(1, 50),
            'srv_count': random.randint(1, 10),
            'same_srv_rate': round(random.uniform(0.1, 0.5), 2),
            'diff_srv_rate': round(random.uniform(0.5, 0.9), 2),
            'dst_host_count': random.randint(10, 255),
            'dst_host_srv_count': random.randint(1, 20),
            'protocol_type': random.choice(['tcp', 'udp', 'icmp']),
            'service': random.choice(['private', 'other']),
            'flag': random.choice(['REJ', 'RSTR']),
            'label': 'probe'
        }
    elif label == 'r2l':
        return {
            'duration': random.randint(5, 60),
            'src_bytes': random.randint(500, 2000),
            'dst_bytes': random.randint(50, 500),
            'count': random.randint(1, 5),
            'srv_count': random.randint(1, 5),
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'dst_host_count': random.randint(1, 10),
            'dst_host_srv_count': random.randint(1, 10),
            'protocol_type': 'tcp',
            'service': random.choice(['ftp', 'telnet', 'ftp_data']),
            'flag': 'SF',
            'label': 'r2l'
        }
    elif label == 'u2r':
        return {
            'duration': random.randint(10, 120),
            'src_bytes': random.randint(2000, 10000),
            'dst_bytes': random.randint(100, 1000),
            'count': 1,
            'srv_count': 1,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'dst_host_count': random.randint(1, 5),
            'dst_host_srv_count': random.randint(1, 5),
            'protocol_type': 'tcp',
            'service': random.choice(['ssh', 'shell', 'exec']),
            'flag': 'SF',
            'label': 'u2r'
        }

data = []
for _ in range(100):
    label = random.choice(labels)
    data.append(generate_case(label))

df = pd.DataFrame(data)
df.to_csv('data/extended_network_traffic.csv', index=False)
print("CSV generated: data/extended_network_traffic.csv with 100 cases.")
