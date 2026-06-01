import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# 1. Load the dataset
df = pd.read_csv('master_performance_report.csv')

# 2. Filter for specific containers and rename them
focus_containers = ['ai', 'ids']
df_filtered = df[df['Container'].isin(focus_containers)].copy()
df_filtered['Container'] = df_filtered['Container'].replace({'ai': 'Inferencer', 'ids': 'Monitor'})

# 3. Define custom order: 'normal' first, followed by others alphabetically
all_attacks = sorted(df_filtered['Attack_Type'].unique())
custom_order = ['normal'] + [a for a in all_attacks if a != 'normal']

# 4. Calculate mean values and reindex to the custom order
summary = df_filtered.groupby(['Container', 'Attack_Type'])[['Avg CPU %', 'Avg Memory MB']].mean().unstack(level=0)
summary = summary.reindex(custom_order)

# 5. Setup plotting variables
attack_types = summary.index
x = np.arange(len(attack_types))
width = 0.35

# --- Plot 1: Average CPU % ---
plt.figure(figsize=(10, 6))
plt.bar(x - width/2, summary['Avg CPU %']['Inferencer'], width, label='Inferencer', color='#1f77b4')
plt.bar(x + width/2, summary['Avg CPU %']['Monitor'], width, label='Monitor', color='#ff7f0e')

plt.ylabel('Average CPU %')
plt.xlabel('Attack Type')
plt.title('Average CPU Usage by Attack Type')
plt.xticks(x, attack_types)
plt.legend()
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.tight_layout()
plt.savefig('cpu_usage.png')
plt.show()

# --- Plot 2: Average Memory MB ---
plt.figure(figsize=(10, 6))
plt.bar(x - width/2, summary['Avg Memory MB']['Inferencer'], width, label='Inferencer', color='#1f77b4')
plt.bar(x + width/2, summary['Avg Memory MB']['Monitor'], width, label='Monitor', color='#ff7f0e')

plt.ylabel('Average Memory (MB)')
plt.xlabel('Attack Type')
plt.title('Average Memory Usage by Attack Type')
plt.xticks(x, attack_types)
plt.legend()
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.tight_layout()
plt.savefig('memory_usage.png')
plt.show()