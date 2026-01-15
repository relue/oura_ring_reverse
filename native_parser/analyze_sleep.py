#!/usr/bin/env python3
"""Analyze sleep stages from SleepNet model."""

import sys
sys.path.insert(0, '.')
from ml_inference.sleepnet import SleepNetModel
from oura.data.reader import RingDataReader
import numpy as np

# Load protobuf (has UTC timestamps from preprocessing)
reader = RingDataReader('input_data/ring_data.pb')

model = SleepNetModel()
result = model.predict_from_reader(reader)

print()
print('=' * 70)
print('Sleep Stage Analysis')
print('=' * 70)

# Summary
print(f'Total epochs: {len(result.stages)} ({len(result.stages) * 30 / 60:.0f} min)')
print(f'Awake: {result.awake_seconds // 60} min')
print(f'Light: {result.light_seconds // 60} min')
print(f'Deep: {result.deep_seconds // 60} min')
print(f'REM: {result.rem_seconds // 60} min')
print(f'Sleep efficiency: {result.sleep_efficiency:.1f}%')

# Stage distribution
print()
print('Stage Distribution:')
stage_names = {0: 'Awake', 1: 'Light', 2: 'Deep', 3: 'REM'}
unique, counts = np.unique(result.stages, return_counts=True)
for stage, count in zip(unique, counts):
    pct = count / len(result.stages) * 100
    name = stage_names.get(stage, f'Unknown({stage})')
    print(f'  {name}: {count} epochs ({pct:.1f}%)')

# Visualize sleep stages over time (text-based hypnogram)
print()
print('Sleep Hypnogram (30-sec epochs):')
print('-' * 70)

# Create a compact representation
stage_chars = {0: 'W', 1: 'L', 2: 'D', 3: 'R'}
compact = ''
for i, stage in enumerate(result.stages):
    compact += stage_chars.get(stage, '?')
    if (i + 1) % 60 == 0:  # New line every 30 min (60 epochs)
        hour_mark = (i + 1) * 30 / 3600
        print(f'{compact} | {hour_mark:.1f}h')
        compact = ''

if compact:
    hour_mark = len(result.stages) * 30 / 3600
    print(f'{compact.ljust(60)} | {hour_mark:.1f}h')

print('-' * 70)
print('Legend: W=Awake, L=Light, D=Deep, R=REM')

# Detect sleep cycles (transitions between stages)
print()
print('Stage Transitions:')
transitions = []
for i in range(1, len(result.stages)):
    if result.stages[i] != result.stages[i-1]:
        from_stage = stage_names.get(result.stages[i-1], '?')
        to_stage = stage_names.get(result.stages[i], '?')
        time_min = i * 30 / 60
        transitions.append((time_min, from_stage, to_stage))

print(f'Total transitions: {len(transitions)}')
if transitions:
    print('First 20 transitions:')
    for t in transitions[:20]:
        print(f'  {t[0]:.1f} min: {t[1]} -> {t[2]}')
