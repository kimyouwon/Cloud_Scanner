import os
import re

total = 0
checks = {}

for f in os.listdir('scanner/checks'):
    if f.endswith('.py') and f != 'base.py' and '__init__' not in f:
        try:
            content = open(f'scanner/checks/{f}', encoding='utf-8').read()
            match = re.search(r'points\s*=\s*(\d+)', content)
            if match:
                points = int(match.group(1))
                checks[f] = points
                total += points
                print(f'{f}: {points}점')
        except Exception as e:
            print(f'{f}: 오류 - {e}')

print(f'\n총 점수: {total}점')
print(f'필요한 점수: {100 - total}점')

