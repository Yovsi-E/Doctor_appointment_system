import re

with open('generate_report.py', 'r', encoding='utf-8') as f:
    content = f.read()

replacements = {
    '\u2018': "'",  # left single quote
    '\u2019': "'",  # right single quote
    '\u201c': '"',  # left double quote
    '\u201d': '"',  # right double quote
    '\u2013': '--', # en dash
    '\u2014': '--', # em dash
    '\u2022': '*',  # bullet
    '\u2026': '...',# ellipsis
    '\u2500': '-',  # box drawing
}

for old, new in replacements.items():
    content = content.replace(old, new)

with open('generate_report.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('Fixed unicode characters')
