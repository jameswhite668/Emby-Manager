import re

with open('history_final.html', 'r', encoding='utf-8') as f:
    html = f.read()

m = re.search(r'<tr onclick.*?</tr>', html, re.DOTALL)
if m:
    row = m.group(0)
    print('Has poster img:', 'movie-poster' in row)
    print('Has overview:', 'data-overview=' in row and 'data-overview=""' not in row)
    print('Has poster URL:', 'data-poster-url=' in row and 'data-poster-url=""' not in row)
    print('Has modal URL:', 'data-modal-image-url=' in row and 'data-modal-image-url=""' not in row)
else:
    print('No row found')
