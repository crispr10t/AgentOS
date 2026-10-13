import psutil

print("Top 5 processes by RAM consumption:")
procs = [
    (p.info['name'], p.info['memory_info'].rss)
    for p in psutil.process_iter(['name', 'memory_info'])
    if p.info.get('memory_info')
]
procs.sort(key=lambda x: x[1], reverse=True)
for name, mem in procs[:5]:
    print(f"{name}: {mem / (1024 * 1024):.2f} MB")
