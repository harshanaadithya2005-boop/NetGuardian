"""Packet-backed flag patterns and sustained rates; never generates traffic."""
from collections import defaultdict
from datetime import datetime
import config

def check_connection_patterns(records,source_ip):
    rows=[r for r in records if r.get('source_ip')==source_ip and not r.get('is_simulated')]
    unusual=[r for r in rows if str(r.get('protocol','')).upper()=='TCP' and
             (str(r.get('tcp_flags','')).upper() in {'FPU','FP','FU'} or r.get('tcp_flags')=='')]
    ports={r.get('destination_port') for r in unusual if r.get('destination_port')}
    flags=dict(type='suspicious_connection',detected=len(unusual)>=8 and len(ports)>=4,
               severity='HIGH',confidence=.9,packet_count=len(unusual),distinct_ports=len(ports),
               packet_ids=[r['id'] for r in unusual if 'id' in r],
               message=f'{len(unusual)} TCP NULL/FIN-PSH-URG pattern packets across {len(ports)} ports; investigate, not proof of compromise.')
    buckets=defaultdict(lambda:[0,0])
    for r in rows:
        try:key=int(datetime.fromisoformat(r['timestamp']).timestamp())//config.FLOOD_BUCKET_SECONDS
        except (ValueError,TypeError,KeyError):continue
        buckets[key][0]+=1;buckets[key][1]+=max(0,r.get('packet_size') or 0)
    hot=sorted(k for k,(count,size) in buckets.items() if count/config.FLOOD_BUCKET_SECONDS>=config.FLOOD_PACKETS_PER_SECOND or size/config.FLOOD_BUCKET_SECONDS>=config.FLOOD_BYTES_PER_SECOND)
    longest=run=0;previous=None
    for k in hot:
        run=run+1 if previous is not None and k==previous+1 else 1
        longest=max(longest,run);previous=k
    hot_rows=[]
    for row in rows:
        try:
            if int(datetime.fromisoformat(row['timestamp']).timestamp())//config.FLOOD_BUCKET_SECONDS in hot:hot_rows.append(row)
        except (ValueError,KeyError,TypeError):pass
    flood=dict(type='sustained_flood',detected=longest>=config.FLOOD_MIN_BUCKETS,severity='HIGH',confidence=.9,
               hot_buckets=len(hot),consecutive_hot_buckets=longest,bucket_seconds=config.FLOOD_BUCKET_SECONDS,
               packet_threshold_per_second=config.FLOOD_PACKETS_PER_SECOND,byte_threshold_per_second=config.FLOOD_BYTES_PER_SECOND,
               packet_ids=[r['id'] for r in hot_rows if 'id' in r],
               message=f'{longest} consecutive {config.FLOOD_BUCKET_SECONDS}-second intervals exceeded configured packet/byte rates.')
    return [flags,flood]
